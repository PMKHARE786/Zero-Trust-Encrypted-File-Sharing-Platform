import os
import sqlite3
import hashlib
import time
import base64
import hmac
import struct
import uuid
import urllib.request
import json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

DB_FILE = 'database.db'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper function to connect to SQLite DB
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

# Initialize Database Schema
def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # User Table with emergency backup codes
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        mfa_secret TEXT,
        mfa_enabled INTEGER DEFAULT 0,
        backup_codes TEXT,
        created_at REAL NOT NULL
    )
    ''')
    
    # Add column backup_codes if users table exists without it (migration safety check)
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN backup_codes TEXT")
    except sqlite3.OperationalError:
        pass
    
    # Shared Files Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        file_path TEXT NOT NULL,
        integrity_hash TEXT NOT NULL,
        download_limit INTEGER DEFAULT 0,
        download_count INTEGER DEFAULT 0,
        expires_at REAL,
        password_hash TEXT,
        created_at REAL NOT NULL
    )
    ''')
    
    # Audit Logs Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        event_type TEXT NOT NULL,
        filename TEXT,
        status TEXT NOT NULL,
        ip_address TEXT NOT NULL,
        country TEXT NOT NULL,
        trust_score INTEGER NOT NULL,
        details TEXT,
        created_at REAL NOT NULL
    )
    ''')
    
    # Brute Force Protection Table
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS failed_attempts (
        id TEXT PRIMARY KEY,
        ip_address TEXT NOT NULL,
        file_id TEXT NOT NULL,
        attempt_count INTEGER DEFAULT 0,
        last_attempt REAL NOT NULL,
        UNIQUE(ip_address, file_id)
    )
    ''')
    
    # Default Whitelist Geofence Configuration
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS geofence (
        id TEXT PRIMARY KEY,
        allowed_countries TEXT NOT NULL
    )
    ''')
    
    # Add default geofence configuration if not exists
    cursor.execute("SELECT COUNT(*) FROM geofence")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO geofence (id, allowed_countries) VALUES ('config', 'India,United States,United Kingdom')")
        
    conn.commit()
    conn.close()

init_db()

# Resolve real client IP and Geolocation
def resolve_client_network(ip_addr):
    if ip_addr in ['127.0.0.1', '::1', 'localhost'] or ip_addr.startswith('192.168.') or ip_addr.startswith('10.'):
        try:
            with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=2) as response:
                ip_data = json.loads(response.read().decode())
                ip_addr = ip_data.get('ip', '127.0.0.1')
        except Exception:
            pass
            
    try:
        with urllib.request.urlopen(f"http://ip-api.com/json/{ip_addr}", timeout=2) as response:
            geo_data = json.loads(response.read().decode())
            country = geo_data.get('country', 'India')
            return ip_addr, country
    except Exception:
        return ip_addr, 'India'

# Custom Base32 TOTP Verification Engine
def verify_totp(secret, code):
    try:
        secret = secret.strip().replace(' ', '').upper()
        missing_padding = len(secret) % 8
        if missing_padding:
            secret += '=' * (8 - missing_padding)
        key = base64.b32decode(secret)
        
        time_step = int(time.time() / 30)
        
        for drift in [-1, 0, 1]:
            t = time_step + drift
            msg = struct.pack(">Q", t)
            h = hmac.new(key, msg, hashlib.sha1).digest()
            o = h[19] & 15
            token = (struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000
            if f"{token:06d}" == str(code):
                return True
        return False
    except Exception:
        return False

# Geofence Validation Helper
def is_country_allowed(country):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT allowed_countries FROM geofence WHERE id = 'config'")
    row = cursor.fetchone()
    conn.close()
    if not row:
        return True
    allowed = [c.strip().lower() for c in row['allowed_countries'].split(',')]
    return country.strip().lower() in allowed

# Register Route
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and Password are required'}), 400
        
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    mfa_secret = base64.b32encode(os.urandom(10)).decode('utf-8')
    
    # Generate 5 Emergency Backup Codes
    backup_list = [uuid.uuid4().hex[:8].upper() for _ in range(5)]
    backup_codes_str = ",".join(backup_list)
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (id, username, password_hash, mfa_secret, mfa_enabled, backup_codes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), username, password_hash, mfa_secret, 0, backup_codes_str, time.time())
        )
        conn.commit()
        return jsonify({
            'message': 'Registration successful',
            'mfa_secret': mfa_secret,
            'backup_codes': backup_list
        })
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()

# Login Route
@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    mfa_code = data.get('mfa_code', '').strip()
    
    raw_ip = request.remote_addr or '127.0.0.1'
    ip_addr, country = resolve_client_network(raw_ip)
    
    simulated_country = request.headers.get('X-Simulated-Country')
    if simulated_country and simulated_country != 'India' and simulated_country != '':
        country = simulated_country

    trust_score = int(request.headers.get('X-Trust-Score', 100))
    
    if not is_country_allowed(country):
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_logs (id, event_type, filename, status, ip_address, country, trust_score, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), 'SUSPICIOUS_LOGIN', None, 'BLOCKED', ip_addr, country, trust_score, f'Geofence block for user: {username}', time.time())
        )
        conn.commit()
        conn.close()
        return jsonify({'error': f'Access Denied: Connection from {country} is not authorized by geofencing policies.'}), 403

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 400
        
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    if user['password_hash'] != password_hash:
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 400
        
    # Verify TOTP Code or Backup Code
    if user['mfa_enabled'] == 1:
        if not mfa_code:
            conn.close()
            return jsonify({'error': 'Invalid MFA Token Code'}), 401
            
        is_mfa_valid = verify_totp(user['mfa_secret'], mfa_code)
        
        # Fallback Check: Emergency Backup Codes
        is_backup_valid = False
        saved_backups = [c.strip() for c in (user['backup_codes'] or '').split(',') if c.strip()]
        
        if not is_mfa_valid and mfa_code.upper() in saved_backups:
            is_backup_valid = True
            saved_backups.remove(mfa_code.upper())
            new_backups_str = ",".join(saved_backups)
            cursor.execute("UPDATE users SET backup_codes = ? WHERE username = ?", (new_backups_str, username))
            conn.commit()
            
        if not is_mfa_valid and not is_backup_valid:
            conn.close()
            return jsonify({'error': 'Invalid MFA Token Code'}), 401
            
    conn.close()
    
    conn = get_db()
    conn.execute(
        "INSERT INTO audit_logs (id, event_type, filename, status, ip_address, country, trust_score, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), 'USER_LOGIN', None, 'SUCCESS', ip_addr, country, trust_score, f'User logged in: {username}', time.time())
    )
    conn.commit()
    conn.close()
    
    return jsonify({
        'message': 'Login successful',
        'username': username,
        'mfa_enabled': user['mfa_enabled'],
        'mfa_secret': user['mfa_secret'],
        'real_ip': ip_addr,
        'real_country': country
    })

# MFA Setup Confirmation Route
@app.route('/api/auth/mfa/enable', methods=['POST'])
def enable_mfa():
    data = request.get_json()
    username = data.get('username')
    mfa_code = data.get('mfa_code')
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
        
    if verify_totp(user['mfa_secret'], mfa_code):
        cursor.execute("UPDATE users SET mfa_enabled = 1 WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'MFA successfully activated'})
    else:
        conn.close()
        return jsonify({'error': 'Verification failed: invalid MFA token'}), 400

# File Upload Route
@app.route('/api/files/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
        
    file = request.files['file']
    integrity_hash = request.form.get('integrity_hash')
    download_limit = int(request.form.get('download_limit', 0))
    expiry_hours = float(request.form.get('expiry_hours', 24))
    password = request.form.get('password', '')
    
    if not integrity_hash:
        return jsonify({'error': 'Cryptographic integrity check hash missing'}), 400
        
    file_id = str(uuid.uuid4())
    filename = file.filename
    file_path = os.path.join(UPLOAD_FOLDER, file_id)
    
    file.save(file_path)
    
    expires_at = time.time() + (expiry_hours * 3600)
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest() if password else None
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO files (id, filename, file_path, integrity_hash, download_limit, download_count, expires_at, password_hash, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?)",
        (file_id, filename, file_path, integrity_hash, download_limit, expires_at, password_hash, time.time())
    )
    
    raw_ip = request.remote_addr or '127.0.0.1'
    ip_addr, country = resolve_client_network(raw_ip)
    
    simulated_country = request.headers.get('X-Simulated-Country')
    if simulated_country and simulated_country != 'India' and simulated_country != '':
        country = simulated_country
        
    trust_score = int(request.headers.get('X-Trust-Score', 100))
    
    cursor.execute(
        "INSERT INTO audit_logs (id, event_type, filename, status, ip_address, country, trust_score, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), 'FILE_UPLOAD', filename, 'SUCCESS', ip_addr, country, trust_score, f'Encrypted file uploaded. ID: {file_id}', time.time())
    )
    conn.commit()
    conn.close()
    
    return jsonify({'file_id': file_id, 'expires_at': expires_at})

# File Download & Decryption Route (Including Brute-Force lockout)
@app.route('/api/files/download/<file_id>', methods=['POST'])
def download_file(file_id):
    data = request.get_json() or {}
    password = data.get('password', '')
    trust_score = data.get('trust_score', 100)
    
    raw_ip = request.remote_addr or '127.0.0.1'
    ip_addr, country = resolve_client_network(raw_ip)
    
    simulated_country = request.headers.get('X-Simulated-Country')
    if simulated_country and simulated_country != 'India' and simulated_country != '':
        country = simulated_country
        
    # Check Geofencing
    if not is_country_allowed(country):
        return jsonify({'error': f'Access Denied: {country} is blacklisted by administrator.'}), 403
        
    # Check Posture Score
    if trust_score < 50:
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_logs (id, event_type, filename, status, ip_address, country, trust_score, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), 'FILE_DOWNLOAD_BLOCKED', file_id, 'BLOCKED', ip_addr, country, trust_score, 'Blocked download attempt due to low endpoint security score.', time.time())
        )
        conn.commit()
        conn.close()
        return jsonify({'error': 'Access Blocked: Your browser posture failed security verification. Please secure your endpoint.'}), 403

    # Brute-Force Lockout Check
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT attempt_count FROM failed_attempts WHERE ip_address = ? AND file_id = ?", (ip_addr, file_id))
    failed_row = cursor.fetchone()
    
    if failed_row and failed_row['attempt_count'] >= 3:
        conn.close()
        # Log malicious attempt
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_logs (id, event_type, filename, status, ip_address, country, trust_score, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), 'BRUTE_FORCE_BLOCKED', file_id, 'BLOCKED', ip_addr, country, trust_score, 'Blocked attempt on locked file due to brute force.', time.time())
        )
        conn.commit()
        conn.close()
        return jsonify({'error': 'Access Blocked: Too many incorrect attempts. This file has been locked for your IP address.'}), 429

    cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    file_record = cursor.fetchone()
    
    if not file_record:
        conn.close()
        return jsonify({'error': 'File not found'}), 404
        
    # Check expiry
    if time.time() > file_record['expires_at']:
        conn.close()
        return jsonify({'error': 'File download link has expired'}), 410
        
    # Check download limits
    if file_record['download_limit'] > 0 and file_record['download_count'] >= file_record['download_limit']:
        conn.close()
        return jsonify({'error': 'Download limit exceeded for this file'}), 410
        
    # Check Password Protection
    if file_record['password_hash']:
        if not password:
            conn.close()
            return jsonify({'error': 'Password required', 'password_required': True}), 401
        provided_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if file_record['password_hash'] != provided_hash:
            # Increment failed attempts
            cursor.execute(
                "INSERT INTO failed_attempts (id, ip_address, file_id, attempt_count, last_attempt) VALUES (?, ?, ?, 1, ?) "
                "ON CONFLICT(ip_address, file_id) DO UPDATE SET attempt_count = attempt_count + 1, last_attempt = ?",
                (str(uuid.uuid4()), ip_addr, file_id, time.time(), time.time())
            )
            
            # Fetch updated attempts
            cursor.execute("SELECT attempt_count FROM failed_attempts WHERE ip_address = ? AND file_id = ?", (ip_addr, file_id))
            attempts = cursor.fetchone()['attempt_count']
            
            # Log failed password attempt
            cursor.execute(
                "INSERT INTO audit_logs (id, event_type, filename, status, ip_address, country, trust_score, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), 'DECRYPT_FAILURE', file_record['filename'], 'FAILED', ip_addr, country, trust_score, f'Incorrect password. Attempt {attempts}/3', time.time())
            )
            conn.commit()
            conn.close()
            
            error_msg = f'Incorrect password entered. Attempt {attempts}/3.'
            if attempts >= 3:
                error_msg = 'Incorrect password. Lockout threshold reached. This file has been locked for your IP.'
                
            return jsonify({'error': error_msg, 'password_required': True}), 401
            
    # Reset failed attempts on success
    cursor.execute("DELETE FROM failed_attempts WHERE ip_address = ? AND file_id = ?", (ip_addr, file_id))
    
    # Update download count
    cursor.execute("UPDATE files SET download_count = download_count + 1 WHERE id = ?", (file_id,))
    
    # Log successful access
    cursor.execute(
        "INSERT INTO audit_logs (id, event_type, filename, status, ip_address, country, trust_score, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (str(uuid.uuid4()), 'FILE_DOWNLOAD', file_record['filename'], 'SUCCESS', ip_addr, country, trust_score, f'File downloaded. ID: {file_id}', time.time())
    )
    conn.commit()
    conn.close()
    
    # Serve file from directory
    return send_from_directory(UPLOAD_FOLDER, file_id, download_name=file_record['filename'])

# Fetch Audit Logs for Dashboard
@app.route('/api/audit-logs', methods=['GET'])
def get_audit_logs():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 50")
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify(logs)

# Retrieve Geofencing Settings & Whitelist Configuration
@app.route('/api/geofence', methods=['GET', 'POST'])
def manage_geofence():
    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        data = request.get_json()
        countries = data.get('countries', 'India,United States')
        cursor.execute("UPDATE geofence SET allowed_countries = ? WHERE id = 'config'", (countries,))
        conn.commit()
        conn.close()
        return jsonify({'message': 'Geofencing configuration updated successfully'})
    else:
        cursor.execute("SELECT allowed_countries FROM geofence WHERE id = 'config'")
        row = cursor.fetchone()
        conn.close()
        return jsonify({'allowed_countries': row['allowed_countries'] if row else ''})

# Serve single-page app
@app.route('/')
def home():
    return send_from_directory('templates', 'index.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)
