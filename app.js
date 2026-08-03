// Global Application State
const API_BASE = 'https://zero-trust-encrypted-file-sharing.onrender.com';

const state = {
    user: null,
    activeTab: 'dashboard',
    simulatedCountry: 'India',
    trustScore: 100,
    devToolsActive: false,
    auditLogs: [],
    geofenceConfig: '',
    selectedFile: null,
    alarmPlaying: false,
    audioCtx: null,
    alarmInterval: null,
    decryptedBlobCache: null,
    decryptedFilenameCache: ''
};

// Canvas Fingerprinting Implementation
function getCanvasFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        canvas.width = 200;
        canvas.height = 50;
        const ctx = canvas.getContext('2d');
        
        ctx.fillStyle = '#070913';
        ctx.fillRect(0, 0, 200, 50);
        
        const grad = ctx.createLinearGradient(0, 0, 200, 0);
        grad.addColorStop(0, '#2563eb');
        grad.addColorStop(1, '#0284c7');
        ctx.fillStyle = grad;
        ctx.font = '14px Outfit';
        ctx.fillText('SECURE_PLATFORM_V1', 10, 30);
        
        ctx.strokeStyle = '#ef4444';
        ctx.beginPath();
        ctx.moveTo(5, 40);
        ctx.lineTo(195, 40);
        ctx.stroke();
        
        const dataUrl = canvas.toDataURL();
        
        let hash = 0;
        for (let i = 0; i < dataUrl.length; i++) {
            const char = dataUrl.charCodeAt(i);
            hash = (hash << 5) - hash + char;
            hash = hash & hash;
        }
        return 'CFP-' + Math.abs(hash).toString(16).toUpperCase();
    } catch (e) {
        return 'CFP-UNAVAILABLE';
    }
}

// Get Browser/Endpoint Details
function getEndpointDetails() {
    const gl = document.createElement('canvas').getContext('webgl');
    let gpu = 'Unknown GPU';
    if (gl) {
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        if (debugInfo) {
            gpu = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
        }
    }
    
    return {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        cores: navigator.hardwareConcurrency || 'N/A',
        screen: `${window.screen.width}x${window.screen.height}`,
        gpu: gpu,
        canvasHash: getCanvasFingerprint()
    };
}

// Calculate Password Strength Entropy
function checkPasswordStrength(password) {
    let score = 0;
    if (!password) return { score: 0, label: 'None', class: '' };
    
    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    
    if (score <= 2) return { score: 1, label: 'Weak (Vulnerable)', class: 'weak' };
    if (score <= 4) return { score: 2, label: 'Medium (Adequate)', class: 'medium' };
    return { score: 3, label: 'Strong (Highly Secure)', class: 'strong' };
}

// Write to Interactive Threat Terminal
function logTerminal(message, type = 'info') {
    const terminal = document.getElementById('threat-terminal');
    if (!terminal) return;
    
    const timestamp = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = `terminal-line ${type}`;
    line.textContent = `[${timestamp}] ${message}`;
    
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

// Synthesize Security Siren Alarm (Web Audio API)
function startAlarm() {
    if (state.alarmPlaying) return;
    
    try {
        state.audioCtx = new (window.AudioContext || window.webkitAudioContext)();
        state.alarmPlaying = true;
        
        let freq = 800;
        state.alarmInterval = setInterval(() => {
            if (!state.audioCtx) return;
            const osc = state.audioCtx.createOscillator();
            const gain = state.audioCtx.createGain();
            
            osc.type = 'sawtooth';
            freq = freq === 800 ? 1100 : 800;
            osc.frequency.setValueAtTime(freq, state.audioCtx.currentTime);
            
            gain.gain.setValueAtTime(0.08, state.audioCtx.currentTime);
            gain.gain.exponentialRampToValueAtTime(0.001, state.audioCtx.currentTime + 0.25);
            
            osc.connect(gain);
            gain.connect(state.audioCtx.destination);
            
            osc.start();
            osc.stop(state.audioCtx.currentTime + 0.25);
        }, 300);
        
        logTerminal("AUDIBLE ALERT ENGINE INITIATED: Siren broadcast active.", "danger");
    } catch (e) {
        console.error("Audio Context initialization failed.", e);
    }
}

function stopAlarm() {
    if (!state.alarmPlaying) return;
    
    clearInterval(state.alarmInterval);
    if (state.audioCtx) {
        state.audioCtx.close();
        state.audioCtx = null;
    }
    state.alarmPlaying = false;
    logTerminal("Audible threat warnings deactivated.", "info");
}

// Client-Side Zero-Knowledge Encryption
async function encryptFile(file, password = '') {
    const key = await window.crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
    
    const rawKey = await window.crypto.subtle.exportKey('raw', key);
    const base64Key = btoa(String.fromCharCode(...new Uint8Array(rawKey)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const arrayBuffer = await file.arrayBuffer();
    
    const ciphertextBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv },
        key,
        arrayBuffer
    );
    
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', arrayBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    const uploadBytes = new Uint8Array(12 + ciphertextBuffer.byteLength);
    uploadBytes.set(iv, 0);
    uploadBytes.set(new Uint8Array(ciphertextBuffer), 12);
    
    return {
        encryptedBlob: new Blob([uploadBytes], { type: 'application/octet-stream' }),
        integrityHash: hexHash,
        keyHash: base64Key
    };
}

// Client-Side Zero-Knowledge Decryption
async function decryptFile(encryptedBlob, keyBase64, originalHash) {
    try {
        const binaryString = atob(keyBase64.replace(/-/g, '+').replace(/_/g, '/'));
        const keyData = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            keyData[i] = binaryString.charCodeAt(i);
        }
        
        const key = await window.crypto.subtle.importKey(
            'raw',
            keyData,
            { name: 'AES-GCM' },
            false,
            ['decrypt']
        );
        
        const arrayBuffer = await encryptedBlob.arrayBuffer();
        const fullBytes = new Uint8Array(arrayBuffer);
        
        const iv = fullBytes.slice(0, 12);
        const ciphertext = fullBytes.slice(12);
        
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: 'AES-GCM', iv: iv },
            key,
            ciphertext
        );
        
        const hashBuffer = await window.crypto.subtle.digest('SHA-256', decryptedBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hexHash = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        
        if (hexHash !== originalHash) {
            throw new Error("INTEGRITY VERIFICATION FAILED: Data tampered or key incorrect.");
        }
        
        return new Blob([decryptedBuffer]);
    } catch (e) {
        logTerminal(`DECRYPTION FAULT: ${e.message}`, "danger");
        throw e;
    }
}

// Render dynamic diagonal security watermark overlay on preview canvas
async function renderSecurePreview(blob, filename) {
    const canvas = document.getElementById('preview-watermark-canvas');
    const ctx = canvas.getContext('2d');
    
    // Set baseline sizes
    canvas.width = 600;
    canvas.height = 350;
    
    // Clear canvas with white background
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    
    // Custom watermark details
    const timestampStr = new Date().toLocaleString();
    const watermarkText = `CONFIDENTIAL // ${state.simulatedCountry} // IP: RESOLVED // ${timestampStr}`;
    
    // If it's an image, render it inside the preview canvas first
    if (blob.type.startsWith('image/')) {
        const img = new Image();
        img.src = URL.createObjectURL(blob);
        await new Promise(resolve => {
            img.onload = () => {
                // Scale image to fit canvas
                const ratio = Math.min(canvas.width / img.width, canvas.height / img.height) * 0.9;
                const w = img.width * ratio;
                const h = img.height * ratio;
                const x = (canvas.width - w) / 2;
                const y = (canvas.height - h) / 2;
                ctx.drawImage(img, x, y, w, h);
                resolve();
            };
        });
    } else {
        // Draw document layout placeholder
        ctx.fillStyle = '#f1f5f9';
        ctx.fillRect(20, 20, canvas.width - 40, canvas.height - 40);
        ctx.strokeStyle = '#cbd5e1';
        ctx.lineWidth = 1.5;
        ctx.strokeRect(20, 20, canvas.width - 40, canvas.height - 40);
        
        // Draw file icon/details placeholder text
        ctx.fillStyle = '#475569';
        ctx.font = '700 16px Outfit';
        ctx.fillText(filename, 50, 60);
        
        ctx.fillStyle = '#94a3b8';
        ctx.font = '13px Outfit';
        ctx.fillText(`File Type: ${blob.type || 'Binary Package'} // Size: ${(blob.size / 1024).toFixed(2)} KB`, 50, 85);
        
        // Mock document paragraph lines
        ctx.fillStyle = '#cbd5e1';
        for (let i = 0; i < 6; i++) {
            ctx.fillRect(50, 120 + (i * 30), canvas.width - 100, 10);
        }
    }
    
    // Overlay diagonal security watermark text
    ctx.save();
    ctx.translate(canvas.width / 2, canvas.height / 2);
    ctx.rotate(-25 * Math.PI / 180);
    ctx.font = '800 13px Fira Code';
    ctx.fillStyle = 'rgba(239, 68, 68, 0.18)'; // Red transparent watermark
    ctx.textAlign = 'center';
    
    // Draw repeating watermarks across canvas
    for (let y = -150; y <= 150; y += 50) {
        ctx.fillText(watermarkText, 0, y);
    }
    ctx.restore();
    
    // Display preview container
    document.getElementById('decrypted-preview-container').style.display = 'block';
}

// Endpoint Posture and DevTools Detection Checks
function runEndpointAssessment() {
    let score = 100;
    let devToolsDetected = false;
    
    const t0 = performance.now();
    debugger; 
    const t1 = performance.now();
    if (t1 - t0 > 100) {
        devToolsDetected = true;
    }
    
    const widthDiff = window.outerWidth - window.innerWidth;
    const heightDiff = window.outerHeight - window.innerHeight;
    if (widthDiff > 160 || heightDiff > 160) {
        devToolsDetected = true;
    }
    
    if (devToolsDetected) {
        score -= 50;
        if (!state.devToolsActive) {
            state.devToolsActive = true;
            logTerminal("ENDPOINT ALERT: Developer console activation detected!", "danger");
            startAlarm();
        }
    } else {
        if (state.devToolsActive) {
            state.devToolsActive = false;
            logTerminal("Developer console deactivated. Endpoint threat level cleared.", "success");
            stopAlarm();
        }
    }
    
    if (window.innerWidth < 480) {
        score -= 15;
    }
    
    const allowedList = state.geofenceConfig.split(',').map(c => c.trim().toLowerCase());
    if (allowedList.length > 0 && !allowedList.includes(state.simulatedCountry.toLowerCase())) {
        score -= 30;
    }
    
    state.trustScore = Math.max(score, 10);
    updateScoreUI();
}

// Update Score Gauge UI
function updateScoreUI() {
    const fill = document.getElementById('gauge-fill');
    const text = document.getElementById('gauge-text');
    const badge = document.getElementById('posture-badge');
    
    if (!fill || !text) return;
    
    const percentage = state.trustScore;
    const offset = 314 - (percentage / 100) * 314;
    fill.style.strokeDashoffset = offset;
    text.textContent = percentage;
    
    fill.classList.remove('warning', 'critical');
    
    let grade = 'A+';
    if (percentage >= 90) {
        grade = 'A';
    } else if (percentage >= 70) {
        fill.classList.add('warning');
        grade = 'B';
    } else if (percentage >= 50) {
        fill.classList.add('warning');
        grade = 'C';
    } else {
        fill.classList.add('critical');
        grade = 'F';
    }
    
    if (badge) {
        badge.textContent = `Grade: ${grade}`;
        badge.className = `status-badge ${grade === 'F' ? 'failed' : (grade === 'C' || grade === 'B' ? 'blocked' : 'success')}`;
    }
}

// API: Register User
async function apiRegister(username, password) {
    try {
        const response = await fetch(`${API_BASE}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await response.json();
        if (response.ok) {
            logTerminal(`User registered: ${username}`, 'success');
            return data;
        } else {
            throw new Error(data.error);
        }
    } catch (e) {
        logTerminal(`Registration Failure: ${e.message}`, 'danger');
        alert(e.message);
    }
}

// API: Setup MFA Setup Token
async function apiEnableMfa(mfaCode) {
    try {
        const response = await fetch(`${API_BASE}/api/auth/mfa/enable`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: state.user.username, mfa_code: mfaCode })
        });
        const data = await response.json();
       if (response.ok) {
            state.user.mfaEnabled = 1;
            logTerminal("Multi-Factor Authentication enabled successfully.", "success");
            alert("MFA Activated!");
            document.getElementById('auth-overlay').style.display = 'none';
            document.getElementById('logged-user-name').textContent = state.user.username;
            document.getElementById('avatar-letter').textContent = state.user.username[0].toUpperCase();
            switchTab('dashboard');
    } else {
            throw new Error(data.error);
        }
    } catch (e) {
        logTerminal(`MFA Activation Failure: ${e.message}`, 'danger');
        alert(e.message);
    }
}

// API: Upload Encrypted File
async function apiUploadFile(file, expiryHours, downloadLimit, password = '') {
    try {
        logTerminal(`Initiating local client encryption for: ${file.name}...`, 'info');
        const { encryptedBlob, integrityHash, keyHash } = await encryptFile(file, password);
        logTerminal(`Encryption complete. SHA-256 Integrity Hash: ${integrityHash}`, 'success');
        
        const formData = new FormData();
        formData.append('file', encryptedBlob, file.name);
        formData.append('integrity_hash', integrityHash);
        formData.append('expiry_hours', expiryHours);
        formData.append('download_limit', downloadLimit);
        formData.append('password', password);
        
        logTerminal("Uploading encrypted package to secure vault...", "info");
        const response = await fetch(`${API_BASE}/api/files/upload`, {
            method: 'POST',
            headers: {
                'X-Simulated-Country': state.simulatedCountry,
                'X-Trust-Score': state.trustScore.toString()
            },
            body: formData
        });
        
        const data = await response.json();
        if (response.ok) {
            logTerminal("Vault upload verified by server.", "success");
            const shareUrl = `${window.location.origin}/#download/${data.file_id}/${integrityHash}#${keyHash}`;
            displayShareLink(shareUrl);
            await fetchAuditLogs();
        } else {
            throw new Error(data.error);
        }
    } catch (e) {
        logTerminal(`Upload failure: ${e.message}`, 'danger');
        alert(e.message);
    }
}

// API: Download and Decrypt File
async function apiDownloadFile(fileId, integrityHash, keyHash, password = '') {
    try {
        logTerminal(`Requesting secure download package for ID: ${fileId}...`, 'info');
        
        const response = await fetch(`${API_BASE}/api/files/download/${fileId}`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Simulated-Country': state.simulatedCountry,
                'X-Trust-Score': state.trustScore.toString()
            },
            body: JSON.stringify({ password, trust_score: state.trustScore })
        });
        
        if (response.status === 401) {
            document.getElementById('download-password-box').style.display = 'block';
            logTerminal("Authentication required: input password to retrieve encryption payload.", "warning");
            return;
        }
        
        // Check Brute Force Lockout
        if (response.status === 429) {
            const data = await response.json().catch(() => null);
            state.trustScore = 10; // Instantly lock browser score to F
            updateScoreUI();
            logTerminal(`[CRITICAL] BRUTE FORCE PASSWORD ATTACK BLOCKED ON FILE: ${fileId}`, "danger");
            startAlarm();
            throw new Error(data ? data.error : "Too many attempts: lockout engaged.");
        }
        
        if (response.status === 403) {
            const data = await response.json().catch(() => null);
            throw new Error(data ? data.error : "Endpoint posture verification failure.");
        }
        if (!response.ok) {
            const data = await response.json().catch(() => null);
            throw new Error(data ? data.error : "Download transaction aborted.");
        }
        
        // Grab blob data directly without reading JSON first
        const encryptedBlob = await response.blob();
        logTerminal("Encrypted package payload received. Initializing client decryptor...", "info");
        
        const decryptedBlob = await decryptFile(encryptedBlob, keyHash, integrityHash);
        logTerminal("Integrity verified! Launching secure watermarked previewer...", "success");
        
        // Read file header details
        const contentDisp = response.headers.get('Content-Disposition');
        let filename = 'decrypted_file.dat';
        if (contentDisp && contentDisp.indexOf('filename=') !== -1) {
            filename = contentDisp.split('filename=')[1].trim().replace(/['"]/g, '');
        }
        
        // Cache decrypted file inside client memory
        state.decryptedBlobCache = decryptedBlob;
        state.decryptedFilenameCache = filename;
        
        // Display secure watermark preview
        await renderSecurePreview(decryptedBlob, filename);
        
        document.getElementById('download-password-box').style.display = 'none';
    } catch (e) {
        logTerminal(`Download Error: ${e.message}`, 'danger');
        alert(e.message);
    }
}

// API: Fetch Audit Logs
async function fetchAuditLogs() {
    try {
        const response = await fetch(`${API_BASE}/api/audit-logs`);
        const logs = await response.json();
        state.auditLogs = logs;
        renderAuditLogs();
        
        document.getElementById('total-shares').textContent = logs.filter(l => l.event_type === 'FILE_UPLOAD').length;
        document.getElementById('active-threats').textContent = logs.filter(l => l.status === 'BLOCKED' || l.event_type === 'SUSPICIOUS_LOGIN' || l.event_type === 'BRUTE_FORCE_BLOCKED').length;
    } catch (e) {
        console.error("Audit log error", e);
    }
}

// API: Fetch Geofencing settings
async function fetchGeofenceSettings() {
    try {
        const response = await fetch(`${API_BASE}/api/geofence`);
        const data = await response.json();
        state.geofenceConfig = data.allowed_countries;
        document.getElementById('geofence-countries').value = data.allowed_countries;
    } catch (e) {
        console.error(e);
    }
}

// API: Save Geofencing settings
async function saveGeofenceSettings() {
    const val = document.getElementById('geofence-countries').value;
    try {
        const response = await fetch(`${API_BASE}/api/geofence`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ countries: val })
        });
        if (response.ok) {
            state.geofenceConfig = val;
            logTerminal(`Geofencing whitelist modified: [${val}]`, "success");
            alert("Settings Saved!");
            runEndpointAssessment();
        }
    } catch (e) {
        alert(e.message);
    }
}

// Render Audit Logs Table
function renderAuditLogs() {
    const tbody = document.getElementById('audit-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    state.auditLogs.forEach(log => {
        const tr = document.createElement('tr');
        const dateStr = new Date(log.created_at * 1000).toLocaleString();
        
        tr.innerHTML = `
            <td>${dateStr}</td>
            <td style="font-family: monospace; font-weight: bold;">${log.event_type}</td>
            <td>${log.filename || 'N/A'}</td>
            <td>${log.ip_address} (${log.country})</td>
            <td><span class="status-badge ${log.status.toLowerCase()}">${log.status}</span></td>
            <td><span style="font-weight: 700; color: ${log.trust_score < 50 ? 'var(--neon-red)' : 'var(--neon-green)'}">${log.trust_score}%</span></td>
        `;
        tbody.appendChild(tr);
    });
}

// Show generated Share link
function displayShareLink(link) {
    const box = document.getElementById('share-link-result');
    const input = document.getElementById('share-link-url');
    box.style.display = 'block';
    input.value = link;
}

// UI Controls: Page Navigation
function switchTab(tabId) {
    state.activeTab = tabId;
    
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.getAttribute('data-tab') === tabId) {
            item.classList.add('active');
        }
    });
    
    document.querySelectorAll('.page-panel').forEach(panel => {
        panel.style.display = 'none';
    });
    document.getElementById(`${tabId}-panel`).style.display = 'flex';
    
    logTerminal(`Routed to workspace panel: ${tabId.toUpperCase()}`, 'info');
}

// Route URL Hash Parsing for download portal
function routeByHash() {
    const hash = window.location.hash;
    if (hash && hash.startsWith('#download/')) {
        const parts = hash.substring(10).split('#');
        if (parts.length === 2) {
            const meta = parts[0].split('/');
            const fileId = meta[0];
            const integrityHash = meta[1];
            const keyHash = parts[1];
            
            const authOverlay = document.getElementById('auth-overlay');
            if (authOverlay) {
                authOverlay.style.display = 'none';
            }
            
            switchTab('download');
            document.getElementById('download-file-id').value = fileId;
            document.getElementById('download-integrity-hash').value = integrityHash;
            document.getElementById('download-key-hash').value = keyHash;
            
            logTerminal(`Decrypted sharing link detected. Encrypted Payload Reference ID: ${fileId}`, 'info');
        }
    }
}

// Initialize Application UI binding
document.addEventListener('DOMContentLoaded', () => {
    const details = getEndpointDetails();
    const detailsContainer = document.getElementById('fingerprint-grid-list');
    if (detailsContainer) {
        detailsContainer.innerHTML = '';
        Object.entries(details).forEach(([key, val]) => {
            const item = document.createElement('div');
            item.className = 'fingerprint-item';
            item.innerHTML = `
                <span class="fingerprint-label">${key}</span>
                <span class="fingerprint-val">${val}</span>
            `;
            detailsContainer.appendChild(item);
        });
    }
    
    runEndpointAssessment();
    setInterval(runEndpointAssessment, 2500);
    
    const signupPass = document.getElementById('signup-password');
    const signupBar = document.getElementById('signup-strength-bar');
    const signupLabel = document.getElementById('signup-strength-label');
    
    if (signupPass && signupBar && signupLabel) {
        signupPass.addEventListener('input', () => {
            const check = checkPasswordStrength(signupPass.value);
            signupBar.className = `strength-bar ${check.class}`;
            signupLabel.textContent = `Strength: ${check.label}`;
        });
    }
    
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('file-input');
    const selectedDetails = document.getElementById('selected-file-details');
    const selectedName = document.getElementById('selected-file-name');
    const selectedSize = document.getElementById('selected-file-size');
    
    if (dropzone && fileInput) {
        dropzone.addEventListener('click', () => fileInput.click());
        
        dropzone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropzone.style.borderColor = 'var(--primary)';
        });
        
        dropzone.addEventListener('dragleave', () => {
            dropzone.style.borderColor = 'rgba(255, 255, 255, 0.12)';
        });
        
        dropzone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropzone.style.borderColor = 'rgba(255, 255, 255, 0.12)';
            if (e.dataTransfer.files.length > 0) {
                handleFileSelection(e.dataTransfer.files[0]);
            }
        });
        
        fileInput.addEventListener('change', () => {
            if (fileInput.files.length > 0) {
                handleFileSelection(fileInput.files[0]);
            }
        });
    }
    
    function handleFileSelection(file) {
        state.selectedFile = file;
        selectedName.textContent = file.name;
        selectedSize.textContent = `${(file.size / 1024).toFixed(2)} KB`;
        selectedDetails.style.display = 'flex';
        logTerminal(`File queued for client-side encryption: ${file.name} (${file.size} bytes)`, 'info');
    }
    
    const copyBtn = document.getElementById('btn-copy-link');
    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            const linkInput = document.getElementById('share-link-url');
            linkInput.select();
            document.execCommand('copy');
            logTerminal("Share link copied to clipboard.", "success");
            alert("Share Link Copied!");
        });
    }
    
    const countrySelector = document.getElementById('posture-country-select');
    if (countrySelector) {
        countrySelector.addEventListener('change', (e) => {
            state.simulatedCountry = e.target.value;
            logTerminal(`Endpoint location simulation changed to: ${state.simulatedCountry}`, 'warning');
            runEndpointAssessment();
        });
    }
    
    // Save Decrypted Document from secure preview frame
    const saveDecryptedBtn = document.getElementById('btn-download-decrypted');
    if (saveDecryptedBtn) {
        saveDecryptedBtn.addEventListener('click', () => {
            if (!state.decryptedBlobCache) return;
            
            const downloadUrl = window.URL.createObjectURL(state.decryptedBlobCache);
            const a = document.createElement('a');
            a.href = downloadUrl;
            a.download = state.decryptedFilenameCache;
            document.body.appendChild(a);
            a.click();
            a.remove();
            
            logTerminal("Decrypted file saved to storage stream.", "success");
            alert("File saved successfully!");
            
            // Clean up preview display
            document.getElementById('decrypted-preview-container').style.display = 'none';
            state.decryptedBlobCache = null;
        });
    }
    
    routeByHash();
    window.addEventListener('hashchange', routeByHash);
});
