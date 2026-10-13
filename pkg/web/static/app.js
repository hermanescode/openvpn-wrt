// OpenVPN OpenWrt Gateway Dashboard Frontend
let sessionToken = localStorage.getItem('openvpn_token') || '';
let selectedFile = null;
let currentProfiles = [];
let statusInterval = null;

// Fallback clipboard copy for plain HTTP LAN environments
function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
    } else {
        fallbackCopy(text);
    }
}

function fallbackCopy(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    try {
        document.execCommand('copy');
    } catch (err) {
        console.error('Fallback copy failed', err);
    }
    document.body.removeChild(textArea);
}

// Format bytes
function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Format seconds into HH:MM:SS
function formatDuration(sec) {
    if (!sec || sec <= 0) return '00:00:00';
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    return [h, m, s].map(v => v < 10 ? '0' + v : v).join(':');
}

// API Fetch helper
async function apiCall(endpoint, method = 'GET', body = null) {
    const headers = {};
    if (sessionToken) {
        headers['X-Session-Token'] = sessionToken;
    }
    if (body && !(body instanceof FormData)) {
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify(body);
    }

    try {
        const res = await fetch(endpoint, {
            method: method,
            headers: headers,
            body: body
        });

        if (res.status === 401) {
            // Show login modal if mutation action was unauthorized
            showLoginModal();
            return { unauthorized: true };
        }

        return await res.json();
    } catch (err) {
        console.error('API Error on ' + endpoint, err);
        return { error: err.message };
    }
}

// DOM Elements
const loginOverlay = document.getElementById('loginOverlay');
const loginForm = document.getElementById('loginForm');
const loginPassword = document.getElementById('loginPassword');
const loginError = document.getElementById('loginError');
const btnLogout = document.getElementById('btnLogout');

const statusDot = document.getElementById('statusDot');
const statusText = document.getElementById('statusText');
const profileSummary = document.getElementById('profileSummary');
const btnConnect = document.getElementById('btnConnect');
const btnDisconnect = document.getElementById('btnDisconnect');

const metricTunIP = document.getElementById('metricTunIP');
const metricPublicIP = document.getElementById('metricPublicIP');
const metricUptime = document.getElementById('metricUptime');
const metricTraffic = document.getElementById('metricTraffic');
const btnCheckIP = document.getElementById('btnCheckIP');

const sysArch = document.getElementById('sysArch');
const sysMem = document.getElementById('sysMem');

const gatewayToggle = document.getElementById('gatewayToggle');
const killswitchToggle = document.getElementById('killswitchToggle');
const gatewayRuleBadge = document.getElementById('gatewayRuleBadge');

const profileList = document.getElementById('profileList');
const logConsole = document.getElementById('logConsole');
const btnClearLogs = document.getElementById('btnClearLogs');
const btnPing = document.getElementById('btnPing');

// Modals
const uploadModal = document.getElementById('uploadModal');
const btnUploadModal = document.getElementById('btnUploadModal');
const btnCloseUpload = document.getElementById('btnCloseUpload');
const tabUploadFile = document.getElementById('tabUploadFile');
const tabPasteText = document.getElementById('tabPasteText');
const tabFileContent = document.getElementById('tabFileContent');
const tabTextContent = document.getElementById('tabTextContent');
const dropZone = document.getElementById('dropZone');
const fileInput = document.getElementById('fileInput');
const selectedFileName = document.getElementById('selectedFileName');
const pasteFilename = document.getElementById('pasteFilename');
const pasteConfig = document.getElementById('pasteConfig');
const btnSaveProfile = document.getElementById('btnSaveProfile');

const viewModal = document.getElementById('viewModal');
const btnCloseView = document.getElementById('btnCloseView');
const viewModalTitle = document.getElementById('viewModalTitle');
const viewModalContent = document.getElementById('viewModalContent');

const settingsModal = document.getElementById('settingsModal');
const btnSettings = document.getElementById('btnSettings');
const btnCloseSettings = document.getElementById('btnCloseSettings');
const settingsForm = document.getElementById('settingsForm');
const newPassword = document.getElementById('newPassword');
const autoConnectSetting = document.getElementById('autoConnectSetting');

// Authentication handling
function showLoginModal() {
    loginOverlay.classList.remove('hidden');
    loginPassword.focus();
}

function hideLoginModal() {
    loginOverlay.classList.add('hidden');
    loginError.classList.add('hidden');
    loginPassword.value = '';
}

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    loginError.classList.add('hidden');
    const pwd = loginPassword.value;
    const res = await apiCall('/api/auth/login', 'POST', { password: pwd });
    if (res.success) {
        sessionToken = res.token || '';
        localStorage.setItem('openvpn_token', sessionToken);
        hideLoginModal();
        btnLogout.classList.remove('hidden');
        refreshAll();
    } else {
        loginError.innerText = res.error || 'Authentication failed';
        loginError.classList.remove('hidden');
    }
});

btnLogout.addEventListener('click', async () => {
    await apiCall('/api/auth/logout', 'POST');
    sessionToken = '';
    localStorage.removeItem('openvpn_token');
    btnLogout.classList.add('hidden');
    refreshStatus();
});

// Status Polling
async function refreshStatus() {
    const data = await apiCall('/api/status');
    if (!data || !data.status) return;

    const s = data.status;

    // Defensive property rendering
    const state = s.state || 'disconnected';
    statusDot.className = 'status-dot ' + state;
    statusText.innerText = state.toUpperCase();

    if (state === 'connected') {
        btnConnect.classList.add('hidden');
        btnDisconnect.classList.remove('hidden');
    } else {
        btnConnect.classList.remove('hidden');
        btnDisconnect.classList.add('hidden');
    }

    if (s.active_profile) {
        let sub = s.active_profile;
        if (s.remote_server) sub += ' (' + s.remote_server + ' ' + (s.protocol || '') + ')';
        profileSummary.innerText = sub;
    } else {
        profileSummary.innerText = 'No profile selected';
    }

    metricTunIP.innerText = s.tunnel_ip || '--';
    metricUptime.innerText = formatDuration(s.uptime_seconds);
    metricTraffic.innerText = formatBytes(s.bytes_in) + ' / ' + formatBytes(s.bytes_out);

    gatewayToggle.checked = !!s.gateway_mode;
    killswitchToggle.checked = !!s.kill_switch;

    if (data.system) {
        sysArch.innerText = (data.system.arch || 'arm').toUpperCase();
        sysMem.innerText = 'Alloc: ' + (data.system.alloc_mb || 0).toFixed(1) + ' MB';
    }

    if (data.auth) {
        if (data.auth.is_authenticated && data.auth.password_required) {
            btnLogout.classList.remove('hidden');
        } else {
            btnLogout.classList.add('hidden');
        }
    }
}

// Fetch Logs
async function refreshLogs() {
    const data = await apiCall('/api/logs');
    if (data && data.logs) {
        const atBottom = logConsole.scrollHeight - logConsole.scrollTop <= logConsole.clientHeight + 40;
        logConsole.innerText = data.logs.join('\n');
        if (atBottom) {
            logConsole.scrollTop = logConsole.scrollHeight;
        }
    }
}

// Profiles
async function refreshProfiles() {
    const data = await apiCall('/api/profiles');
    if (!data || !data.profiles) return;

    currentProfiles = data.profiles;
    profileList.innerHTML = '';

    if (currentProfiles.length === 0) {
        profileList.innerHTML = '<div class="empty-state">No .ovpn profiles found. Upload one to get started!</div>';
        return;
    }

    currentProfiles.forEach(p => {
        const item = document.createElement('div');
        item.className = 'profile-item' + (p.is_active ? ' active' : '');

        let meta = formatBytes(p.size);
        if (p.remote) meta += ' | ' + p.remote + ' (' + (p.proto || 'UDP') + ')';

        item.innerHTML = `
            <div class="profile-info">
                <span class="profile-name">${p.is_active ? '⭐ ' : ''}${escapeHtml(p.name)}</span>
                <span class="profile-meta">${meta}</span>
            </div>
            <div class="profile-actions">
                <button class="btn btn-sm btn-outline btn-view" title="View config">👁️</button>
                <button class="btn btn-sm ${p.is_active ? 'btn-success' : 'btn-outline'} btn-select">
                    ${p.is_active ? 'Selected' : 'Use'}
                </button>
                <button class="btn btn-sm btn-outline btn-delete" title="Delete">🗑️</button>
            </div>
        `;

        item.querySelector('.btn-select').addEventListener('click', async (e) => {
            e.stopPropagation();
            await selectProfile(p.name);
        });

        item.querySelector('.btn-view').addEventListener('click', async (e) => {
            e.stopPropagation();
            await viewProfile(p.name);
        });

        item.querySelector('.btn-delete').addEventListener('click', async (e) => {
            e.stopPropagation();
            if (confirm(`Delete profile "${p.name}"?`)) {
                await deleteProfile(p.name);
            }
        });

        profileList.appendChild(item);
    });
}

async function selectProfile(name) {
    const res = await apiCall('/api/profiles/select', 'POST', { profile: name });
    if (res.success) {
        refreshProfiles();
        refreshStatus();
    }
}

async function viewProfile(name) {
    const res = await apiCall(`/api/profiles/content?filename=${encodeURIComponent(name)}`);
    if (res.success) {
        viewModalTitle.innerText = name;
        viewModalContent.innerText = res.content;
        viewModal.classList.remove('hidden');
    }
}

async function deleteProfile(name) {
    const res = await apiCall('/api/profiles/delete', 'POST', { filename: name });
    if (res.success) {
        refreshProfiles();
    }
}

// Connect / Disconnect
btnConnect.addEventListener('click', async () => {
    btnConnect.disabled = true;
    statusText.innerText = 'CONNECTING...';
    statusDot.className = 'status-dot connecting';
    const res = await apiCall('/api/connect', 'POST', {});
    btnConnect.disabled = false;
    if (res.error) {
        alert('Connect failed: ' + res.error);
    }
    refreshStatus();
    refreshLogs();
});

btnDisconnect.addEventListener('click', async () => {
    btnDisconnect.disabled = true;
    const res = await apiCall('/api/disconnect', 'POST', {});
    btnDisconnect.disabled = false;
    refreshStatus();
    refreshLogs();
});

// Gateway & KillSwitch Toggles
gatewayToggle.addEventListener('change', async () => {
    const enabled = gatewayToggle.checked;
    gatewayRuleBadge.innerText = 'Updating firewall...';
    const res = await apiCall('/api/gateway/toggle', 'POST', { enable: enabled });
    if (res.success) {
        gatewayRuleBadge.innerText = enabled ? 'Firewall: Active' : 'Firewall: Disabled';
        gatewayRuleBadge.className = 'badge ' + (enabled ? 'badge-success' : '');
    } else {
        gatewayToggle.checked = !enabled;
        alert('Failed to update firewall: ' + (res.error || 'Unknown error'));
    }
});

killswitchToggle.addEventListener('change', async () => {
    const ks = killswitchToggle.checked;
    const res = await apiCall('/api/gateway/toggle', 'POST', { kill_switch: ks });
    if (!res.success) {
        killswitchToggle.checked = !ks;
        alert('Failed to update kill switch: ' + (res.error || 'Unknown error'));
    }
});

// Check Public IP
btnCheckIP.addEventListener('click', async () => {
    metricPublicIP.innerText = 'Checking...';
    btnCheckIP.disabled = true;
    const res = await apiCall('/api/myip');
    btnCheckIP.disabled = false;
    if (res.success) {
        metricPublicIP.innerText = res.ip;
    } else {
        metricPublicIP.innerText = 'Failed';
    }
});

// Ping Test
btnPing.addEventListener('click', async () => {
    const target = prompt('Enter IP or domain to ping:', '1.1.1.1');
    if (!target) return;
    btnPing.disabled = true;
    btnPing.innerText = 'Pinging...';
    const res = await apiCall(`/api/ping?target=${encodeURIComponent(target)}`);
    btnPing.disabled = false;
    btnPing.innerText = '📶 Ping Test';
    if (res.success) {
        alert(res.output);
    } else {
        alert('Ping failed:\n' + (res.error || 'Unreachable'));
    }
});

// Clear Logs
btnClearLogs.addEventListener('click', async () => {
    await apiCall('/api/logs/clear', 'POST');
    logConsole.innerText = '';
});

// Upload Modal Logic
btnUploadModal.addEventListener('click', () => {
    uploadModal.classList.remove('hidden');
    selectedFile = null;
    selectedFileName.innerText = '';
    pasteFilename.value = '';
    pasteConfig.value = '';
});
btnCloseUpload.addEventListener('click', () => uploadModal.classList.add('hidden'));

tabUploadFile.addEventListener('click', () => {
    tabUploadFile.classList.add('active');
    tabPasteText.classList.remove('active');
    tabFileContent.classList.remove('hidden');
    tabTextContent.classList.add('hidden');
});

tabPasteText.addEventListener('click', () => {
    tabPasteText.classList.add('active');
    tabUploadFile.classList.remove('active');
    tabTextContent.classList.remove('hidden');
    tabFileContent.classList.add('hidden');
});

dropZone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        selectedFile = e.target.files[0];
        selectedFileName.innerText = 'Selected: ' + selectedFile.name;
    }
});

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = 'var(--accent-blue)';
});

dropZone.addEventListener('dragleave', () => {
    dropZone.style.borderColor = 'var(--border-color)';
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.style.borderColor = 'var(--border-color)';
    if (e.dataTransfer.files.length > 0) {
        selectedFile = e.dataTransfer.files[0];
        selectedFileName.innerText = 'Selected: ' + selectedFile.name;
    }
});

btnSaveProfile.addEventListener('click', async () => {
    if (tabUploadFile.classList.contains('active')) {
        if (!selectedFile) {
            alert('Please select a .ovpn file');
            return;
        }
        const formData = new FormData();
        formData.append('file', selectedFile);
        const res = await apiCall('/api/profiles/upload', 'POST', formData);
        if (res.success) {
            uploadModal.classList.add('hidden');
            refreshProfiles();
        } else {
            alert('Upload failed: ' + (res.error || 'Unknown error'));
        }
    } else {
        const fn = pasteFilename.value.trim();
        const cnt = pasteConfig.value.trim();
        if (!fn || !cnt) {
            alert('Please provide both profile name and config content');
            return;
        }
        const res = await apiCall('/api/profiles/upload', 'POST', { filename: fn, content: cnt });
        if (res.success) {
            uploadModal.classList.add('hidden');
            refreshProfiles();
        } else {
            alert('Save failed: ' + (res.error || 'Unknown error'));
        }
    }
});

// View Modal Close
btnCloseView.addEventListener('click', () => viewModal.classList.add('hidden'));

// Settings Modal
btnSettings.addEventListener('click', () => settingsModal.classList.remove('hidden'));
btnCloseSettings.addEventListener('click', () => settingsModal.classList.add('hidden'));

settingsForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const pwd = newPassword.value.trim();
    if (pwd) {
        const pRes = await apiCall('/api/auth/password', 'POST', { new_password: pwd });
        if (!pRes.success) {
            alert('Failed to update password: ' + pRes.error);
            return;
        }
    }
    const autoConn = autoConnectSetting.checked;
    await apiCall('/api/config', 'POST', { auto_connect: autoConn });
    settingsModal.classList.add('hidden');
    newPassword.value = '';
    alert('Settings saved successfully.');
});

// Helper Escape HTML
function escapeHtml(text) {
    const div = document.createElement('div');
    div.innerText = text;
    return div.innerHTML;
}

// Initial Load
function refreshAll() {
    refreshStatus();
    refreshProfiles();
    refreshLogs();
}

refreshAll();
statusInterval = setInterval(() => {
    refreshStatus();
    refreshLogs();
}, 2500);
