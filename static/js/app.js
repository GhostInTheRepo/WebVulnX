/**
 * WebVulnX - Application Logic
 * Frontend JavaScript for the security scanner
 */

// API Base URL
const API_BASE = '';

// Application State
const state = {
    activeView: 'vuln-scan',
    scanResults: {
        vulnScan: null,
        portScan: null,
        dirFuzz: null,
        techDetect: null,
        dnsRecon: null
    },
    isScanning: false
};

// DOM Elements
const elements = {
    navItems: null,
    scanViews: null,
    toastContainer: null
};

/**
 * Initialize the application
 */
document.addEventListener('DOMContentLoaded', () => {
    initializeElements();
    setupEventListeners();
    showView('vuln-scan');
});

/**
 * Initialize DOM element references
 */
function initializeElements() {
    elements.navItems = document.querySelectorAll('.nav-item');
    elements.scanViews = document.querySelectorAll('.scan-view');

    elements.toastContainer = document.createElement('div');
    elements.toastContainer.className = 'toast-container';
    document.body.appendChild(elements.toastContainer);

    // Create sidebar overlay for mobile
    const overlay = document.createElement('div');
    overlay.className = 'sidebar-overlay';
    document.body.appendChild(overlay);
    elements.overlay = overlay;

    elements.sidebar = document.querySelector('.sidebar');
    elements.menuToggle = document.getElementById('menu-toggle');
    elements.themeToggle = document.getElementById('theme-toggle');

    // Initialize Theme
    initializeTheme();
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Navigation
    elements.navItems.forEach(item => {
        item.addEventListener('click', () => {
            const viewId = item.dataset.view;
            showView(viewId);
            // Close sidebar on mobile when item selected
            closeSidebar();
        });
    });

    // Mobile Menu
    elements.menuToggle?.addEventListener('click', toggleSidebar);
    elements.overlay?.addEventListener('click', closeSidebar);

    // Theme Toggle
    elements.themeToggle?.addEventListener('click', toggleTheme);

    // Scan buttons
    document.getElementById('vuln-scan-btn')?.addEventListener('click', runVulnScan);
    document.getElementById('port-scan-btn')?.addEventListener('click', runPortScan);
    document.getElementById('dir-fuzz-btn')?.addEventListener('click', runDirFuzz);
    document.getElementById('tech-detect-btn')?.addEventListener('click', runTechDetect);
    document.getElementById('dns-recon-btn')?.addEventListener('click', runDNSRecon);

    // PDF buttons
    document.querySelectorAll('.pdf-btn').forEach(btn => {
        btn.addEventListener('click', generatePDF);
    });

    // Enter key on inputs
    document.querySelectorAll('.target-input').forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const btn = input.closest('.input-section').querySelector('.scan-btn');
                if (btn && !btn.disabled) {
                    btn.click();
                }
            }
        });
    });
}

/**
 * Show a specific scan view
 */
function showView(viewId) {
    state.activeView = viewId;

    // Update navigation
    elements.navItems.forEach(item => {
        item.classList.toggle('active', item.dataset.view === viewId);
    });

    // Update views
    elements.scanViews.forEach(view => {
        view.classList.toggle('active', view.id === viewId);
    });
}

/**
 * Run vulnerability scan
 */
async function runVulnScan() {
    const input = document.getElementById('vuln-target');
    const btn = document.getElementById('vuln-scan-btn');
    const resultsBody = document.querySelector('#vuln-scan .results-body');

    const target = input.value.trim();
    if (!target) {
        showToast('Please enter a target URL', 'warning');
        input.focus();
        return;
    }

    setButtonLoading(btn, true, 'Scanning...');
    showLoading(resultsBody, 'Running vulnerability scan...', 'vuln');

    try {
        const response = await fetch(`${API_BASE}/api/vuln-scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const data = await response.json();

        if (data.success) {
            state.scanResults.vulnScan = data.results;
            renderVulnResults(data.results);
            updateVulnStats(data.results);
            showToast(`Scan complete! Found ${data.results.vulnerabilities?.length || 0} findings`, 'success');
        } else {
            throw new Error(data.error || 'Scan failed');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
        renderError(resultsBody, error.message);
    } finally {
        stopProgress();
        setButtonLoading(btn, false, 'Start Scanning');
    }
}

/**
 * Run port scan
 */
async function runPortScan() {
    const input = document.getElementById('port-target');
    const btn = document.getElementById('port-scan-btn');
    const resultsBody = document.querySelector('#port-scan .results-body');

    const target = input.value.trim();
    if (!target) {
        showToast('Please enter a target', 'warning');
        input.focus();
        return;
    }

    // Get scan type from active option
    const scanType = document.querySelector('#port-scan .option-btn.active')?.dataset.type || 'common';

    setButtonLoading(btn, true, 'Scanning...');
    showLoading(resultsBody, 'Scanning ports...', 'port');

    try {
        const response = await fetch(`${API_BASE}/api/port-scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target, scan_type: scanType })
        });

        const data = await response.json();

        if (data.success) {
            state.scanResults.portScan = data.results;
            renderPortResults(data.results);
            showToast(`Found ${data.results.open_ports || 0} open ports`, 'success');
        } else {
            throw new Error(data.error || 'Scan failed');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
        renderError(resultsBody, error.message);
    } finally {
        setButtonLoading(btn, false, 'Port Scanning');
    }
}

/**
 * Run directory fuzzing
 */
async function runDirFuzz() {
    const input = document.getElementById('dir-target');
    const btn = document.getElementById('dir-fuzz-btn');
    const resultsBody = document.querySelector('#dir-fuzz .results-body');

    const target = input.value.trim();
    if (!target) {
        showToast('Please enter a target URL', 'warning');
        input.focus();
        return;
    }

    setButtonLoading(btn, true, 'Fuzzing...');
    showLoading(resultsBody, 'Discovering directories...', 'dir');

    try {
        const response = await fetch(`${API_BASE}/api/dir-fuzz`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const data = await response.json();

        if (data.success) {
            state.scanResults.dirFuzz = data.results;
            renderDirResults(data.results);
            showToast(`Found ${data.results.found_count || 0} paths`, 'success');
        } else {
            throw new Error(data.error || 'Scan failed');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
        renderError(resultsBody, error.message);
    } finally {
        setButtonLoading(btn, false, 'Start Fuzzing');
    }
}

/**
 * Run technology detection
 */
async function runTechDetect() {
    const input = document.getElementById('tech-target');
    const btn = document.getElementById('tech-detect-btn');
    const resultsBody = document.querySelector('#tech-detect .results-body');

    const target = input.value.trim();
    if (!target) {
        showToast('Please enter a target URL', 'warning');
        input.focus();
        return;
    }

    setButtonLoading(btn, true, 'Detecting...');
    showLoading(resultsBody, 'Analyzing technologies...', 'tech');

    try {
        const response = await fetch(`${API_BASE}/api/tech-detect`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const data = await response.json();

        if (data.success) {
            state.scanResults.techDetect = data.results;
            renderTechResults(data.results);
            showToast(`Detected ${data.results.tech_count || 0} technologies`, 'success');
        } else {
            throw new Error(data.error || 'Detection failed');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
        renderError(resultsBody, error.message);
    } finally {
        setButtonLoading(btn, false, 'Detect Technologies');
    }
}

/**
 * Run DNS Reconnaissance
 */
async function runDNSRecon() {
    const input = document.getElementById('dns-target');
    const btn = document.getElementById('dns-recon-btn');
    const resultsBody = document.querySelector('#dns-recon .results-body');

    const target = input.value.trim();
    if (!target) {
        showToast('Please enter a target domain', 'warning');
        input.focus();
        return;
    }

    setButtonLoading(btn, true, 'Reconnaissance...');
    showLoading(resultsBody, 'Fetching DNS records...', 'dns');

    try {
        const response = await fetch(`${API_BASE}/api/dns-recon`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });

        const data = await response.json();

        if (data.success) {
            state.scanResults.dnsRecon = data.results;
            renderDNSResults(data.results);
            showToast(`Found ${data.results.total_records || 0} records`, 'success');
        } else {
            throw new Error(data.error || 'Recon failed');
        }
    } catch (error) {
        showToast(`Error: ${error.message}`, 'error');
        renderError(resultsBody, error.message);
    } finally {
        setButtonLoading(btn, false, 'Start Recon');
    }
}

/**
 * Generate PDF report
 */
async function generatePDF() {
    const results = state.scanResults;

    // Check if we have any results
    if (!results.vulnScan && !results.portScan && !results.dirFuzz && !results.techDetect && !results.dnsRecon) {
        showToast('No scan results to export. Run a scan first.', 'warning');
        return;
    }

    showToast('Generating PDF report...', 'info');

    try {
        // Prepare data
        const reportData = {
            target: results.vulnScan?.target || results.portScan?.target ||
                results.dirFuzz?.target || results.techDetect?.target || 'Unknown',
            vuln_scan: results.vulnScan,
            port_scan: results.portScan,
            dir_fuzz: results.dirFuzz,
            tech_detect: results.techDetect,
            dns_recon: results.dnsRecon
        };

        const response = await fetch(`${API_BASE}/api/generate-pdf`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(reportData)
        });

        if (!response.ok) {
            throw new Error('Failed to generate PDF');
        }

        // Download the PDF
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `vulnerability_report_${new Date().toISOString().slice(0, 10)}.pdf`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);

        showToast('PDF report downloaded successfully!', 'success');
    } catch (error) {
        showToast(`Error generating PDF: ${error.message}`, 'error');
    }
}

/**
 * Render vulnerability scan results with CVSS and recommendations
 */
function renderVulnResults(results) {
    const container = document.querySelector('#vuln-scan .results-body');
    const vulns = results.vulnerabilities || [];

    if (vulns.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">✅</div>
                <div class="empty-text">No vulnerabilities detected</div>
                <div class="empty-hint">The target appears to be secure against common vulnerabilities</div>
            </div>
        `;
        return;
    }

    // Sort by CVSS score descending
    vulns.sort((a, b) => (b.cvss_score || 0) - (a.cvss_score || 0));

    let infoHtml = '';
    if (results.ip_address) {
        infoHtml = `
            <div class="info-grid">
                <div class="info-card">
                    <div class="info-card-label">IP Address</div>
                    <div class="info-card-value">${escapeHtml(results.ip_address)}</div>
                </div>
            </div>
        `;
    }

    container.innerHTML = infoHtml + vulns.map((vuln, index) => `
        <div class="result-item animate-slide-up stagger-${Math.min(index + 1, 5)}">
            <div class="result-header">
                <span class="result-name">
                    ${getVulnIcon(vuln.type)} ${escapeHtml(vuln.name)}
                </span>
                <div class="result-badges">
                    <span class="severity-badge ${(vuln.severity || 'info').toLowerCase()}">${vuln.severity || 'INFO'}</span>
                    ${vuln.cvss_score ? `<span class="cvss-badge" title="${vuln.cvss_vector || ''}">CVSS ${vuln.cvss_score}</span>` : ''}
                </div>
            </div>
            
            ${vuln.cwe ? `<div class="vuln-cwe">${escapeHtml(vuln.cwe)}</div>` : ''}
            
            ${vuln.description ? `<div class="result-description">${escapeHtml(vuln.description)}</div>` : ''}
            
            ${vuln.evidence ? `
                <div class="vuln-evidence">
                    <strong>📌 Evidence:</strong> ${escapeHtml(vuln.evidence)}
                </div>
            ` : ''}
            
            ${vuln.matched_at ? `<div class="result-url">🔗 ${escapeHtml(vuln.matched_at)}</div>` : ''}
            
            ${vuln.parameter ? `<div class="vuln-param">📍 Vulnerable Parameter: <code>${escapeHtml(vuln.parameter)}</code></div>` : ''}
            
            ${vuln.recommendation && vuln.recommendation.length > 0 ? `
                <div class="vuln-recommendations">
                    <strong>✅ Recommendations:</strong>
                    <ul>
                        ${vuln.recommendation.slice(0, 3).map(rec => `<li>${escapeHtml(rec)}</li>`).join('')}
                    </ul>
                </div>
            ` : ''}
            
            ${vuln.references && vuln.references.length > 0 ? `
                <div class="vuln-references">
                    <strong>📚 References:</strong>
                    ${vuln.references.slice(0, 2).map(ref => `<a href="${escapeHtml(ref)}" target="_blank" rel="noopener">${escapeHtml(ref.split('/').slice(-1)[0] || ref)}</a>`).join(' | ')}
                </div>
            ` : ''}
        </div>
    `).join('');
}

/**
 * Update vulnerability stats badges
 */
function updateVulnStats(results) {
    const vulns = results.vulnerabilities || [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

    vulns.forEach(v => {
        const sev = (v.severity || 'info').toLowerCase();
        if (counts.hasOwnProperty(sev)) counts[sev]++;
    });

    const statsContainer = document.querySelector('#vuln-scan .results-stats');
    if (statsContainer) {
        statsContainer.innerHTML = `
            ${counts.critical > 0 ? `<span class="stat-badge critical">🔴 ${counts.critical} Critical</span>` : ''}
            ${counts.high > 0 ? `<span class="stat-badge high">🟠 ${counts.high} High</span>` : ''}
            ${counts.medium > 0 ? `<span class="stat-badge medium">🟡 ${counts.medium} Medium</span>` : ''}
            ${counts.low > 0 ? `<span class="stat-badge low">🟢 ${counts.low} Low</span>` : ''}
            ${counts.info > 0 ? `<span class="stat-badge info">ℹ️ ${counts.info} Info</span>` : ''}
        `;
    }
}

/**
 * Render port scan results
 */
function renderPortResults(results) {
    const container = document.querySelector('#port-scan .results-body');
    const ports = results.ports || [];

    // Update stats
    const statsContainer = document.querySelector('#port-scan .results-stats');
    if (statsContainer) {
        statsContainer.innerHTML = `
            <span class="stat-badge info">🔌 ${results.open_ports || 0} Open</span>
            <span class="stat-badge">⏱️ ${results.scan_time || 0}s</span>
        `;
    }

    if (ports.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🔒</div>
                <div class="empty-text">No open ports detected</div>
                <div class="empty-hint">The target may be behind a firewall or all ports are closed</div>
            </div>
        `;
        return;
    }

    let infoHtml = '';
    if (results.ip_address) {
        infoHtml = `
            <div class="info-grid">
                <div class="info-card">
                    <div class="info-card-label">IP Address</div>
                    <div class="info-card-value">${escapeHtml(results.ip_address)}</div>
                </div>
            </div>
        `;
    }

    container.innerHTML = infoHtml + `
        <div class="port-list">
            ${ports.map((port, index) => `
                <div class="port-item animate-slide-up stagger-${Math.min(index + 1, 5)}">
                    <span class="port-number">${port.port}</span>
                    <span class="port-state ${port.state}">${port.state}</span>
                    <span class="port-service">${escapeHtml(port.service || 'unknown')}</span>
                    <span class="port-version">${escapeHtml(port.version || '')}</span>
                    <span class="port-risk">
                        <span class="risk-indicator ${port.risk || 'low'}"></span>
                    </span>
                </div>
            `).join('')}
        </div>
    `;
}

/**
 * Render directory fuzzing results
 */
function renderDirResults(results) {
    const container = document.querySelector('#dir-fuzz .results-body');
    const discovered = results.discovered || [];

    // Update stats
    const statsContainer = document.querySelector('#dir-fuzz .results-stats');
    if (statsContainer) {
        statsContainer.innerHTML = `
            <span class="stat-badge info">📁 ${results.found_count || 0} Found</span>
            <span class="stat-badge">🔍 ${results.requests_made || 0} Requests</span>
            <span class="stat-badge">⏱️ ${results.scan_time || 0}s</span>
        `;
    }

    if (discovered.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">📂</div>
                <div class="empty-text">No hidden paths discovered</div>
                <div class="empty-hint">Common directories and files were not found on this target</div>
            </div>
        `;
        return;
    }

    let infoHtml = '';
    if (results.ip_address) {
        infoHtml = `
            <div class="info-grid">
                <div class="info-card">
                    <div class="info-card-content-wrapper">
                        <div>
                            <div class="info-card-label">IP Address</div>
                            <div class="info-card-value">${escapeHtml(results.ip_address)}</div>
                        </div>
                        <div class="filter-dropdown-container">
                            <button class="filter-btn" onclick="toggleFilterDropdown(event)">
                                🌪️ Filter Paths
                            </button>
                            <div class="filter-dropdown" id="path-filter-dropdown">
                                <div class="filter-option" onclick="filterPaths('all')">All</div>
                                <div class="filter-option" onclick="filterPaths(200)">200 OK</div>
                                <div class="filter-option" onclick="filterPaths(301)">301 Moved</div>
                                <div class="filter-option" onclick="filterPaths(302)">302 Found</div>
                                <div class="filter-option" onclick="filterPaths(401)">401 Unauth</div>
                                <div class="filter-option" onclick="filterPaths(403)">403 Forbidden</div>
                                <div class="filter-option" onclick="filterPaths(404)">404 Not Found</div>
                                <div class="filter-option" onclick="filterPaths(500)">500 Error</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    container.innerHTML = infoHtml + `
        <div class="dir-list">
            ${discovered.map((item, index) => `
                <div class="dir-item animate-slide-up stagger-${Math.min(index + 1, 5)}">
                    <span class="dir-path">/${escapeHtml(item.path)}</span>
                    <span class="dir-status ${getStatusClass(item.status)}">${item.status}</span>
                    <span class="dir-size">${formatBytes(item.length)}</span>
                    <span class="dir-type">${escapeHtml(item.type || 'other')}</span>
                </div>
            `).join('')}
        </div>
    `;
}

/**
 * Render technology detection results
 */
function renderTechResults(results) {
    const container = document.querySelector('#tech-detect .results-body');
    const technologies = results.technologies || [];

    // Update stats
    const statsContainer = document.querySelector('#tech-detect .results-stats');
    if (statsContainer) {
        statsContainer.innerHTML = `
            <span class="stat-badge info">🔧 ${results.tech_count || 0} Technologies</span>
            <span class="stat-badge">⏱️ ${results.scan_time || 0}s</span>
        `;
    }

    if (technologies.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🔍</div>
                <div class="empty-text">No technologies detected</div>
                <div class="empty-hint">Unable to identify the technology stack</div>
            </div>
        `;
        return;
    }

    // Add info cards at top
    let infoHtml = '';
    if (results.ip_address || results.ssl) {
        infoHtml = `
            <div class="info-grid">
                ${results.ip_address ? `
                    <div class="info-card">
                        <div class="info-card-label">IP Address</div>
                        <div class="info-card-value">${escapeHtml(results.ip_address)}</div>
                    </div>
                ` : ''}
                ${results.ssl?.enabled ? `
                    <div class="info-card">
                        <div class="info-card-label">SSL Status</div>
                        <div class="info-card-value ${results.ssl.valid ? 'highlight' : ''}">${results.ssl.valid ? '✅ Valid' : '⚠️ Invalid'}</div>
                    </div>
                ` : ''}
            </div>
        `;
    }

    container.innerHTML = `
        ${infoHtml}
        <div class="tech-list">
            ${technologies.map((tech, index) => `
                <div class="tech-item animate-slide-up stagger-${Math.min(index + 1, 5)}">
                    <span class="tech-icon">${tech.icon || '🔧'}</span>
                    <div class="tech-info">
                        <div class="tech-name">${escapeHtml(tech.name)}</div>
                        ${tech.version ? `<div class="tech-version">v${escapeHtml(tech.version)}</div>` : ''}
                    </div>
                    <span class="tech-category">${escapeHtml(tech.category || 'Other')}</span>
                    <div class="tech-confidence">
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: ${tech.confidence || 50}%"></div>
                        </div>
                        <span>${tech.confidence || 50}%</span>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

/**
 * Set button loading state
 */
function setButtonLoading(btn, loading, text) {
    if (!btn) return;

    btn.disabled = loading;
    btn.classList.toggle('scanning', loading);
    btn.innerHTML = loading
        ? `<span class="spinner"></span> ${text}`
        : `🚀 ${text}`;
}

/**
 * Show loading state with animated progress bar
 */
let progressInterval = null;

function showLoading(container, message = 'Loading...', scanType = 'vuln') {
    if (!container) return;

    // Configuration for different scan types
    const SCAN_CONFIGS = {
        'vuln': {
            title: 'Security Scan in Progress',
            icon: '🔍',
            stages: [
                { percent: 0, text: 'Initializing scan...' },
                { percent: 10, text: 'Connecting to target...' },
                { percent: 20, text: 'Checking security headers...' },
                { percent: 35, text: 'Testing for CSRF vulnerabilities...' },
                { percent: 50, text: 'Scanning for XSS vulnerabilities...' },
                { percent: 65, text: 'Testing SQL injection points...' },
                { percent: 75, text: 'Checking sensitive files...' },
                { percent: 85, text: 'Analyzing CORS configuration...' },
                { percent: 92, text: 'Verifying SSL/TLS...' },
                { percent: 98, text: 'Generating report...' }
            ],
            modules: [
                { id: 'headers', label: '🛡️ Headers', index: 0 },
                { id: 'csrf', label: '🔒 CSRF', index: 1 },
                { id: 'xss', label: '💉 XSS', index: 2 },
                { id: 'sqli', label: '🗄️ SQLi', index: 3 },
                { id: 'files', label: '📁 Files', index: 4 },
                { id: 'ssl', label: '🔐 SSL', index: 5 }
            ]
        },
        'port': {
            title: 'Port Scan in Progress',
            icon: '🔌',
            stages: [
                { percent: 0, text: 'Initializing scanner...' },
                { percent: 15, text: 'Resolving IP address...' },
                { percent: 30, text: 'Scanning top ports...' },
                { percent: 60, text: 'Analyzing services...' },
                { percent: 85, text: 'Verifying results...' },
                { percent: 98, text: 'Finalizing...' }
            ],
            modules: [
                { id: 'open_ports', label: '🔌 Open Ports', index: 0 }
            ]
        },
        'dir': {
            title: 'Directory Fuzzing in Progress',
            icon: '📁',
            stages: [
                { percent: 0, text: 'Initializing fuzzer...' },
                { percent: 20, text: 'Fuzzing directories...' },
                { percent: 40, text: 'Checking file extensions...' },
                { percent: 60, text: 'Analyzing responses...' },
                { percent: 80, text: 'Verifying status codes...' },
                { percent: 98, text: 'Finalizing...' }
            ],
            modules: [
                { id: 'dir_enum', label: '📂 Directory Enumeration', index: 0 },
                { id: 'file_enum', label: '📄 File Enumeration', index: 1 },
                { id: 'hidden', label: '👻 Hidden Paths', index: 2 },
                { id: 'sensitive', label: '🔒 Sensitive Files', index: 3 },
                { id: 'http_status', label: '📊 HTTP Status Analysis', index: 4 }
            ]
        },
        'tech': {
            title: 'Technology Detection in Progress',
            icon: '🔧',
            stages: [
                { percent: 0, text: 'Initializing detector...' },
                { percent: 20, text: 'Analyzing headers...' },
                { percent: 40, text: 'Scanning body content...' },
                { percent: 60, text: 'Detecting frameworks...' },
                { percent: 80, text: 'Identifying CMS...' },
                { percent: 98, text: 'Finalizing...' }
            ],
            modules: [
                { id: 'server', label: '🌐 Web Server Detection', index: 0 },
                { id: 'lang', label: '💻 Programming Language', index: 1 },
                { id: 'framework', label: '🏗️ Framework Detection', index: 2 },
                { id: 'cms', label: '📝 CMS Detection', index: 3 },
                { id: 'js_lib', label: '📜 JavaScript Libraries', index: 4 }
            ]
        },
        'dns': {
            title: 'DNS Reconnaissance in Progress',
            icon: '🌍',
            stages: [
                { percent: 0, text: 'Initializing recon...' },
                { percent: 30, text: 'Querying nameservers...' },
                { percent: 60, text: 'Enumerating subdomains...' },
                { percent: 85, text: 'Fetching records...' },
                { percent: 98, text: 'Finalizing...' }
            ],
            modules: [
                { id: 'dns_rec', label: '📋 DNS Records', index: 0 },
                { id: 'subdomains', label: '🌐 Subdomain Enumeration', index: 1 }
            ]
        }
    };

    const config = SCAN_CONFIGS[scanType] || SCAN_CONFIGS['vuln'];
    const scanStages = config.stages;

    // Generate modules HTML
    const modulesHtml = config.modules.map((mod, i) => 
        `<div class="stage-item ${i === 0 ? 'active' : ''}" data-index="${i}">${mod.label}</div>`
    ).join('');

    container.innerHTML = `
        <div class="scan-progress-container">
            <div class="scan-progress-header">
                <div class="scan-icon">${config.icon}</div>
                <div class="scan-title">${config.title}</div>
            </div>
            <div class="scan-progress-box">
                <div class="progress-fill" id="progress-fill"></div>
                <div class="progress-percent" id="progress-percent">0%</div>
            </div>
            <div class="scan-status" id="scan-status">${scanStages[0].text}</div>
            <div class="scan-stages">
                ${modulesHtml}
            </div>
        </div>
    `;

    // Clear any existing interval
    if (progressInterval) clearInterval(progressInterval);

    let stageIndex = 0;
    const progressFill = document.getElementById('progress-fill');
    const progressPercent = document.getElementById('progress-percent');
    const scanStatus = document.getElementById('scan-status');
    const stageItems = container.querySelectorAll('.stage-item');
    
    // Calculate stage transitions
    const totalModules = config.modules.length;
    const totalStages = scanStages.length;
    
    // Animate progress
    progressInterval = setInterval(() => {
        if (stageIndex < totalStages) {
            const stage = scanStages[stageIndex];

            // Update progress bar
            if (progressFill) progressFill.style.width = `${stage.percent}%`;
            if (progressPercent) progressPercent.textContent = `${stage.percent}%`;
            if (scanStatus) scanStatus.textContent = stage.text;

            // Update active module based on progress
            // Simple mapping: distribute modules across the progress
            if (totalModules > 0) {
                const progressRatio = stageIndex / (totalStages - 1);
                const activeModuleIndex = Math.min(
                    Math.floor(progressRatio * totalModules), 
                    totalModules - 1
                );
                
                stageItems.forEach((item, i) => {
                    if (i < activeModuleIndex) {
                        item.classList.remove('active');
                        item.classList.add('complete');
                    } else if (i === activeModuleIndex) {
                        item.classList.add('active');
                        item.classList.remove('complete');
                    } else {
                        item.classList.remove('active', 'complete');
                    }
                });
            }

            stageIndex++;
        }
    }, 2000);
}

/**
 * Stop progress animation
 */
function stopProgress() {
    if (progressInterval) {
        clearInterval(progressInterval);
        progressInterval = null;
    }
}

/**
 * Render error state
 */
function renderError(container, message) {
    if (!container) return;
    container.innerHTML = `
        <div class="empty-state">
            <div class="empty-icon">❌</div>
            <div class="empty-text">Error occurred</div>
            <div class="empty-hint">${escapeHtml(message)}</div>
        </div>
    `;
}

/**
 * Show toast notification
 */
function showToast(message, type = 'info') {
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || 'ℹ️'}</span>
        <span class="toast-message">${escapeHtml(message)}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    `;

    elements.toastContainer.appendChild(toast);

    // Auto remove after 5 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.animation = 'slideIn 0.3s ease reverse';
            setTimeout(() => toast.remove(), 300);
        }
    }, 5000);
}

/**
 * Get vulnerability type icon
 */
function getVulnIcon(type) {
    const icons = {
        xss: '💉',
        sqli: '🗄️',
        lfi: '📁',
        ssrf: '🌐',
        cors: '🔗',
        header: '📋',
        exposure: '🔓',
        info_disclosure: 'ℹ️',
        nuclei: '☢️'
    };
    return icons[type] || '🔍';
}

/**
 * Get status class based on HTTP status code
 */
function getStatusClass(status) {
    if (status >= 200 && status < 300) return 'success';
    if (status >= 300 && status < 400) return 'redirect';
    if (status >= 400 && status < 500) return 'forbidden';
    if (status >= 500) return 'error';
    return '';
}

/**
 * Render DNS Recon results
 */
function renderDNSResults(results) {
    const container = document.querySelector('#dns-recon .results-body');
    const records = results.records || {};
    
    // Update stats
    const statsContainer = document.querySelector('#dns-recon .results-stats');
    if (statsContainer) {
        statsContainer.innerHTML = `
            <span class="stat-badge info">🌍 ${results.total_records || 0} Records</span>
            <span class="stat-badge">⏱️ ${results.scan_time || 0}s</span>
        `;
    }

    if (Object.keys(records).length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">🌍</div>
                <div class="empty-text">No DNS records found</div>
                <div class="empty-hint">Try a different domain or check network connection</div>
            </div>
        `;
        return;
    }

    let html = '';
    
    // Order of display
    const typeOrder = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA'];
    
    typeOrder.forEach(type => {
        if (records[type] && records[type].length > 0) {
            
            // Special handling for A records (Table View)
            if (type === 'A') {
                html += `
                    <div class="dns-group animate-slide-up">
                        <div class="dns-group-title">${type} Records</div>
                        <div class="dns-table-container" style="overflow-x: auto;">
                            <table style="width: 100%; border-collapse: collapse; background: var(--bg-secondary); border-radius: 8px; overflow: hidden;">
                                <thead>
                                    <tr style="background: rgba(255,255,255,0.05); text-align: left;">
                                        <th style="padding: 12px 16px; color: var(--text-muted); font-size: 13px; font-weight: 600;">IP Address</th>
                                        <th style="padding: 12px 16px; color: var(--text-muted); font-size: 13px; font-weight: 600;">Hosts</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${(() => {
                                        // Group by IP
                                        const ipMap = {};
                                        records[type].forEach(rec => {
                                            if (!ipMap[rec.data]) {
                                                ipMap[rec.data] = new Set();
                                            }
                                            // Extract hostname if possible or use name
                                            let host = rec.name;
                                            if (host.endsWith('.')) host = host.slice(0, -1);
                                            ipMap[rec.data].add(host);
                                        });
                                        
                                        return Object.entries(ipMap).map(([ip, hosts]) => `
                                            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                                                <td style="padding: 12px 16px; font-family: monospace; color: var(--accent-cyan);">${escapeHtml(ip)}</td>
                                                <td style="padding: 12px 16px; color: var(--text-primary);">${escapeHtml(Array.from(hosts).join(', '))}</td>
                                            </tr>
                                        `).join('');
                                    })()}
                                </tbody>
                            </table>
                        </div>
                    </div>
                `;
            } else {
                // Default rendering for other types
                html += `
                    <div class="dns-group animate-slide-up">
                        <div class="dns-group-title">${type} Records</div>
                        <div class="dns-list">
                            ${records[type].map(record => `
                                <div class="dns-item">
                                    <span class="dns-data">${escapeHtml(record.data)}</span>
                                    <div class="dns-meta">
                                        ${record.ttl ? `<span class="dns-ttl">TTL: ${record.ttl}</span>` : ''}
                                        ${results.geolocation && results.geolocation[record.data] ? `
                                            <span class="dns-geo">
                                                📍 ${results.geolocation[record.data].country || ''} 
                                                ${results.geolocation[record.data].org || ''}
                                            </span>
                                        ` : ''}
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
        }
    });

    container.innerHTML = html;
}

/**
 * Format bytes to human readable string
 */
function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Option button click handler
 */
function selectOption(btn) {
    const group = btn.closest('.scan-options');
    group.querySelectorAll('.option-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
}

/**
 * Toggle filter dropdown
 */
function toggleFilterDropdown(e) {
    if (e) e.stopPropagation();
    const dropdown = document.getElementById('path-filter-dropdown');
    if (dropdown) {
        dropdown.classList.toggle('show');
    }
}

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
    const dropdown = document.getElementById('path-filter-dropdown');
    if (dropdown && dropdown.classList.contains('show') && !e.target.closest('.filter-dropdown-container')) {
        dropdown.classList.remove('show');
    }
});

/**
 * Filter paths by status code
 */
function filterPaths(status) {
    const items = document.querySelectorAll('#dir-fuzz .dir-item');
    
    items.forEach(item => {
        const statusEl = item.querySelector('.dir-status');
        if (!statusEl) return;
        
        const itemStatus = statusEl.textContent;
        
        if (status === 'all') {
            item.style.display = 'grid';
        } else {
            // Check if itemStatus contains the status code (as string)
            if (itemStatus.includes(status.toString())) {
                item.style.display = 'grid';
            } else {
                item.style.display = 'none';
            }
        }
    });
    
    // Close dropdown
    const dropdown = document.getElementById('path-filter-dropdown');
    if (dropdown) dropdown.classList.remove('show');
    
    // Show toast
    showToast(`Filter applied: ${status === 'all' ? 'All Paths' : status}`, 'info');
}

/**
 * Toggle mobile sidebar
 */
function toggleSidebar() {
    elements.sidebar?.classList.toggle('active');
    elements.overlay?.classList.toggle('active');
}

/**
 * Close mobile sidebar
 */
function closeSidebar() {
    elements.sidebar?.classList.remove('active');
    elements.overlay?.classList.remove('active');
}

/**
 * Initialize Theme
 */
function initializeTheme() {
    const savedTheme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    if (savedTheme === 'light' || (!savedTheme && !prefersDark)) {
        document.body.classList.add('light-mode');
        updateThemeUI(true);
    } else {
        document.body.classList.remove('light-mode');
        updateThemeUI(false);
    }
}

/**
 * Toggle Theme
 */
function toggleTheme() {
    const isLight = document.body.classList.toggle('light-mode');
    localStorage.setItem('theme', isLight ? 'light' : 'dark');
    updateThemeUI(isLight);
}

/**
 * Update Theme UI Elements
 */
function updateThemeUI(isLight) {
    if (!elements.themeToggle) return;
    
    const icon = elements.themeToggle.querySelector('.toggle-icon');
    const text = elements.themeToggle.querySelector('.toggle-text');
    
    if (isLight) {
        icon.textContent = '☀️';
        text.textContent = 'Light Mode';
        elements.themeToggle.setAttribute('aria-label', 'Switch to Dark Mode');
    } else {
        icon.textContent = '🌙';
        text.textContent = 'Dark Mode';
        elements.themeToggle.setAttribute('aria-label', 'Switch to Light Mode');
    }
}
