/* ──────────────────────────────────────────────
   EndpointForge - Main JavaScript
   ────────────────────────────────────────────── */

// ── State ──
let currentScanData = null;
let isScanning = false;
let isDemoMode = false;

// ── API Helpers ──
async function apiCall(endpoint, method = 'GET', body = null) {
    const options = {
        method,
        headers: { 'Content-Type': 'application/json' }
    };
    if (body) options.body = JSON.stringify(body);

    const response = await fetch(endpoint, options);
    return await response.json();
}

// ── Scan Functions ──
async function runScan(module) {
    if (isScanning) return;
    isScanning = true;
    updateScanStatus('Scanning...', true);
    showLoading(module);

    try {
        const result = await apiCall(`/api/scan/${module}`, 'POST', {});
        if (result.status === 'success') {
            renderResults(module, result.data);
        } else {
            showError(module, result.message || 'Scan failed');
        }
    } catch (error) {
        showError(module, `Error: ${error.message}`);
    } finally {
        isScanning = false;
        updateScanStatus('Ready', false);
        hideLoading(module);
    }
}

async function runFullScan() {
    if (isScanning) return;
    isScanning = true;
    updateScanStatus('Running full scan...', true);

    try {
        const result = await apiCall('/api/scan/full', 'POST', {});
        if (result.status === 'success') {
            currentScanData = result.data;
            renderDashboard(result.data);
        }
    } catch (error) {
        showError('dashboard', `Error: ${error.message}`);
    } finally {
        isScanning = false;
        updateScanStatus('Ready', false);
    }
}

async function loadDemoData(module = 'full') {
    isDemoMode = true;
    updateScanStatus('Loading demo data...', true);

    try {
        const result = await apiCall(`/api/demo/${module}`, 'GET');
        if (result.status === 'success') {
            currentScanData = result.data;
            if (module === 'full') {
                renderDashboard(result.data);
            } else {
                renderResults(module, result.data);
            }
            showDemoBanner();
        }
    } catch (error) {
        showError('dashboard', `Error loading demo: ${error.message}`);
    } finally {
        updateScanStatus('Demo Mode', false);
    }
}

// ── Render Functions ──
function renderDashboard(data) {
    // Aggregate severity counts
    const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const modules = ['processes', 'network', 'filesystem', 'registry', 'persistence'];

    let totalFindings = 0;
    modules.forEach(mod => {
        if (data[mod] && data[mod].summary) {
            Object.keys(severity).forEach(sev => {
                severity[sev] += data[mod].summary[sev] || 0;
            });
            totalFindings += data[mod].findings_count || 0;
        }
    });

    // Update stat cards
    updateStatCard('total-findings', totalFindings);
    updateStatCard('critical-count', severity.critical);
    updateStatCard('high-count', severity.high);
    updateStatCard('medium-count', severity.medium);
    updateStatCard('low-count', severity.low);

    // Render all findings sorted by severity
    const allFindings = [];
    modules.forEach(mod => {
        if (data[mod] && data[mod].findings) {
            data[mod].findings.forEach(f => {
                f._module = mod;
                allFindings.push(f);
            });
        }
    });

    allFindings.sort((a, b) => {
        const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return (order[a.severity] || 5) - (order[b.severity] || 5);
    });

    renderFindings('dashboard-findings', allFindings);

    // Update module summary cards
    renderModuleSummary(data);
}

function renderResults(module, data) {
    const container = document.getElementById(`${module}-results`);
    if (!container) return;

    if (data.findings && data.findings.length > 0) {
        renderFindings(`${module}-findings`, data.findings);
    }

    // Module-specific rendering
    switch (module) {
        case 'processes':
            renderProcessTable(data);
            break;
        case 'network':
            renderNetworkTable(data);
            break;
        case 'filesystem':
            renderFilesystemResults(data);
            break;
        case 'registry':
            renderRegistryResults(data);
            break;
        case 'persistence':
            renderPersistenceResults(data);
            break;
    }
}

function renderFindings(containerId, findings) {
    const container = document.getElementById(containerId);
    if (!container) return;

    if (!findings || findings.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <div class="empty-icon">&#x2713;</div>
                <div class="empty-title">No Findings</div>
                <p>No suspicious activity detected in this scan.</p>
            </div>`;
        return;
    }

    container.innerHTML = findings.map(f => `
        <div class="finding-item ${f.severity}">
            <div class="finding-header">
                <span class="severity-badge ${f.severity}">${f.severity}</span>
                <span class="finding-message">${escapeHtml(f.message)}</span>
            </div>
            ${f.details ? `<div class="finding-details">${escapeHtml(f.details)}</div>` : ''}
            ${f.mitre_id ? `<span class="mitre-tag">${f.mitre_id} — ${escapeHtml(f.mitre_name || '')}</span>` : ''}
        </div>
    `).join('');
}

function renderProcessTable(data) {
    const container = document.getElementById('process-table');
    if (!container || !data.processes) return;

    const suspiciousPids = new Set(
        data.findings.filter(f => f.pid).map(f => f.pid)
    );

    container.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>PID</th>
                    <th>PPID</th>
                    <th>Name</th>
                    <th>Path</th>
                    <th>User</th>
                    <th>CPU%</th>
                    <th>Mem%</th>
                </tr>
            </thead>
            <tbody>
                ${data.processes.map(p => `
                    <tr style="${suspiciousPids.has(p.pid) ? 'background: rgba(255, 71, 87, 0.06);' : ''}">
                        <td>${p.pid}</td>
                        <td>${p.ppid}</td>
                        <td style="${suspiciousPids.has(p.pid) ? 'color: var(--accent-red); font-weight: 600;' : 'color: var(--accent-cyan);'}">${escapeHtml(p.name)}</td>
                        <td class="truncate" title="${escapeHtml(p.exe || '')}">${escapeHtml(p.exe || 'N/A')}</td>
                        <td>${escapeHtml(p.username || 'N/A')}</td>
                        <td>${p.cpu_percent || 0}%</td>
                        <td>${p.memory_percent || 0}%</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>`;
}

function renderNetworkTable(data) {
    const container = document.getElementById('network-table');
    if (!container || !data.connections) return;

    const suspiciousPids = new Set(
        data.findings.filter(f => f.pid).map(f => f.pid)
    );

    container.innerHTML = `
        <table class="data-table">
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>Local Address</th>
                    <th>Remote Address</th>
                    <th>Status</th>
                    <th>Protocol</th>
                </tr>
            </thead>
            <tbody>
                ${data.connections.map(c => `
                    <tr style="${suspiciousPids.has(c.pid) ? 'background: rgba(255, 71, 87, 0.06);' : ''}">
                        <td>${c.pid}</td>
                        <td style="${suspiciousPids.has(c.pid) ? 'color: var(--accent-red); font-weight: 600;' : ''}">${escapeHtml(c.process)}</td>
                        <td>${escapeHtml(c.local_address)}</td>
                        <td>${escapeHtml(c.remote_address)}</td>
                        <td><span class="os-badge ${c.status === 'ESTABLISHED' ? 'windows' : 'linux'}">${c.status}</span></td>
                        <td>${c.protocol}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>`;
}

function renderFilesystemResults(data) {
    const container = document.getElementById('filesystem-changes');
    if (!container) return;

    if (!data.changes) {
        container.innerHTML = '<p class="empty-state">Run a baseline scan first, then check integrity.</p>';
        return;
    }

    container.innerHTML = `
        <div class="stats-grid" style="margin-bottom: 16px;">
            <div class="stat-card high"><div class="stat-value">${data.new_files || 0}</div><div class="stat-label">New Files</div></div>
            <div class="stat-card critical"><div class="stat-value">${data.modified_files || 0}</div><div class="stat-label">Modified</div></div>
            <div class="stat-card medium"><div class="stat-value">${data.deleted_files || 0}</div><div class="stat-label">Deleted</div></div>
        </div>
        <p style="color: var(--text-secondary); font-size: 13px; margin-bottom: 16px;">Baseline: ${data.baseline_date || 'N/A'}</p>
    `;
}

function renderRegistryResults(data) {
    const container = document.getElementById('registry-entries');
    if (!container) return;

    if (!data.os_supported) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">&#x1F4BB;</div><div class="empty-title">Windows Only</div><p>Registry analysis is only available on Windows systems.</p></div>';
        return;
    }

    if (data.entries) {
        container.innerHTML = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Key</th>
                        <th>Value Name</th>
                        <th>Value Data</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.entries.map(e => `
                        <tr style="${e.status === 'suspicious' ? 'background: rgba(255, 71, 87, 0.06);' : ''}">
                            <td class="truncate" title="${escapeHtml(e.key)}">${escapeHtml(e.key)}</td>
                            <td>${escapeHtml(e.name)}</td>
                            <td class="truncate" title="${escapeHtml(e.value)}">${escapeHtml(e.value)}</td>
                            <td>${e.status === 'suspicious' ? '<span class="severity-badge high">Suspicious</span>' : '<span class="severity-badge low">OK</span>'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>`;
    }
}

function renderPersistenceResults(data) {
    const container = document.getElementById('persistence-mechanisms');
    if (!container || !data.mechanisms) return;

    container.innerHTML = data.mechanisms.map(m => `
        <div class="finding-item ${m.suspicious ? 'high' : 'info'}" style="border-left-color: ${m.suspicious ? 'var(--severity-high)' : 'var(--border-color)'};">
            <div class="finding-header">
                <span class="severity-badge ${m.suspicious ? 'high' : 'info'}">${m.type}</span>
                <span class="os-badge ${m.platform}">${m.platform}</span>
                <span class="finding-message">${escapeHtml(m.name || m.source || m.content || 'Unknown')}</span>
            </div>
            ${m.action ? `<div class="finding-details">${escapeHtml(m.action)}</div>` : ''}
            ${m.path ? `<div class="finding-details">${escapeHtml(m.path)}</div>` : ''}
            ${m.content ? `<div class="finding-details">${escapeHtml(m.content)}</div>` : ''}
            ${m.exec_start ? `<div class="finding-details">ExecStart: ${escapeHtml(m.exec_start)}</div>` : ''}
        </div>
    `).join('');
}

function renderModuleSummary(data) {
    const container = document.getElementById('module-summary');
    if (!container) return;

    const modules = [
        { key: 'processes', name: 'Process Execution', icon: '&#x2699;' },
        { key: 'network', name: 'Network Connections', icon: '&#x1F310;' },
        { key: 'filesystem', name: 'File System Integrity', icon: '&#x1F4C1;' },
        { key: 'registry', name: 'Registry Modifications', icon: '&#x1F5C3;' },
        { key: 'persistence', name: 'Persistence Detection', icon: '&#x1F512;' },
    ];

    container.innerHTML = modules.map(mod => {
        const modData = data[mod.key];
        if (!modData) return '';
        const count = modData.findings_count || 0;
        const critCount = modData.summary?.critical || 0;
        const highCount = modData.summary?.high || 0;

        return `
            <div class="card" style="cursor: pointer;" onclick="window.location.href='/${mod.key === 'filesystem' ? 'filesystem' : mod.key}'">
                <div class="card-header">
                    <span class="card-title">${mod.icon} ${mod.name}</span>
                    <span class="severity-badge ${count > 0 ? (critCount > 0 ? 'critical' : 'high') : 'low'}">${count} findings</span>
                </div>
                <div style="display: flex; gap: 16px; font-size: 13px; color: var(--text-secondary);">
                    ${critCount > 0 ? `<span style="color: var(--severity-critical);">&#x25CF; ${critCount} critical</span>` : ''}
                    ${highCount > 0 ? `<span style="color: var(--severity-high);">&#x25CF; ${highCount} high</span>` : ''}
                    ${count === 0 ? '<span style="color: var(--severity-low);">&#x25CF; Clean</span>' : ''}
                </div>
            </div>`;
    }).join('');
}

// ── Report Generation ──
async function generateReport(format = 'markdown') {
    if (!currentScanData) {
        alert('No scan data available. Run a scan or load demo data first.');
        return;
    }

    try {
        const result = await apiCall('/api/report/generate', 'POST', {
            scan_data: currentScanData,
            format: format
        });

        if (result.status === 'success') {
            const reportContainer = document.getElementById('report-output');
            if (reportContainer) {
                reportContainer.textContent = result.data.content;
            }
        }
    } catch (error) {
        alert(`Report generation failed: ${error.message}`);
    }
}

async function exportReport(format = 'markdown') {
    if (!currentScanData) {
        alert('No scan data available. Run a scan or load demo data first.');
        return;
    }

    try {
        const response = await fetch('/api/report/export', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                scan_data: currentScanData,
                format: format
            })
        });

        const blob = await response.blob();
        const ext = format === 'markdown' ? 'md' : 'json';
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `EndpointForge_Report_${new Date().toISOString().slice(0, 19).replace(/[:-]/g, '')}.${ext}`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (error) {
        alert(`Export failed: ${error.message}`);
    }
}

// ── UI Helpers ──
function updateStatCard(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

function updateScanStatus(text, active) {
    const statusText = document.getElementById('scan-status-text');
    const statusDot = document.getElementById('scan-status-dot');
    if (statusText) statusText.textContent = text;
    if (statusDot) {
        statusDot.classList.toggle('active', active);
    }
}

function showLoading(module) {
    const el = document.getElementById(`${module}-loading`);
    if (el) el.classList.add('active');
}

function hideLoading(module) {
    const el = document.getElementById(`${module}-loading`);
    if (el) el.classList.remove('active');
}

function showError(module, message) {
    const container = document.getElementById(`${module}-findings`) ||
                      document.getElementById(`${module}-results`);
    if (container) {
        container.innerHTML = `
            <div class="finding-item critical">
                <div class="finding-header">
                    <span class="severity-badge critical">Error</span>
                    <span class="finding-message">${escapeHtml(message)}</span>
                </div>
            </div>`;
    }
}

function showDemoBanner() {
    const banners = document.querySelectorAll('.demo-banner');
    banners.forEach(b => b.style.display = 'flex');
}

function switchTab(tabId) {
    document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    const btn = document.querySelector(`[data-tab="${tabId}"]`);
    const content = document.getElementById(tabId);
    if (btn) btn.classList.add('active');
    if (content) content.classList.add('active');
}

function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// ── Initialize ──
document.addEventListener('DOMContentLoaded', () => {
    // Mark active nav link
    const currentPath = window.location.pathname;
    document.querySelectorAll('.nav-link').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});
