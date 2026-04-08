/**
 * CyberSec Dashboard — Application JavaScript
 *
 * Frequences de rafraichissement (PRD Section 5.2.2) :
 *   - Alertes actives     : 5 secondes  (GET /threats/active)
 *   - Statut systeme      : 30 secondes (GET /health)
 *   - Statistiques        : 60 secondes (GET /threats/stats)
 *   - Top 10 IPs          : 5 minutes   (GET /threats/active + calcul local)
 *   - Timeline            : A la demande
 */

// ── Configuration ────────────────────────────────────────────────────
const API_URL = 'http://localhost:8080';

// Cache local des donnees
let allAlerts    = [];
let attackChart  = null;
let timelineChart = null;

// ── Initialisation ───────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    console.log('[CyberSec] Dashboard initialise');
    initCharts();
    fetchAll();

    // Timers de rafraichissement
    setInterval(fetchActiveAlerts, 5000);          // 5s
    setInterval(fetchHealth,       30000);          // 30s
    setInterval(fetchStats,        60000);          // 60s
    setInterval(fetchTimeline,     5 * 60 * 1000); // 5min
});

function fetchAll() {
    fetchHealth();
    fetchActiveAlerts();
    fetchStats();
    fetchTimeline();
}

// ── API Calls ────────────────────────────────────────────────────────

async function fetchHealth() {
    try {
        const res  = await fetch(`${API_URL}/health`);
        const data = await res.json();
        updateSystemStatus(data);
    } catch (e) {
        updateSystemStatus(null);
    }
}

async function fetchActiveAlerts() {
    showRefreshIndicator(true);
    try {
        const res  = await fetch(`${API_URL}/threats/active`);
        const data = await res.json();
        allAlerts = Array.isArray(data) ? data : [];
        updateAlerts(allAlerts);
        updateMetrics(allAlerts);
        updateTopIPs(allAlerts);
        updateAttackChart(allAlerts);
        updateLastUpdate();
    } catch (e) {
        console.warn('[CyberSec] fetchActiveAlerts failed:', e.message);
        showEmptyAlerts('Erreur de connexion a l\'API');
    } finally {
        showRefreshIndicator(false);
    }
}

async function fetchStats() {
    try {
        const res  = await fetch(`${API_URL}/threats/stats`);
        const data = await res.json();
        // Les stats globales enrichissent les metriques
        if (data.high_risk_ips !== undefined) {
            document.getElementById('metric-blocked').textContent = data.high_risk_ips;
        }
    } catch (e) {
        console.warn('[CyberSec] fetchStats failed:', e.message);
    }
}

async function fetchTimeline() {
    try {
        const res  = await fetch(`${API_URL}/threats/timeline`);
        const data = await res.json();
        if (Array.isArray(data) && data.length > 0) {
            updateTimelineChart(data);
        }
    } catch (e) {
        console.warn('[CyberSec] fetchTimeline failed:', e.message);
    }
}

async function searchIP() {
    const ip = document.getElementById('ip-input').value.trim();
    if (!ip) return;

    const resultDiv = document.getElementById('ip-result');
    resultDiv.classList.remove('hidden');
    resultDiv.innerHTML = '<div class="loading">⏳ Analyse en cours...</div>';

    try {
        const res    = await fetch(`${API_URL}/threats/ip/${encodeURIComponent(ip)}`);
        const profile = await res.json();
        renderIPProfile(profile, resultDiv);
    } catch (e) {
        resultDiv.innerHTML = `<div style="color:var(--color-critical)">❌ Erreur: ${e.message}</div>`;
    }
}

// ── Renderers ────────────────────────────────────────────────────────

function updateSystemStatus(data) {
    const dot  = document.getElementById('status-dot');
    const text = document.getElementById('status-text');
    const compApi       = document.getElementById('comp-api');
    const compHbase     = document.getElementById('comp-hbase');
    const compCassandra = document.getElementById('comp-cassandra');

    if (!data) {
        dot.className  = 'status-dot down';
        text.textContent = 'API Hors ligne';
        setComponent(compApi, 'DOWN');
        setComponent(compHbase, 'DOWN');
        setComponent(compCassandra, 'DOWN');
        return;
    }

    const isUp = data.status === 'UP';
    dot.className     = `status-dot ${isUp ? 'up' : 'degraded'}`;
    text.textContent  = isUp ? 'Systeme Operationnel' : 'Systeme Degrade';

    const components = data.components || {};
    setComponent(compApi,       components.api       || 'UP');
    setComponent(compHbase,     components.hbase     || 'UNKNOWN');
    setComponent(compCassandra, components.cassandra || 'UNKNOWN');
}

function setComponent(el, status) {
    el.textContent = status === 'UP' ? '✅ UP' : status === 'DOWN' ? '❌ DOWN' : '⏳ ...';
    el.className   = `component-status ${status === 'UP' ? 'up' : status === 'DOWN' ? 'down' : 'checking'}`;
}

function updateAlerts(alerts) {
    const tbody = document.getElementById('alerts-tbody');
    const badge = document.getElementById('badge-alerts');
    badge.textContent = alerts.length;

    if (alerts.length === 0) {
        showEmptyAlerts('Aucune alerte active en ce moment');
        return;
    }

    const filterSev = document.getElementById('filter-severity').value;
    const filtered  = filterSev === 'ALL'
        ? alerts
        : alerts.filter(a => a.severity === filterSev);

    tbody.innerHTML = filtered.map(alert => `
        <tr>
            <td>
                <span class="ip-cell" onclick="fillIPSearch('${esc(alert.ipSource)}')">
                    ${esc(alert.ipSource || '—')}
                </span>
            </td>
            <td>${formatAlertType(alert.alertType)}</td>
            <td><span class="sev sev-${esc(alert.severity)}">${esc(alert.severity || '—')}</span></td>
            <td>
                <div class="score-cell">
                    <span>${alert.threatScore || 0}</span>
                    <div class="score-bar">
                        <div class="score-fill" style="width:${alert.threatScore || 0}%;
                             background:${scoreColor(alert.threatScore)}"></div>
                    </div>
                </div>
            </td>
            <td>${alert.eventCount || 0}</td>
            <td>${formatBytes(alert.bytesTotal)}</td>
            <td>${formatTime(alert.lastSeen)}</td>
            <td>
                <button class="btn-small" onclick="fillIPSearch('${esc(alert.ipSource)}')">
                    Analyser
                </button>
            </td>
        </tr>
    `).join('');
}

function filterAlerts() {
    updateAlerts(allAlerts);
}

function showEmptyAlerts(msg) {
    document.getElementById('alerts-tbody').innerHTML =
        `<tr class="loading-row"><td colspan="8">${msg}</td></tr>`;
}

function updateMetrics(alerts) {
    const critical = alerts.filter(a => a.severity === 'CRITICAL').length;
    const high     = alerts.filter(a => a.severity === 'HIGH').length;

    document.getElementById('metric-critical').textContent = critical;
    document.getElementById('metric-high').textContent     = high;
    document.getElementById('metric-total').textContent    = alerts.length;
}

function updateTopIPs(alerts) {
    // Compter les alertes par IP
    const ipCounts = {};
    const ipScores = {};
    alerts.forEach(a => {
        const ip = a.ipSource;
        if (!ip) return;
        ipCounts[ip] = (ipCounts[ip] || 0) + 1;
        ipScores[ip] = Math.max(ipScores[ip] || 0, a.threatScore || 0);
    });

    const sorted = Object.entries(ipScores)
        .sort(([,a], [,b]) => b - a)
        .slice(0, 10);

    const container = document.getElementById('top-ips-container');

    if (sorted.length === 0) {
        container.innerHTML = '<div class="loading">Aucune IP malveillante detectee</div>';
        return;
    }

    const maxScore = sorted[0][1] || 100;
    container.innerHTML = sorted.map(([ip, score], i) => `
        <div class="top-ip-row" onclick="fillIPSearch('${esc(ip)}')">
            <span class="top-ip-rank">#${i + 1}</span>
            <span class="top-ip-addr">${esc(ip)}</span>
            <div style="flex:1; padding: 0 8px;">
                <div class="top-ip-bar" style="width:${(score/maxScore*100).toFixed(0)}%"></div>
            </div>
            <span class="top-ip-score">${score}</span>
        </div>
    `).join('');
}

function renderIPProfile(profile, container) {
    if (!profile || !profile.ip) {
        container.innerHTML = '<div style="color:var(--color-critical)">IP non trouvee</div>';
        return;
    }

    const batch = profile.batchLayer || {};
    const speed = profile.speedLayer || {};
    const rec   = profile.recommendation || 'ALLOW';

    container.innerHTML = `
        <div style="margin-bottom:10px;">
            <strong style="font-size:15px;font-family:var(--font-mono);">${esc(profile.ip)}</strong>
            <span class="rec rec-${rec}" style="margin-left:10px;">${rec}</span>
            <span style="margin-left:8px;font-size:11px;color:var(--text-dim);">
                Confiance: ${((profile.confidence || 0) * 100).toFixed(0)}%
            </span>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
                <div style="font-size:11px;color:var(--accent-blue);font-weight:700;margin-bottom:6px;">
                    📦 BATCH LAYER
                </div>
                <div class="ip-result-row">
                    <span class="ip-result-label">Score reputation</span>
                    <span class="ip-result-value" style="color:${scoreColor(batch.reputationScore)}">
                        ${batch.reputationScore || 0}/100
                    </span>
                </div>
                <div class="ip-result-row">
                    <span class="ip-result-label">Total evenements</span>
                    <span class="ip-result-value">${(batch.totalHistoricalEvents || 0).toLocaleString()}</span>
                </div>
                <div class="ip-result-row">
                    <span class="ip-result-label">Types d'attaques</span>
                    <span class="ip-result-value" style="font-size:11px;">
                        ${(batch.attackTypesDetected || []).join(', ') || '—'}
                    </span>
                </div>
            </div>
            <div>
                <div style="font-size:11px;color:var(--color-high);font-weight:700;margin-bottom:6px;">
                    ⚡ SPEED LAYER
                </div>
                <div class="ip-result-row">
                    <span class="ip-result-label">Alertes actives</span>
                    <span class="ip-result-value" style="color:${speed.activeAlerts > 0 ? 'var(--color-critical)' : 'var(--color-low)'}">
                        ${speed.activeAlerts || 0}
                    </span>
                </div>
                <div class="ip-result-row">
                    <span class="ip-result-label">Score actuel</span>
                    <span class="ip-result-value" style="color:${scoreColor(speed.currentThreatScore)}">
                        ${speed.currentThreatScore || 0}/100
                    </span>
                </div>
                <div class="ip-result-row">
                    <span class="ip-result-label">Derniere vue</span>
                    <span class="ip-result-value" style="font-size:11px;">
                        ${formatTime(speed.lastSeen) || '—'}
                    </span>
                </div>
            </div>
        </div>
    `;
}

function fillIPSearch(ip) {
    document.getElementById('ip-input').value = ip;
    searchIP();
}

// ── Charts ───────────────────────────────────────────────────────────

function initCharts() {
    Chart.defaults.color = '#8888aa';
    Chart.defaults.borderColor = '#2a2a4a';

    // Donut : distribution des types d'attaques
    const ctxDonut = document.getElementById('chart-attack-types').getContext('2d');
    attackChart = new Chart(ctxDonut, {
        type: 'doughnut',
        data: {
            labels: ['BRUTE_FORCE', 'SQLI', 'PORT_SCAN', 'TOOL_DETECTED', 'VOLUME_ANOMALY', 'AUTRE'],
            datasets: [{
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: [
                    '#ff4757', '#ff7f50', '#ffd700',
                    '#7c4dff', '#4a9eff', '#2ed573'
                ],
                borderWidth: 2,
                borderColor: '#1a1a2e'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: { boxWidth: 12, font: { size: 11 } }
                }
            }
        }
    });

    // Ligne : timeline des menaces
    const ctxLine = document.getElementById('chart-timeline').getContext('2d');
    timelineChart = new Chart(ctxLine, {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Malicious',
                    data: [],
                    borderColor: '#ff4757',
                    backgroundColor: '#ff475715',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 3
                },
                {
                    label: 'Suspicious',
                    data: [],
                    borderColor: '#ffd700',
                    backgroundColor: '#ffd70015',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 3
                },
                {
                    label: 'Benign',
                    data: [],
                    borderColor: '#2ed573',
                    backgroundColor: '#2ed57315',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { intersect: false, mode: 'index' },
            scales: {
                x: {
                    ticks: { maxTicksLimit: 12, font: { size: 10 } }
                },
                y: {
                    beginAtZero: true,
                    ticks: { font: { size: 10 } }
                }
            },
            plugins: {
                legend: {
                    labels: { boxWidth: 12, font: { size: 11 } }
                }
            }
        }
    });
}

function updateAttackChart(alerts) {
    if (!attackChart) return;
    const counts = {
        'BRUTE_FORCE': 0, 'SQLI_DETECTED': 0, 'PORT_SCAN': 0,
        'KNOWN_ATTACK_TOOL': 0, 'VOLUME_ANOMALY': 0, 'OTHER': 0
    };
    alerts.forEach(a => {
        const type = a.alertType || 'OTHER';
        if (counts[type] !== undefined) counts[type]++;
        else counts['OTHER']++;
    });

    attackChart.data.datasets[0].data = [
        counts['BRUTE_FORCE'],
        counts['SQLI_DETECTED'],
        counts['PORT_SCAN'],
        counts['KNOWN_ATTACK_TOOL'],
        counts['VOLUME_ANOMALY'],
        counts['OTHER']
    ];
    attackChart.update('none');
}

function updateTimelineChart(data) {
    if (!timelineChart) return;
    const labels    = data.map(d => `${d.date} ${d.hour}h`);
    const malicious  = data.map(d => d.malicious  || 0);
    const suspicious = data.map(d => d.suspicious || 0);
    const benign     = data.map(d => d.benign     || 0);

    timelineChart.data.labels                  = labels;
    timelineChart.data.datasets[0].data        = malicious;
    timelineChart.data.datasets[1].data        = suspicious;
    timelineChart.data.datasets[2].data        = benign;
    timelineChart.update();
}

// ── Helpers ──────────────────────────────────────────────────────────

function formatAlertType(type) {
    const labels = {
        'BRUTE_FORCE':      '🔑 Brute Force',
        'SQLI_DETECTED':    '💉 SQL Injection',
        'XSS_DETECTED':     '🕷️ XSS',
        'LFI_DETECTED':     '📁 LFI',
        'KNOWN_ATTACK_TOOL':'🛠️ Outil Malveillant',
        'VOLUME_ANOMALY':   '📈 Anomalie Volume',
        'PORT_SCAN':        '🔍 Port Scan',
        'SIGNATURE_MATCH':  '⚠️ Signature',
    };
    return labels[type] || (type || '—');
}

function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB'];
    let i = 0;
    let val = bytes;
    while (val >= 1024 && i < units.length - 1) { val /= 1024; i++; }
    return `${val.toFixed(1)} ${units[i]}`;
}

function formatTime(iso) {
    if (!iso) return '—';
    try {
        const d = new Date(iso);
        return d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    } catch (e) { return iso; }
}

function scoreColor(score) {
    const s = score || 0;
    if (s >= 80) return 'var(--color-critical)';
    if (s >= 60) return 'var(--color-high)';
    if (s >= 40) return 'var(--color-medium)';
    return 'var(--color-low)';
}

function esc(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function updateLastUpdate() {
    document.getElementById('last-update').textContent =
        'Mis a jour : ' + new Date().toLocaleTimeString('fr-FR');
}

function showRefreshIndicator(active) {
    const el = document.getElementById('refresh-indicator');
    el.classList.toggle('active', active);
}
