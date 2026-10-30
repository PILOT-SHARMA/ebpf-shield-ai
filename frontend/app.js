/**
 * app.js — ContainerShield AI: AI-Powered Container Security Monitoring Platform
 * Owner: Ananya Mishra (frontend / QA)
 *
 * Full SPA controller for all 8 views, live WebSocket streaming,
 * dynamic SVG/CSS analytics charts, alert triage, container monitoring,
 * and system health diagnostics.
 */

// ──────────────────────────────────────────────
// State & Configuration
// ──────────────────────────────────────────────

const API_BASE = window.location.origin;
const WS_PROTOCOL = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const WS_URL = `${WS_PROTOCOL}//${window.location.host}/ws/v1/stream`;

let currentView = 'overview';
let allEvents = [];
let allAlerts = [];
let allContainers = [];
let activeRules = [];
let auditLogs = [];
let currentEventFilter = 'all';
let currentAlertSeverityFilter = 'all';
let currentAlertStatusFilter = 'all';
let eventSearchQuery = '';
let ws = null;
let reconnectTimer = null;
let liveStreamPaused = false;
let currentMetrics = null;

// ──────────────────────────────────────────────
// View Navigation
// ──────────────────────────────────────────────

const VIEW_METADATA = {
    overview: {
        title: 'Overview Dashboard',
        subtitle: 'Executive runtime threat landscape & telemetry overview',
    },
    monitoring: {
        title: 'Runtime Kernel Telemetry',
        subtitle: 'Real-time eBPF event stream (process, file, network)',
    },
    detection: {
        title: 'Threat Detection Architecture',
        subtitle: 'Dual-layer heuristic rules & Isolation Forest ML model',
    },
    alerts: {
        title: 'Security Alerts & Incident Response',
        subtitle: 'Triage desk, forensic evidence, and container mitigations',
    },
    analytics: {
        title: 'AI Analytics & Anomaly Scores',
        subtitle: 'Statistical distributions, threat trajectories, and engine coverage',
    },
    containers: {
        title: 'Container Workload Monitoring',
        subtitle: 'Container inventory, namespace context, and risk levels',
    },
    timeline: {
        title: 'Event Correlation Timeline',
        subtitle: 'Chronological timeline of threats, alerts, and mitigations',
    },
    health: {
        title: 'System Health & Audit Trail',
        subtitle: 'Service health checks, collector mode, and compliance log',
    },
};

function showView(viewName) {
    if (!VIEW_METADATA[viewName]) return;
    currentView = viewName;

    // Update nav items active state
    document.querySelectorAll('.sidebar-nav .nav-item').forEach(btn => {
        btn.classList.remove('active');
    });
    const activeNavBtn = document.getElementById(`nav-${viewName}`);
    if (activeNavBtn) activeNavBtn.classList.add('active');

    // Update view containers
    document.querySelectorAll('.view').forEach(v => {
        v.classList.remove('active');
    });
    const targetView = document.getElementById(`view-${viewName}`);
    if (targetView) targetView.classList.add('active');

    // Update Topbar
    const meta = VIEW_METADATA[viewName];
    document.getElementById('viewTitle').textContent = meta.title;
    document.getElementById('viewSubtitle').textContent = meta.subtitle;

    // Refresh view-specific data
    refreshCurrentView();
}

function refreshCurrentView() {
    refreshStats();
    if (currentView === 'overview') {
        fetchMetricsSummary();
        renderOverviewFeeds();
    } else if (currentView === 'monitoring') {
        loadEvents();
    } else if (currentView === 'detection') {
        loadRules();
    } else if (currentView === 'alerts') {
        loadAlerts();
    } else if (currentView === 'analytics') {
        fetchMetricsSummary();
    } else if (currentView === 'containers') {
        loadContainers();
    } else if (currentView === 'timeline') {
        loadTimeline();
    } else if (currentView === 'health') {
        checkHealth();
        refreshAuditLog();
    }
}

// ──────────────────────────────────────────────
// WebSocket Live Streaming
// ──────────────────────────────────────────────

function connectWebSocket() {
    if (ws && ws.readyState === WebSocket.OPEN) return;

    try {
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            updateConnectionUI(true);
            console.log('[WS] Connected to live kernel telemetry stream');
            if (reconnectTimer) {
                clearInterval(reconnectTimer);
                reconnectTimer = null;
            }
        };

        ws.onmessage = (event) => {
            try {
                const msg = JSON.parse(event.data);
                if (msg.type === 'new_event') {
                    handleIncomingEvent(msg.data);
                } else if (msg.type === 'new_alert') {
                    handleIncomingAlert(msg.data);
                }
            } catch (e) {
                console.warn('[WS] Non-JSON or error parsing:', e);
            }
        };

        ws.onclose = () => {
            updateConnectionUI(false);
            console.log('[WS] Disconnected. Reconnecting in 3 seconds...');
            setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = (err) => {
            console.error('[WS] Socket error:', err);
            ws.close();
        };

        // Periodic heartbeat ping every 25 seconds
        if (!reconnectTimer) {
            reconnectTimer = setInterval(() => {
                if (ws && ws.readyState === WebSocket.OPEN) {
                    ws.send('ping');
                }
            }, 25000);
        }
    } catch (err) {
        console.error('[WS] Connection exception:', err);
        setTimeout(connectWebSocket, 3000);
    }
}

function updateConnectionUI(connected) {
    const el = document.getElementById('connectionStatus');
    const txt = document.getElementById('connectionText');
    if (connected) {
        el.className = 'connection-indicator connected';
        txt.textContent = 'Live Stream Connected';
    } else {
        el.className = 'connection-indicator disconnected';
        txt.textContent = 'Reconnecting Stream…';
    }
}

function handleIncomingEvent(event) {
    if (liveStreamPaused) return;

    // Prepend to allEvents array (cap at 200)
    allEvents.unshift(event);
    if (allEvents.length > 200) allEvents.pop();

    // Update real-time views
    if (currentView === 'monitoring') {
        renderEventsList();
    } else if (currentView === 'overview') {
        renderOverviewFeeds();
    } else if (currentView === 'timeline') {
        renderTimeline();
    }

    refreshStats();
}

function handleIncomingAlert(alert) {
    // Prepend to allAlerts array (cap at 100)
    allAlerts.unshift(alert);
    if (allAlerts.length > 100) allAlerts.pop();

    updateAlertBadge();

    if (currentView === 'alerts') {
        renderAlertsList();
    } else if (currentView === 'overview') {
        renderOverviewFeeds();
    } else if (currentView === 'timeline') {
        renderTimeline();
    }

    refreshStats();
}

function updateAlertBadge() {
    const openCount = allAlerts.filter(a => a.status === 'open').length;
    const badge = document.getElementById('navThreatBadge');
    if (badge) {
        if (openCount > 0) {
            badge.style.display = 'inline-block';
            badge.textContent = openCount;
        } else {
            badge.style.display = 'none';
        }
    }
}

// ──────────────────────────────────────────────
// API Calls & Data Ingestion
// ──────────────────────────────────────────────

async function refreshStats() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/stats`);
        if (!res.ok) return;
        const stats = await res.json();

        document.getElementById('statTotalEvents').textContent = Number(stats.total_events || 0).toLocaleString();
        document.getElementById('statSuspicious').textContent = Number(stats.suspicious_events || 0).toLocaleString();
        document.getElementById('statOpenAlerts').textContent = Number(stats.open_alerts || 0).toLocaleString();
        document.getElementById('statCritical').textContent = Number(stats.critical_alerts || 0).toLocaleString();

        // Also fetch containers count
        const cRes = await fetch(`${API_BASE}/api/v1/containers?limit=200`);
        if (cRes.ok) {
            const containers = await cRes.json();
            allContainers = containers;
            document.getElementById('statContainers').textContent = containers.length;
            const containerCountEl = document.getElementById('containerCount');
            if (containerCountEl) containerCountEl.textContent = containers.length;
        }
    } catch (e) {
        console.warn('Stats fetch error:', e);
    }
}

async function loadEvents() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/events?limit=100`);
        if (!res.ok) return;
        allEvents = await res.json();
        renderEventsList();
    } catch (e) {
        console.error('Error loading events:', e);
    }
}

async function loadAlerts() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/alerts?limit=100`);
        if (!res.ok) return;
        allAlerts = await res.json();
        updateAlertBadge();
        renderAlertsList();
    } catch (e) {
        console.error('Error loading alerts:', e);
    }
}

async function loadContainers() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/containers?limit=100`);
        if (!res.ok) return;
        allContainers = await res.json();
        renderContainersList();
    } catch (e) {
        console.error('Error loading containers:', e);
    }
}

async function loadRules() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/rules`);
        if (!res.ok) return;
        activeRules = await res.json();
        renderRulesGrid();
    } catch (e) {
        console.error('Error loading rules:', e);
    }
}

async function fetchMetricsSummary() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/metrics/summary`);
        if (!res.ok) return;
        currentMetrics = await res.json();
        renderAnalyticsCharts();
    } catch (e) {
        console.error('Error fetching metrics summary:', e);
    }
}

async function loadTimeline() {
    // Ensure both events and alerts are loaded
    await Promise.all([loadEvents(), loadAlerts()]);
    renderTimeline();
}

async function checkHealth() {
    try {
        const [healthRes, sensorRes] = await Promise.all([
            fetch(`${API_BASE}/api/v1/health`),
            fetch(`${API_BASE}/api/v1/sensor/status`),
        ]);

        const health = healthRes.ok ? await healthRes.json() : null;
        const sensor = sensorRes.ok ? await sensorRes.json() : null;

        // Backend
        if (health && health.status === 'healthy') {
            document.getElementById('healthBackendBadge').className = 'health-badge healthy';
            document.getElementById('healthBackendBadge').textContent = 'HEALTHY';
            document.getElementById('healthBackendDetail').textContent = `v${health.version} • Uptime: ${health.uptime_seconds}s`;
        }

        // Database
        if (health && health.database === 'connected') {
            document.getElementById('healthDatabaseBadge').className = 'health-badge healthy';
            document.getElementById('healthDatabaseBadge').textContent = 'CONNECTED';
            document.getElementById('healthDatabaseDetail').textContent = 'PostgreSQL / Persistent Volume Ready';
        } else {
            document.getElementById('healthDatabaseBadge').className = 'health-badge degraded';
            document.getElementById('healthDatabaseBadge').textContent = 'DISCONNECTED';
        }

        // Sensor / Collector
        if (sensor) {
            const isReplay = sensor.mode.includes('REPLAY');
            document.getElementById('healthCollectorBadge').className = isReplay ? 'health-badge replay' : 'health-badge healthy';
            document.getElementById('healthCollectorBadge').textContent = sensor.mode;
            document.getElementById('healthCollectorDetail').textContent = `${sensor.events_collected} Events • ${sensor.status.toUpperCase()}`;

            // Update sidebar mode badge
            const modeText = document.getElementById('modeBadgeText');
            if (modeText) modeText.textContent = isReplay ? 'DEMO REPLAY MODE' : 'LIVE EBPF MODE';
        }

        // Render health details JSON
        const detailsEl = document.getElementById('healthDetails');
        if (detailsEl) {
            detailsEl.innerHTML = `
                <div style="font-family: var(--font-mono); font-size: 12px; background: var(--bg-base); padding: 16px; border-radius: var(--radius-md); border: 1px solid var(--border);">
                    <div style="color: var(--primary-light); margin-bottom: 8px;">// Active Diagnostic Report</div>
                    <div><strong>Application Health:</strong> ${JSON.stringify(health, null, 2)}</div>
                    <div style="margin-top: 10px;"><strong>Sensor Telemetry Status:</strong> ${JSON.stringify(sensor, null, 2)}</div>
                </div>
            `;
        }
    } catch (e) {
        console.error('Error checking health:', e);
    }
}

async function refreshAuditLog() {
    try {
        const res = await fetch(`${API_BASE}/api/v1/audit?limit=50`);
        if (!res.ok) return;
        auditLogs = await res.json();
        renderAuditList();
    } catch (e) {
        console.error('Error fetching audit log:', e);
    }
}

// ──────────────────────────────────────────────
// Renderers
// ──────────────────────────────────────────────

// 1. Overview Feeds
function renderOverviewFeeds() {
    // Recent events preview (first 5)
    const eventContainer = document.getElementById('overviewEventsList');
    const recent = allEvents.slice(0, 5);
    document.getElementById('overviewEventCount').textContent = allEvents.length;

    if (!recent.length) {
        eventContainer.innerHTML = '<div class="empty-state"><div class="icon">📡</div><p>Waiting for events…</p></div>';
    } else {
        eventContainer.innerHTML = recent.map(ev => createEventItemHTML(ev)).join('');
    }

    // Active alerts preview (first 5)
    const alertContainer = document.getElementById('overviewAlertsList');
    const openAlerts = allAlerts.filter(a => a.status === 'open').slice(0, 5);
    document.getElementById('overviewAlertCount').textContent = allAlerts.filter(a => a.status === 'open').length;

    if (!openAlerts.length) {
        alertContainer.innerHTML = '<div class="empty-state"><div class="icon">🛡️</div><p>No active alerts. System secure.</p></div>';
    } else {
        alertContainer.innerHTML = openAlerts.map(al => createAlertItemHTML(al)).join('');
    }
}

// 2. Events List (Runtime Monitoring)
function renderEventsList() {
    const listEl = document.getElementById('eventsList');
    const countEl = document.getElementById('eventCount');

    let filtered = allEvents;
    if (currentEventFilter === 'suspicious') {
        filtered = filtered.filter(e => e.is_suspicious === 1);
    } else if (currentEventFilter !== 'all') {
        filtered = filtered.filter(e => e.event_type === currentEventFilter);
    }

    if (eventSearchQuery) {
        const q = eventSearchQuery.toLowerCase();
        filtered = filtered.filter(e =>
            (e.executable && e.executable.toLowerCase().includes(q)) ||
            (e.args && e.args.toLowerCase().includes(q)) ||
            (e.pod_name && e.pod_name.toLowerCase().includes(q)) ||
            (e.container_id && e.container_id.toLowerCase().includes(q)) ||
            (String(e.pid).includes(q))
        );
    }

    if (countEl) countEl.textContent = filtered.length;

    if (!filtered.length) {
        listEl.innerHTML = '<div class="empty-state"><div class="icon">📡</div><p>No telemetry events matching current filter</p></div>';
        return;
    }

    listEl.innerHTML = filtered.map(ev => createEventItemHTML(ev)).join('');
}

function filterEvents(type) {
    currentEventFilter = type;
    document.querySelectorAll('#view-monitoring .panel-tab').forEach(b => b.classList.remove('active'));
    event.target.classList.add('active');
    renderEventsList();
}

function filterEventsSearch() {
    eventSearchQuery = document.getElementById('eventSearchInput').value;
    renderEventsList();
}

function createEventItemHTML(ev) {
    const isSusp = ev.is_suspicious === 1;
    const score = Number(ev.threat_score || 0).toFixed(2);
    let scoreClass = 'score-safe';
    if (score >= 0.70) scoreClass = 'score-threat';
    else if (score >= 0.40) scoreClass = 'score-elevated';

    const timeStr = formatTimestamp(ev.observed_at);
    const cmd = escapeHtml(ev.args || ev.executable || 'unknown');
    const exe = escapeHtml(ev.executable || '');
    const pod = escapeHtml(ev.pod_name || 'host');
    const cid = ev.container_id ? ev.container_id.substring(0, 10) : 'none';

    return `
        <div class="event-item ${isSusp ? 'suspicious' : ''}">
            <span class="event-type-badge type-${ev.event_type}">${ev.event_type.replace('_', ' ')}</span>
            <div class="event-details">
                <div class="event-command" title="${cmd}">${cmd}</div>
                <div class="event-meta">
                    <span title="Executable: ${exe}">exe: ${exe.split('/').pop()}</span>
                    <span>pid: ${ev.pid}</span>
                    <span class="event-tag" title="Pod: ${pod}">pod: ${pod}</span>
                    <span class="event-tag" title="Container: ${cid}">cid: ${cid}</span>
                    <span>${timeStr}</span>
                </div>
            </div>
            <span class="event-threat-score ${scoreClass}" title="Composite Threat Score">${score}</span>
        </div>
    `;
}

// 3. Alerts List (Security Alerts)
function renderAlertsList() {
    const listEl = document.getElementById('alertsList');
    const countEl = document.getElementById('alertCount');

    let filtered = allAlerts;
    if (currentAlertSeverityFilter !== 'all') {
        filtered = filtered.filter(a => a.severity === currentAlertSeverityFilter);
    }
    if (currentAlertStatusFilter !== 'all') {
        filtered = filtered.filter(a => a.status === currentAlertStatusFilter);
    }

    if (countEl) countEl.textContent = filtered.length;

    if (!filtered.length) {
        listEl.innerHTML = '<div class="empty-state"><div class="icon">🛡️</div><p>No security alerts matching current filters</p></div>';
        return;
    }

    listEl.innerHTML = filtered.map(al => createAlertItemHTML(al)).join('');
}

function filterAlerts(severity) {
    currentAlertSeverityFilter = severity;
    const tabs = event.target.parentElement.querySelectorAll('.panel-tab');
    tabs.forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    renderAlertsList();
}

function filterAlertStatus(status) {
    currentAlertStatusFilter = status;
    const tabs = event.target.parentElement.querySelectorAll('.panel-tab');
    tabs.forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');
    renderAlertsList();
}

function createAlertItemHTML(al) {
    const sev = al.severity ? al.severity.toLowerCase() : 'medium';
    const pillClass = `pill-${sev}`;
    const timeStr = formatTimestamp(al.created_at);
    const ruleId = al.rule_id || 'ML-ANOMALY';
    const reason = escapeHtml(al.reason || 'Anomalous kernel behavior detected');
    const pod = al.event ? al.event.pod_name : (al.evidence && al.evidence.pod ? al.evidence.pod : 'workload');
    const cid = al.event ? al.event.container_id : (al.evidence && al.evidence.container ? al.evidence.container : '');
    const isAcknowledged = al.status === 'acknowledged';
    const isResolved = al.status === 'resolved';

    return `
        <div class="alert-item severity-${sev}">
            <span class="severity-pill ${pillClass}">${sev}</span>
            <div class="alert-body">
                <div class="alert-title-row">
                    <span class="rule-id-tag">${ruleId}</span>
                    <span class="alert-reason">${reason}</span>
                    <span class="status-badge status-${al.status}">${al.status}</span>
                </div>
                <div class="alert-meta-row">
                    <span>Target Pod: <strong>${escapeHtml(pod)}</strong></span>
                    ${cid ? `<span>Container: <code>${cid.substring(0, 10)}</code></span>` : ''}
                    <span>Score: <strong>${Number(al.score || 0).toFixed(2)}</strong></span>
                    <span>Triggered: ${timeStr}</span>
                    ${al.acknowledged_by ? `<span style="color:var(--sev-medium);">Ack by: ${escapeHtml(al.acknowledged_by)}</span>` : ''}
                </div>
            </div>
            <div class="alert-actions">
                ${!isAcknowledged && !isResolved ? `
                    <button class="btn btn-ack btn-sm" onclick="handleAcknowledgeAlert('${al.id}')" title="Acknowledge Alert">
                        ✓ Acknowledge
                    </button>
                ` : ''}
                <button class="btn btn-primary btn-sm" onclick="openAlertModal('${al.id}')">
                    🔍 Investigate
                </button>
            </div>
        </div>
    `;
}

// 4. Alert Acknowledge & Response Mitigation
async function handleAcknowledgeAlert(alertId) {
    try {
        const res = await fetch(`${API_BASE}/api/v1/alerts/${alertId}/acknowledge`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ actor: 'security_analyst', notes: 'Triaged via Web Dashboard' }),
        });
        if (res.ok) {
            console.log(`Alert ${alertId} acknowledged`);
            await loadAlerts();
            refreshStats();
        }
    } catch (e) {
        console.error('Error acknowledging alert:', e);
    }
}

async function triggerResponseAction(alertId, action) {
    try {
        const res = await fetch(`${API_BASE}/api/v1/responses`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alert_id: alertId,
                action: action,
                mode: 'simulate',
                actor: 'security_lead',
            }),
        });

        if (res.ok) {
            const data = await res.json();
            const resultBox = document.getElementById('modalResponseResult');
            if (resultBox) {
                resultBox.style.display = 'block';
                resultBox.className = 'env-banner';
                resultBox.style.marginTop = '12px';
                resultBox.style.width = '100%';
                resultBox.innerHTML = `<strong>Action Executed:</strong> ${escapeHtml(data.result)}`;
            }
            await loadAlerts();
            refreshStats();
        }
    } catch (e) {
        console.error('Error executing response action:', e);
    }
}

async function changeAlertStatus(alertId, status) {
    try {
        const res = await fetch(`${API_BASE}/api/v1/alerts/${alertId}?status=${status}`, {
            method: 'PATCH',
        });
        if (res.ok) {
            closeAlertModal();
            await loadAlerts();
            refreshStats();
        }
    } catch (e) {
        console.error('Error changing alert status:', e);
    }
}

// 5. Alert Investigation Modal
function openAlertModal(alertId) {
    const alertObj = allAlerts.find(a => a.id === alertId);
    if (!alertObj) return;

    const modal = document.getElementById('alertModal');
    const body = document.getElementById('alertModalBody');
    const ev = alertObj.event || {};
    const evidence = alertObj.evidence || {};

    const exec = ev.executable || evidence.executable || 'N/A';
    const args = ev.args || evidence.args || 'N/A';
    const pid = ev.pid || evidence.pid || 'N/A';
    const pod = ev.pod_name || evidence.pod || 'N/A';
    const namespace = ev.namespace || evidence.namespace || 'default';
    const container = ev.container_id || evidence.container || 'N/A';
    const recommendedAction = evidence.recommended_action || 'Review container lifecycle and process hierarchy.';

    body.innerHTML = `
        <div style="margin-bottom: 16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 10px;">
                <span class="severity-pill pill-${alertObj.severity}">${alertObj.severity.toUpperCase()}</span>
                <span class="rule-id-tag">${alertObj.rule_id || 'ML-ANOMALY'}</span>
                <span class="status-badge status-${alertObj.status}">${alertObj.status.toUpperCase()}</span>
            </div>
            <h4 style="font-size:15px; color:var(--text-main); margin-bottom:6px;">${escapeHtml(alertObj.reason)}</h4>
            <div style="font-size:12px; color:var(--text-muted);">Alert ID: <code>${alertObj.id}</code></div>
        </div>

        <div style="margin-bottom: 16px;">
            <div style="font-size:12px; font-weight:700; color:var(--primary-light); margin-bottom:6px;">FORENSIC EVENT EVIDENCE</div>
            <div class="forensics-box">
{
  "executable": "${escapeHtml(exec)}",
  "arguments": "${escapeHtml(args)}",
  "process_id": ${pid},
  "container_id": "${escapeHtml(container)}",
  "pod_name": "${escapeHtml(pod)}",
  "namespace": "${escapeHtml(namespace)}",
  "threat_score": ${Number(alertObj.score || 0).toFixed(4)},
  "detection_method": "${escapeHtml(evidence.detection_method || 'hybrid')}"
}
            </div>
        </div>

        <div style="background: rgba(99, 102, 241, 0.08); border: 1px solid var(--border-hover); border-radius: var(--radius-md); padding: 12px; margin-bottom: 16px;">
            <div style="font-size: 11px; font-weight: 700; color: #a5b4fc; text-transform: uppercase;">Recommended Remediation</div>
            <div style="font-size: 12px; color: #e0e7ff; margin-top: 4px;">${escapeHtml(recommendedAction)}</div>
        </div>

        <div id="modalResponseResult" style="display:none;"></div>

        <div class="mitigation-actions">
            <button class="btn btn-danger btn-sm" onclick="triggerResponseAction('${alertObj.id}', 'isolate_pod')">
                🛡️ Isolate Pod (Network Policy)
            </button>
            <button class="btn btn-danger btn-sm" onclick="triggerResponseAction('${alertObj.id}', 'terminate_container')">
                🛑 Terminate Container
            </button>
            <button class="btn btn-ghost btn-sm" onclick="triggerResponseAction('${alertObj.id}', 'quarantine')">
                📦 Quarantine Namespace
            </button>
            <button class="btn btn-ack btn-sm" onclick="changeAlertStatus('${alertObj.id}', 'resolved')">
                ✓ Mark Resolved
            </button>
            <button class="btn btn-ghost btn-sm" onclick="changeAlertStatus('${alertObj.id}', 'false_positive')">
                ✕ False Positive
            </button>
        </div>
    `;

    modal.classList.add('active');
}

function closeAlertModal() {
    const modal = document.getElementById('alertModal');
    if (modal) modal.classList.remove('active');
}

// 6. Threat Detection Rules Grid
function renderRulesGrid() {
    const grid = document.getElementById('rulesGrid');
    if (!grid) return;

    if (!activeRules.length) {
        grid.innerHTML = '<div class="empty-state"><div class="icon">⚔️</div><p>No active rules loaded</p></div>';
        return;
    }

    const mitreMap = {
        R001: 'T1611 • Escape to Host',
        R002: 'T1003 • OS Credential Dumping',
        R003: 'T1059 • Command & Scripting',
        R004: 'T1068 • Exploitation for Privilege Escalation',
        R005: 'T1496 • Resource Hijacking (Cryptomining)',
        R006: 'T1571 • Non-Standard Port Connection',
        R007: 'T1082 • System Information Discovery',
    };

    grid.innerHTML = activeRules.map(rule => {
        const mitre = mitreMap[rule.rule_id] || 'MITRE ATT&CK Container Matrix';
        return `
            <div class="rule-card">
                <div class="rule-header">
                    <span class="rule-id">${rule.rule_id}</span>
                    <span class="severity-pill pill-${rule.severity}">${rule.severity}</span>
                </div>
                <div class="rule-name">${escapeHtml(rule.name)}</div>
                <div class="rule-desc">${escapeHtml(rule.description || 'Heuristic threat signature')}</div>
                <div class="mitre-badge">${mitre}</div>
            </div>
        `;
    }).join('');
}

// 7. Container Monitoring Grid
function renderContainersList() {
    const container = document.getElementById('containersList');
    if (!container) return;

    if (!allContainers.length) {
        container.innerHTML = '<div class="empty-state"><div class="icon">📦</div><p>No container workloads tracked yet</p></div>';
        return;
    }

    container.innerHTML = allContainers.map(c => {
        const isSuspicious = c.status === 'suspicious' || c.threat_level === 'critical';
        const cardClass = isSuspicious ? 'container-card suspicious-workload' : 'container-card';
        const threatBadgeClass = c.threat_level === 'critical' ? 'pill-critical' : (c.threat_level === 'elevated' ? 'pill-medium' : 'pill-low');

        return `
            <div class="${cardClass}">
                <div class="container-card-header">
                    <span class="container-id-badge">${c.container_id.substring(0, 12)}</span>
                    <span class="severity-pill ${threatBadgeClass}">${c.threat_level.toUpperCase()}</span>
                </div>
                <div class="container-pod-name" title="${escapeHtml(c.pod_name)}">Pod: ${escapeHtml(c.pod_name || 'unknown')}</div>
                <div class="container-image" title="${escapeHtml(c.image)}">${escapeHtml(c.image || 'alpine')}</div>
                <div style="display:flex; gap:8px; margin-bottom:12px; font-size:11px;">
                    <span class="event-tag">ns: ${escapeHtml(c.namespace || 'default')}</span>
                    <span class="event-tag">node: ${escapeHtml(c.node_name || 'node-01')}</span>
                </div>
                <div class="container-stats-row">
                    <span>Events: <strong>${c.event_count || 0}</strong></span>
                    <span style="color:${c.alert_count > 0 ? 'var(--sev-critical)' : 'inherit'};">
                        Alerts: <strong>${c.alert_count || 0}</strong>
                    </span>
                    <span>Status: <strong>${c.status}</strong></span>
                </div>
            </div>
        `;
    }).join('');
}

// 8. Event Timeline
function renderTimeline() {
    const container = document.getElementById('timelineList');
    if (!container) return;

    // Merge events and alerts into a unified timeline
    const timelineItems = [];

    allEvents.forEach(e => {
        timelineItems.push({
            type: 'event',
            timestamp: new Date(e.observed_at),
            title: `Syscall: ${e.event_type}`,
            desc: e.args || e.executable || 'Kernel operation',
            severity: e.threat_score >= 0.7 ? 'critical' : (e.threat_score >= 0.4 ? 'high' : 'safe'),
            context: `${e.pod_name || 'pod'} • pid ${e.pid}`,
        });
    });

    allAlerts.forEach(a => {
        timelineItems.push({
            type: 'alert',
            timestamp: new Date(a.created_at),
            title: `🚨 Alert: ${a.rule_id || 'Detection'}`,
            desc: a.reason,
            severity: a.severity || 'critical',
            context: a.event ? a.event.pod_name : 'workload',
        });
    });

    timelineItems.sort((a, b) => b.timestamp - a.timestamp);
    const sliced = timelineItems.slice(0, 30);

    if (!sliced.length) {
        container.innerHTML = '<div class="empty-state"><div class="icon">🕐</div><p>No activity recorded in timeline</p></div>';
        return;
    }

    container.innerHTML = sliced.map(item => `
        <div class="timeline-item">
            <div class="timeline-marker ${item.severity}">
                ${item.type === 'alert' ? '🚨' : (item.severity === 'safe' ? '✓' : '⚠️')}
            </div>
            <div class="timeline-content">
                <div class="timeline-header">
                    <span class="timeline-title">${escapeHtml(item.title)}</span>
                    <span class="timeline-time">${formatTimestamp(item.timestamp)}</span>
                </div>
                <div style="font-size:12px; color:var(--text-main); font-family:var(--font-mono); margin-bottom:4px;">
                    ${escapeHtml(item.desc)}
                </div>
                <div style="font-size:11px; color:var(--text-subtle);">
                    ${escapeHtml(item.context)}
                </div>
            </div>
        </div>
    `).join('');
}

// 9. Analytics Charts
function renderAnalyticsCharts() {
    if (!currentMetrics) return;

    // A. Threat Distribution in Overview
    const overviewDist = document.getElementById('threatDistChart');
    if (overviewDist) {
        const dist = currentMetrics.alerts_by_severity || {};
        const total = (dist.critical || 0) + (dist.high || 0) + (dist.medium || 0) + (dist.low || 0) || 1;
        overviewDist.innerHTML = `
            ${createBarRow('Critical Threats', dist.critical || 0, total, 'fill-critical')}
            ${createBarRow('High Risk', dist.high || 0, total, 'fill-high')}
            ${createBarRow('Medium Risk', dist.medium || 0, total, 'fill-medium')}
            ${createBarRow('Low / Informational', dist.low || 0, total, 'fill-low')}
        `;
    }

    // B. Detection Methods
    const methodsEl = document.getElementById('detectionMethodsChart');
    if (methodsEl) {
        const methods = currentMetrics.detection_methods || { rule: 0, ml: 0, hybrid: 0 };
        const total = (methods.rule || 0) + (methods.ml || 0) + (methods.hybrid || 0) || 1;
        methodsEl.innerHTML = `
            ${createBarRow('Heuristic Rules Engine', methods.rule || 0, total, 'fill-primary')}
            ${createBarRow('Machine Learning Isolation Forest', methods.ml || 0, total, 'fill-success')}
            ${createBarRow('Hybrid Composite Scoring', methods.hybrid || 0, total, 'fill-medium')}
        `;
    }

    // C. Events by Type in Analytics View
    const evtTypeEl = document.getElementById('eventTypeChart');
    if (evtTypeEl) {
        const evts = currentMetrics.events_by_type || {};
        const total = (evts.process_exec || 0) + (evts.file_open || 0) + (evts.net_connect || 0) || 1;
        evtTypeEl.innerHTML = `
            ${createBarRow('process_exec (Syscall Exec)', evts.process_exec || 0, total, 'fill-primary')}
            ${createBarRow('file_open (File Access)', evts.file_open || 0, total, 'fill-medium')}
            ${createBarRow('net_connect (Socket Outbound)', evts.net_connect || 0, total, 'fill-success')}
        `;
    }

    // D. Severity Chart in Analytics View
    const sevEl = document.getElementById('severityChart');
    if (sevEl) {
        const dist = currentMetrics.alerts_by_severity || {};
        const total = (dist.critical || 0) + (dist.high || 0) + (dist.medium || 0) + (dist.low || 0) || 1;
        sevEl.innerHTML = `
            ${createBarRow('Critical', dist.critical || 0, total, 'fill-critical')}
            ${createBarRow('High', dist.high || 0, total, 'fill-high')}
            ${createBarRow('Medium', dist.medium || 0, total, 'fill-medium')}
            ${createBarRow('Low', dist.low || 0, total, 'fill-low')}
        `;
    }

    // E. Threat Score Sparkline Trajectory
    const sparklineEl = document.getElementById('threatScoreChart');
    if (sparklineEl) {
        const scores = currentMetrics.recent_threat_scores || [];
        sparklineEl.innerHTML = renderSVGSparkline(scores);
    }

    // F. Top Triggered Rules
    const topRulesEl = document.getElementById('topRulesPanel');
    if (topRulesEl) {
        const rules = currentMetrics.top_triggered_rules || [];
        if (!rules.length) {
            topRulesEl.innerHTML = '<div class="empty-state"><div class="icon">🏆</div><p>No rule triggers recorded</p></div>';
        } else {
            topRulesEl.innerHTML = rules.map(r => `
                <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 0; border-bottom:1px solid var(--border);">
                    <div>
                        <span class="rule-id-tag">${r.rule_id}</span>
                        <span style="font-size:12px; margin-left:8px; color:var(--text-main);">${escapeHtml(r.reason || r.rule_id)}</span>
                    </div>
                    <span class="count-badge">${r.count} matches</span>
                </div>
            `).join('');
        }
    }

    // G. Histogram Bins
    const histEl = document.getElementById('scoreHistogramPanel');
    if (histEl) {
        const scores = allEvents.map(e => Number(e.threat_score || 0));
        const bins = [0, 0, 0, 0, 0]; // 0-0.2, 0.2-0.4, 0.4-0.6, 0.6-0.8, 0.8-1.0
        scores.forEach(s => {
            if (s < 0.2) bins[0]++;
            else if (s < 0.4) bins[1]++;
            else if (s < 0.6) bins[2]++;
            else if (s < 0.8) bins[3]++;
            else bins[4]++;
        });
        const maxBin = Math.max(...bins, 1);

        histEl.innerHTML = `
            <div style="display:grid; grid-template-columns: repeat(5, 1fr); gap:12px; align-items:end; height:140px; padding: 10px 0;">
                ${bins.map((val, idx) => {
                    const pct = Math.round((val / maxBin) * 100);
                    const labels = ['0.0 - 0.2 (Normal)', '0.2 - 0.4 (Low)', '0.4 - 0.6 (Medium)', '0.6 - 0.8 (Elevated)', '0.8 - 1.0 (Critical)'];
                    const colors = ['var(--success)', 'var(--sev-low)', 'var(--sev-medium)', 'var(--sev-high)', 'var(--sev-critical)'];
                    return `
                        <div style="display:flex; flex-direction:column; align-items:center; height:100%; justify-content:flex-end;">
                            <span style="font-size:11px; font-weight:700; margin-bottom:4px; font-family:var(--font-mono);">${val}</span>
                            <div style="width:100%; height:${Math.max(pct, 6)}%; background:${colors[idx]}; border-radius:4px 4px 0 0; transition:height 0.4s ease;"></div>
                            <span style="font-size:10px; color:var(--text-subtle); margin-top:6px; text-align:center;">${labels[idx]}</span>
                        </div>
                    `;
                }).join('')}
            </div>
        `;
    }
}

function createBarRow(label, count, total, fillClass) {
    const pct = Math.round((count / total) * 100);
    return `
        <div class="bar-chart-row">
            <div class="bar-chart-label">
                <span>${label}</span>
                <span><strong>${count}</strong> (${pct}%)</span>
            </div>
            <div class="bar-track">
                <div class="bar-fill ${fillClass}" style="width: ${pct}%;"></div>
            </div>
        </div>
    `;
}

function renderSVGSparkline(scores) {
    if (!scores || !scores.length) {
        return '<div class="empty-state"><div class="icon">📈</div><p>Streaming scores trajectory…</p></div>';
    }

    const width = 600;
    const height = 150;
    const padding = 20;

    const points = scores.map((val, idx) => {
        const x = padding + (idx / Math.max(scores.length - 1, 1)) * (width - 2 * padding);
        const y = height - padding - (val * (height - 2 * padding));
        return `${x.toFixed(1)},${y.toFixed(1)}`;
    }).join(' ');

    const lastVal = scores[scores.length - 1];

    return `
        <div style="position:relative;">
            <svg viewBox="0 0 ${width} ${height}" class="sparkline-svg" style="width:100%; height:160px;">
                <defs>
                    <linearGradient id="scoreGrad" x1="0%" y1="0%" x2="0%" y2="100%">
                        <stop offset="0%" stop-color="#6366f1" stop-opacity="0.3"/>
                        <stop offset="100%" stop-color="#6366f1" stop-opacity="0.0"/>
                    </linearGradient>
                </defs>
                <line x1="${padding}" y1="${height - padding - 0.6 * (height - 2 * padding)}" x2="${width - padding}" y2="${height - padding - 0.6 * (height - 2 * padding)}" stroke="rgba(239, 68, 68, 0.4)" stroke-dasharray="4" stroke-width="1"/>
                <polyline fill="none" stroke="#6366f1" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" points="${points}"/>
            </svg>
            <div style="display:flex; justify-content:space-between; font-size:11px; color:var(--text-subtle); margin-top:4px;">
                <span>Historical Stream</span>
                <span>Threshold: <strong style="color:var(--sev-critical);">0.60</strong></span>
                <span>Latest Score: <strong style="color:var(--primary-light);">${lastVal.toFixed(2)}</strong></span>
            </div>
        </div>
    `;
}

// 10. Audit Log
function renderAuditList() {
    const container = document.getElementById('auditList');
    if (!container) return;

    document.getElementById('auditCount').textContent = auditLogs.length;

    if (!auditLogs.length) {
        container.innerHTML = '<div class="empty-state"><div class="icon">📝</div><p>No audit trail records yet.</p></div>';
        return;
    }

    container.innerHTML = `
        <table style="width:100%; border-collapse:collapse; font-size:12px;">
            <thead>
                <tr style="border-bottom:1px solid var(--border); color:var(--text-muted); text-align:left;">
                    <th style="padding:8px;">Timestamp</th>
                    <th style="padding:8px;">Actor</th>
                    <th style="padding:8px;">Action</th>
                    <th style="padding:8px;">Target</th>
                    <th style="padding:8px;">Detail</th>
                </tr>
            </thead>
            <tbody>
                ${auditLogs.map(log => `
                    <tr style="border-bottom:1px solid var(--border);">
                        <td style="padding:8px; font-family:var(--font-mono); color:var(--text-subtle);">${formatTimestamp(log.timestamp)}</td>
                        <td style="padding:8px; font-weight:600; color:var(--primary-light);">${escapeHtml(log.actor)}</td>
                        <td style="padding:8px;"><span class="rule-id-tag">${escapeHtml(log.action)}</span></td>
                        <td style="padding:8px; font-family:var(--font-mono);">${escapeHtml(log.target ? log.target.substring(0, 10) : 'system')}</td>
                        <td style="padding:8px; color:var(--text-muted);">${escapeHtml(log.detail)}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}

// ──────────────────────────────────────────────
// Utility Functions
// ──────────────────────────────────────────────

function formatTimestamp(ts) {
    if (!ts) return '--:--:--';
    const d = new Date(ts);
    return d.toTimeString().split(' ')[0];
}

function escapeHtml(str) {
    if (!str) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function updateClock() {
    const clockEl = document.getElementById('currentTime');
    if (clockEl) {
        const now = new Date();
        clockEl.textContent = now.toUTCString().split(' ')[4] + ' UTC';
    }
}

// ──────────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    console.log('🛡️ Initializing ContainerShield AI Dashboard...');

    // Live clock
    setInterval(updateClock, 1000);
    updateClock();

    // Initial WebSocket
    connectWebSocket();

    // Initial Data Fetch
    refreshCurrentView();

    // Auto-refresh stats every 8 seconds
    setInterval(() => {
        refreshStats();
        if (currentView === 'overview' || currentView === 'analytics') {
            fetchMetricsSummary();
        }
    }, 8000);
});
