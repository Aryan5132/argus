/**
 * Sentinel – Main App Controller
 * Handles routing, state, real-time polling, and event orchestration.
 */

const STATE = {
  view: 'dashboard',
  findings: { page: 1, pageSize: 25, total: 0, pages: 0, items: [] },
  filters: { severity: '', resource_type: '', status: 'OPEN', search: '' },
  scans: [],
  stats: null,
  lastScanAt: null,
  schedulerNextRun: null,
  scanning: false,
  pollInterval: null,
  relativeTimeInterval: null,
  clockInterval: null,
};

// ── Initialise ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  bindNavigation();
  bindActions();
  startLiveClock();
  loadAllData();

  // Real-time polling: refresh every 10 seconds
  STATE.pollInterval = setInterval(() => {
    loadAllData(true);  // silent refresh
  }, 10_000);

  // Live relative-time updates between API refreshes
  STATE.relativeTimeInterval = setInterval(() => {
    refreshRelativeTimeLabels();
  }, 5_000);
});

// ── Live Clock ────────────────────────────────────────────────────────
function startLiveClock() {
  const clockEl = document.getElementById('live-clock');
  if (!clockEl) return;
  function tick() {
    const now = new Date();
    clockEl.textContent = now.toLocaleString(undefined, {
      weekday: 'short',
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  }
  tick();
  STATE.clockInterval = setInterval(tick, 1000);
}

// ── Navigation ────────────────────────────────────────────────────────
function bindNavigation() {
  document.querySelectorAll('.nav-item, .view-all-link').forEach(el => {
    el.addEventListener('click', e => {
      e.preventDefault();
      navigateTo(el.dataset.view);
    });
  });
}

function navigateTo(view) {
  if (!view) return;
  STATE.view = view;

  document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));

  const viewEl = document.getElementById(`view-${view}`);
  const navEl  = document.getElementById(`nav-${view}`);
  if (viewEl) viewEl.classList.add('active');
  if (navEl)  navEl.classList.add('active');

  const titles = { dashboard: 'Dashboard', findings: 'Findings', scans: 'Scan History', settings: 'Settings' };
  document.getElementById('page-title').textContent = titles[view] || view;

  if (view === 'findings') loadFindings();
  if (view === 'scans')    loadScans();
  if (view === 'settings') loadSettings();
}

// ── Actions ───────────────────────────────────────────────────────────
function bindActions() {
  // Trigger scan
  document.getElementById('trigger-scan-btn').addEventListener('click', triggerScan);
  document.getElementById('refresh-btn').addEventListener('click', () => loadAllData());

  // Findings filters
  document.getElementById('search-input').addEventListener('input', debounce(() => {
    STATE.filters.search = document.getElementById('search-input').value;
    STATE.findings.page = 1;
    loadFindings();
  }, 400));

  ['filter-severity', 'filter-resource', 'filter-status'].forEach(id => {
    document.getElementById(id).addEventListener('change', e => {
      const key = id.replace('filter-', '').replace('-', '_');
      STATE.filters[key] = e.target.value;
      STATE.findings.page = 1;
      loadFindings();
    });
  });

  // Settings actions
  document.getElementById('save-alert-btn').addEventListener('click', saveAlertConfig);
  document.getElementById('test-alert-btn').addEventListener('click', testAlertConfig);
}

// ── Load All Data ─────────────────────────────────────────────────────
async function loadAllData(silent = false) {
  try {
    const [stats, awsStatus] = await Promise.all([
      api.getStats(),
      api.getAWSStatus(),
    ]);

    STATE.stats = stats;
    updateDashboard(stats);
    updateAWSStatus(awsStatus);

    if (STATE.view === 'findings') loadFindings(silent);
    if (STATE.view === 'scans')    loadScans(silent);
  } catch (err) {
    if (!silent) showToast('Failed to load dashboard data: ' + err.message, 'error');
  }
}

// ── Dashboard ─────────────────────────────────────────────────────────
function updateDashboard(stats) {
  document.getElementById('kpi-critical').textContent = stats.critical;
  document.getElementById('kpi-high').textContent     = stats.high;
  document.getElementById('kpi-medium').textContent   = stats.medium;
  document.getElementById('kpi-low').textContent      = stats.low;
  document.getElementById('kpi-open').textContent     = stats.open_findings;
  document.getElementById('kpi-fixed').textContent    = stats.fixed;

  const lastScanEl = document.getElementById('last-scan-text');
  if (stats.last_scan_at) {
    STATE.lastScanAt = stats.last_scan_at;
    const scanDate = new Date(stats.last_scan_at);
    const formatted = scanDate.toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    });
    if (lastScanEl) {
      lastScanEl.textContent = 'Last scan: ' + formatted + ' (' + timeAgo(stats.last_scan_at) + ')';
    }
  } else if (lastScanEl) {
    lastScanEl.textContent = 'Last scan: No scan yet';
  }

  // Badge
  const badge = document.getElementById('findings-badge');
  badge.textContent = stats.open_findings;
  badge.style.display = stats.open_findings > 0 ? 'inline' : 'none';

  updateCharts(stats);
  loadRecentFindings();
}

async function loadRecentFindings() {
  try {
    const resp = await api.getFindings({ page: 1, page_size: 8, status: 'OPEN' });
    const el = document.getElementById('recent-findings-table');
    if (el) el.innerHTML = renderRecentFindings(resp.items);
  } catch (e) {
    // silently fail
  }
}

// ── AWS Status ────────────────────────────────────────────────────────
function updateAWSStatus(status) {
  const dot  = document.getElementById('status-dot');
  const text = document.getElementById('aws-status-text');

  if (status.connected) {
    dot.className = 'status-dot connected';
    text.textContent = `AWS Live · ${status.region}`;
  } else {
    dot.className = 'status-dot demo';
    text.textContent = `Scanner Active · Generated Data (${status.region})`;
  }
}

// ── Findings ──────────────────────────────────────────────────────────
async function loadFindings(silent = false) {
  const params = {
    page: STATE.findings.page,
    page_size: STATE.findings.pageSize,
  };
  if (STATE.filters.severity)      params.severity = STATE.filters.severity;
  if (STATE.filters.resource_type) params.resource_type = STATE.filters.resource_type;
  if (STATE.filters.status)        params.status = STATE.filters.status;
  if (STATE.filters.search)        params.search = STATE.filters.search;

  try {
    const resp = await api.getFindings(params);
    STATE.findings = { ...STATE.findings, ...resp };

    const container = document.getElementById('findings-table-container');
    if (container) {
      container.innerHTML = renderFindingsTable(resp.items, onFindingClick);
      // Bind row clicks
      container.querySelectorAll('[data-id]').forEach(row => {
        row.addEventListener('click', () => onFindingClick(parseInt(row.dataset.id)));
      });
    }

    const pagEl = document.getElementById('findings-pagination');
    if (pagEl) {
      pagEl.innerHTML = renderPagination(resp.page, resp.pages, goToPage);
      pagEl.querySelectorAll('[data-page]').forEach(btn => {
        btn.addEventListener('click', () => goToPage(parseInt(btn.dataset.page)));
      });
    }
  } catch (err) {
    if (!silent) showToast('Failed to load findings: ' + err.message, 'error');
  }
}

function goToPage(page) {
  STATE.findings.page = page;
  loadFindings();
}

async function onFindingClick(id) {
  try {
    const finding = await api.getFinding(id);
    const panel = document.getElementById('detail-panel');
    const content = document.getElementById('detail-content');
    const overlay = document.getElementById('detail-overlay');

    content.innerHTML = renderDetailPanel(finding);
    panel.classList.add('open');

    // Close handlers
    document.getElementById('close-detail-btn').addEventListener('click', closeDetail);
    overlay.addEventListener('click', closeDetail);

    // Status update buttons
    content.querySelectorAll('.status-action-btn').forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await api.updateFindingStatus(btn.dataset.id, btn.dataset.status);
          showToast(`Marked as ${btn.dataset.status}`, 'success');
          closeDetail();
          loadFindings();
          loadAllData(true);
        } catch (e) {
          showToast('Update failed: ' + e.message, 'error');
        }
      });
    });
  } catch (err) {
    showToast('Failed to load finding: ' + err.message, 'error');
  }
}

function closeDetail() {
  document.getElementById('detail-panel').classList.remove('open');
}

// ── Scans ─────────────────────────────────────────────────────────────
async function loadScans(silent = false) {
  try {
    const [scansResp, scheduler] = await Promise.all([
      api.getScans(1, 20),
      api.getScheduler(),
    ]);
    STATE.scans = scansResp.items;

    const el = document.getElementById('scans-table');
    if (el) el.innerHTML = renderScansTable(scansResp.items);

    const info = document.getElementById('scheduler-info');
    if (info && scheduler) {
      const nextRun = scheduler.jobs[0]?.next_run;
      STATE.schedulerNextRun = nextRun || null;
      info.textContent = scheduler.running
        ? `Scheduler running · Every ${scheduler.interval_hours}h · Next: ${nextRun ? timeAgo(nextRun) : '—'}`
        : 'Scheduler stopped';
    }
  } catch (err) {
    if (!silent) showToast('Failed to load scans: ' + err.message, 'error');
  }
}

function refreshRelativeTimeLabels() {
  if (STATE.lastScanAt) {
    const lastScanText = document.getElementById('last-scan-text');
    if (lastScanText && !STATE.scanning) {
      const scanDate = new Date(STATE.lastScanAt);
      const formatted = scanDate.toLocaleString(undefined, {
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit',
      });
      lastScanText.textContent = 'Last scan: ' + formatted + ' (' + timeAgo(STATE.lastScanAt) + ')';
    }
  }

  const info = document.getElementById('scheduler-info');
  if (info && STATE.schedulerNextRun) {
    const schedInterval = document.getElementById('sched-interval');
    const everyText = schedInterval ? schedInterval.textContent : 'Every —';
    info.textContent = `Scheduler running · ${everyText} · Next: ${timeAgo(STATE.schedulerNextRun)}`;
  }
}

// ── Reset UI to zero before a new scan ────────────────────────────────
function resetStatsUI() {
  // Zero out all KPI counters
  ['kpi-critical', 'kpi-high', 'kpi-medium', 'kpi-low', 'kpi-open', 'kpi-fixed'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.textContent = '0';
  });

  // Hide findings badge
  const badge = document.getElementById('findings-badge');
  if (badge) { badge.textContent = '0'; badge.style.display = 'none'; }

  // Clear last-scan text
  const lastScanText = document.getElementById('last-scan-text');
  if (lastScanText) lastScanText.textContent = 'Scanning in progress...';

  // Clear recent findings table
  const recentTable = document.getElementById('recent-findings-table');
  if (recentTable) recentTable.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⟳</div><p>Scan running — results will appear shortly.</p></div>';

  // Clear findings table if on findings view
  const findingsContainer = document.getElementById('findings-table-container');
  if (findingsContainer) findingsContainer.innerHTML = '<div class="empty-state"><div class="empty-state-icon">⟳</div><p>Scan running — results will appear shortly.</p></div>';

  // Reset charts to zero
  if (typeof resetCharts === 'function') resetCharts();
}

// ── Trigger Scan ──────────────────────────────────────────────────────
async function triggerScan() {
  if (STATE.scanning) return;
  STATE.scanning = true;

  const btn = document.getElementById('trigger-scan-btn');
  const indicator = document.getElementById('scan-indicator');
  btn.classList.add('scanning');
  btn.textContent = '⟳ Scanning...';
  indicator.style.display = 'flex';

  // Reset all displayed values to zero immediately
  resetStatsUI();

  try {
    await api.triggerScan();
    showToast('Scan triggered! Results will appear in ~30 seconds.', 'info');

    // Poll for completion
    let checks = 0;
    const poll = setInterval(async () => {
      checks++;
      try {
        await loadAllData(true);
      } catch (e) {}
      if (checks >= 20) {
        clearInterval(poll);
        stopScanUI();
      }
    }, 5_000);

    // Auto-stop after 2 min
    setTimeout(() => { clearInterval(poll); stopScanUI(); }, 120_000);
  } catch (err) {
    showToast('Failed to trigger scan: ' + err.message, 'error');
    stopScanUI();
  }
}

function stopScanUI() {
  STATE.scanning = false;
  const btn = document.getElementById('trigger-scan-btn');
  const indicator = document.getElementById('scan-indicator');
  btn.classList.remove('scanning');
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Run Scan Now`;
  indicator.style.display = 'none';
  loadAllData(true);
}

// ── Settings ──────────────────────────────────────────────────────────
async function loadSettings() {
  try {
    const [awsStatus, scheduler] = await Promise.all([
      api.getAWSStatus(),
      api.getScheduler(),
    ]);

    document.getElementById('settings-aws-status').textContent  = awsStatus.connected ? '✅ Connected' : '✅ Local Generator Active';
    document.getElementById('settings-account-id').textContent  = awsStatus.account_id || '—';
    document.getElementById('settings-region').textContent      = awsStatus.region || '—';
    document.getElementById('settings-mode').textContent        = awsStatus.connected ? 'live' : 'generated';

    document.getElementById('sched-status').textContent   = scheduler.running ? '✅ Running' : '⛔ Stopped';
    document.getElementById('sched-interval').textContent = `Every ${scheduler.interval_hours} hour(s)`;
    const nextRun = scheduler.jobs[0]?.next_run;
    document.getElementById('sched-next').textContent = nextRun ? new Date(nextRun).toLocaleString() : '—';
  } catch (e) {}
}

async function saveAlertConfig() {
  const type   = document.getElementById('alert-type-select').value;
  const target = document.getElementById('alert-target').value.trim();
  const sev    = document.getElementById('alert-min-sev').value;

  if (!target) { showToast('Please enter a target email or webhook URL', 'warning'); return; }

  try {
    await api.createAlert({ alert_type: type, enabled: true, target, min_severity: sev });
    showToast('Alert configuration saved!', 'success');
    document.getElementById('alert-target').value = '';
  } catch (err) {
    showToast('Failed to save: ' + err.message, 'error');
  }
}

async function testAlertConfig() {
  const type = document.getElementById('alert-type-select').value;
  try {
    const resp = await api.testAlert(type);
    showToast(resp.message, resp.success ? 'success' : 'error');
  } catch (err) {
    showToast('Test failed: ' + err.message, 'error');
  }
}

// ── Utilities ─────────────────────────────────────────────────────────
function debounce(fn, delay) {
  let timer;
  return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), delay); };
}
