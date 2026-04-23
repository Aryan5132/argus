/**
 * Sentinel – Reusable UI Components
 */

// ── Toast Notifications ────────────────────────────────────────────────
function showToast(message, type = 'info', duration = 4000) {
  const icons = { success: '✅', error: '🔴', info: 'ℹ️', warning: '⚠️' };
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `<span>${icons[type] || ''}</span><span>${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'toast-in 0.3s ease reverse';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ── Severity Badge ─────────────────────────────────────────────────────
function severityBadge(severity) {
  return `<span class="badge badge-${severity}">${severity}</span>`;
}

// ── Status Badge ───────────────────────────────────────────────────────
function statusBadge(status) {
  const labels = {
    OPEN: 'Open', ACKNOWLEDGED: 'Acknowledged',
    FIXED: 'Fixed', FALSE_POSITIVE: 'False Positive',
  };
  return `<span class="status-badge status-${status}">${labels[status] || status}</span>`;
}

// ── ML Risk Score Bar ──────────────────────────────────────────────────
function riskScoreBar(score) {
  const pct = Math.round(score * 100);
  let color = '#00bb77';
  if (pct >= 80) color = '#ff3366';
  else if (pct >= 60) color = '#ff6b35';
  else if (pct >= 40) color = '#ffb800';
  return `
    <div class="risk-score-bar">
      <div class="risk-bar-bg">
        <div class="risk-bar-fill" style="width:${pct}%;background:${color}"></div>
      </div>
      <span class="risk-score-val">${score.toFixed(2)}</span>
    </div>`;
}

// ── Resource Type Icon ─────────────────────────────────────────────────
function resourceIcon(type) {
  const icons = {
    S3: '🪣', IAM: '👤', SECURITY_GROUP: '🔒', EC2: '🖥️',
  };
  return icons[type] || '☁️';
}

// ── Format Timestamp ───────────────────────────────────────────────────
function formatDate(isoStr) {
  if (!isoStr) return '—';
  let str = isoStr;
  if (typeof str === 'string' && !str.endsWith('Z') && !str.match(/[+\-]\d{2}:?\d{2}$/) && str.includes('T')) str += 'Z';
  const d = new Date(str);
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

function timeAgo(isoStr) {
  if (!isoStr) return '—';
  let str = isoStr;
  if (typeof str === 'string' && !str.endsWith('Z') && !str.match(/[+\-]\d{2}:?\d{2}$/) && str.includes('T')) str += 'Z';
  const diff = Date.now() - new Date(str).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

// ── Findings Table ─────────────────────────────────────────────────────
function renderFindingsTable(findings, onRowClick) {
  if (!findings.length) {
    return `<div class="empty-state">
      <div class="empty-state-icon">🛡️</div>
      <p>No findings matching the current filters.</p>
    </div>`;
  }

  const rows = findings.map(f => `
    <tr data-id="${f.id}" style="cursor:pointer">
      <td>${severityBadge(f.severity)}</td>
      <td>${resourceIcon(f.resource_type)} <span style="font-size:11px;color:var(--text-secondary)">${f.resource_type}</span></td>
      <td style="max-width:300px">
        <div style="font-size:13px;font-weight:500;color:var(--text-primary);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${f.title}</div>
      </td>
      <td class="resource-id">${f.resource_id}</td>
      <td>${riskScoreBar(f.ml_risk_score)}</td>
      <td>${statusBadge(f.status)}</td>
      <td style="color:var(--text-dim);font-size:12px">${timeAgo(f.created_at)}</td>
    </tr>`).join('');

  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Severity</th><th>Resource</th><th>Finding</th>
          <th>Resource ID</th><th>Risk Score</th><th>Status</th><th>Detected</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── Finding Detail Panel ───────────────────────────────────────────────
function renderDetailPanel(finding) {
  const scoreColor = finding.ml_risk_score >= 0.8 ? '#ff3366'
    : finding.ml_risk_score >= 0.6 ? '#ff6b35'
    : finding.ml_risk_score >= 0.4 ? '#ffb800' : '#00bb77';

  return `
    <button class="detail-close" id="close-detail-btn">✕</button>
    <div style="margin-bottom:10px">${severityBadge(finding.severity)}&nbsp;&nbsp;${statusBadge(finding.status)}</div>
    <h2 class="detail-title">${finding.title}</h2>

    <div class="detail-field">
      <div class="detail-label">Resource Type</div>
      <div class="detail-value">${resourceIcon(finding.resource_type)} ${finding.resource_type}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Resource ID</div>
      <div class="detail-value mono">${finding.resource_id}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Region</div>
      <div class="detail-value mono">${finding.region || '—'}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Rule ID</div>
      <div class="detail-value mono">${finding.rule_id}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">ML Risk Score</div>
      <div class="risk-meter">
        <div class="risk-meter-bar">
          <div class="risk-meter-fill" style="width:${Math.round(finding.ml_risk_score*100)}%;background:${scoreColor}"></div>
        </div>
        <span style="font-family:var(--font-mono);font-size:13px;color:${scoreColor}">${finding.ml_risk_score.toFixed(3)}</span>
      </div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Description</div>
      <div class="detail-value" style="line-height:1.6;color:var(--text-secondary)">${finding.description}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">💡 Suggested Fix</div>
      <div class="fix-box">${finding.suggested_fix}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Detected</div>
      <div class="detail-value">${formatDate(finding.created_at)}</div>
    </div>
    <div class="detail-field">
      <div class="detail-label">Update Status</div>
      <div class="status-actions">
        <button class="status-action-btn ack" data-status="ACKNOWLEDGED" data-id="${finding.id}">Acknowledge</button>
        <button class="status-action-btn fix" data-status="FIXED" data-id="${finding.id}">Mark Fixed</button>
        <button class="status-action-btn fp"  data-status="FALSE_POSITIVE" data-id="${finding.id}">False Positive</button>
      </div>
    </div>`;
}

// ── Scans Table ────────────────────────────────────────────────────────
function renderScansTable(scans) {
  if (!scans.length) {
    return `<div class="empty-state"><div class="empty-state-icon">📊</div><p>No scans yet. Click "Run Scan Now" to start.</p></div>`;
  }

  const rows = scans.map(s => {
    const total = s.total_findings || 0;
    const critW = total ? Math.max(3, (s.critical_count / total) * 80) : 0;
    const highW = total ? Math.max(3, (s.high_count / total) * 80) : 0;
    const medW  = total ? Math.max(3, (s.medium_count / total) * 80) : 0;
    const lowW  = total ? Math.max(3, (s.low_count / total) * 80) : 0;

    return `
      <tr>
        <td style="font-family:var(--font-mono);font-size:12px">#${s.id}</td>
        <td><span class="scan-status-${s.status.toLowerCase()}">${s.status}</span></td>
        <td style="font-size:12px;color:var(--text-secondary)">${formatDate(s.started_at)}</td>
        <td style="font-size:12px;color:var(--text-secondary)">${s.completed_at ? formatDate(s.completed_at) : '—'}</td>
        <td style="font-size:12px;color:var(--text-secondary)">${s.triggered_by}</td>
        <td>
          <div style="display:flex;align-items:center;gap:6px">
            <div class="mini-bar">
              ${s.critical_count ? `<div class="mini-bar-seg" style="width:${critW}px;background:#ff3366" title="Critical: ${s.critical_count}"></div>` : ''}
              ${s.high_count ? `<div class="mini-bar-seg" style="width:${highW}px;background:#ff6b35" title="High: ${s.high_count}"></div>` : ''}
              ${s.medium_count ? `<div class="mini-bar-seg" style="width:${medW}px;background:#ffb800" title="Medium: ${s.medium_count}"></div>` : ''}
              ${s.low_count ? `<div class="mini-bar-seg" style="width:${lowW}px;background:#00bb77" title="Low: ${s.low_count}"></div>` : ''}
            </div>
            <span style="font-size:12px;color:var(--text-secondary)">${total}</span>
          </div>
        </td>
      </tr>`;
  }).join('');

  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Run #</th><th>Status</th><th>Started</th><th>Completed</th>
          <th>Triggered By</th><th>Findings</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── Recent Findings Mini Table (Dashboard) ─────────────────────────────
function renderRecentFindings(findings) {
  if (!findings.length) {
    return `<div class="empty-state"><div class="empty-state-icon">✅</div><p>No open findings. Your cloud looks healthy!</p></div>`;
  }
  const rows = findings.slice(0, 8).map(f => `
    <tr>
      <td>${severityBadge(f.severity)}</td>
      <td>${resourceIcon(f.resource_type)}&nbsp;<span style="font-size:11px;color:var(--text-secondary)">${f.resource_type}</span></td>
      <td style="max-width:320px;font-size:13px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${f.title}</td>
      <td class="resource-id">${f.resource_id.slice(0, 40)}${f.resource_id.length > 40 ? '...' : ''}</td>
      <td>${riskScoreBar(f.ml_risk_score)}</td>
      <td style="color:var(--text-dim);font-size:12px">${timeAgo(f.created_at)}</td>
    </tr>`).join('');

  return `
    <table class="data-table">
      <thead>
        <tr><th>Severity</th><th>Resource</th><th>Finding</th><th>Resource ID</th><th>Risk</th><th>When</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── Pagination ─────────────────────────────────────────────────────────
function renderPagination(currentPage, totalPages, onPageClick) {
  if (totalPages <= 1) return '';
  let html = '';
  const start = Math.max(1, currentPage - 2);
  const end   = Math.min(totalPages, currentPage + 2);

  if (currentPage > 1)
    html += `<button class="page-btn" data-page="${currentPage-1}">‹</button>`;

  for (let p = start; p <= end; p++)
    html += `<button class="page-btn${p === currentPage ? ' active' : ''}" data-page="${p}">${p}</button>`;

  if (currentPage < totalPages)
    html += `<button class="page-btn" data-page="${currentPage+1}">›</button>`;

  html += `<span class="page-info">Page ${currentPage} of ${totalPages}</span>`;
  return html;
}
