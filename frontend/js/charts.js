/**
 * Sentinel – Chart.js Visualizations
 */

let severityChart = null;
let resourceChart = null;
let trendChart   = null;

const CHART_DEFAULTS = {
  font: { family: 'Inter, sans-serif', size: 12 },
  color: '#4a5a7a',
};

Chart.defaults.font = CHART_DEFAULTS.font;
Chart.defaults.color = CHART_DEFAULTS.color;

function initCharts() {
  _initSeverityChart();
  _initResourceChart();
  _initTrendChart();
}

// ── Severity Donut ─────────────────────────────────────────────────────
function _initSeverityChart() {
  const ctx = document.getElementById('severityChart');
  if (!ctx) return;
  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        data: [0, 0, 0, 0],
        backgroundColor: ['#ff3366', '#ff6b35', '#ffb800', '#00bb77'],
        borderColor: '#0d1224',
        borderWidth: 3,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: {
          position: 'bottom',
          labels: { padding: 16, usePointStyle: true, pointStyleWidth: 8, color: '#8899cc', font: { size: 11 } },
        },
        tooltip: {
          backgroundColor: '#12172b',
          borderColor: '#1e2a4a',
          borderWidth: 1,
          titleColor: '#e8eeff',
          bodyColor: '#8899cc',
          padding: 10,
        },
      },
    },
  });
}

// ── Resource Type Bar ──────────────────────────────────────────────────
function _initResourceChart() {
  const ctx = document.getElementById('resourceChart');
  if (!ctx) return;
  resourceChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Open Findings',
        data: [],
        backgroundColor: 'rgba(0, 212, 255, 0.15)',
        borderColor: '#00d4ff',
        borderWidth: 1,
        borderRadius: 4,
        hoverBackgroundColor: 'rgba(0, 212, 255, 0.3)',
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#12172b',
          borderColor: '#1e2a4a',
          borderWidth: 1,
          titleColor: '#e8eeff',
          bodyColor: '#8899cc',
          padding: 10,
        },
      },
      scales: {
        x: {
          grid: { color: 'rgba(30,45,90,0.3)', drawBorder: false },
          ticks: { color: '#4a5a7a' },
        },
        y: {
          grid: { color: 'rgba(30,45,90,0.3)', drawBorder: false },
          ticks: { color: '#4a5a7a', stepSize: 1 },
          beginAtZero: true,
        },
      },
    },
  });
}

// ── Trend Line Chart ───────────────────────────────────────────────────
function _initTrendChart() {
  const ctx = document.getElementById('trendChart');
  if (!ctx) return;
  trendChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Findings Detected',
        data: [],
        borderColor: '#00d4ff',
        backgroundColor: 'rgba(0, 212, 255, 0.05)',
        borderWidth: 2,
        fill: true,
        tension: 0.4,
        pointBackgroundColor: '#00d4ff',
        pointBorderColor: '#0d1224',
        pointBorderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 6,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#12172b',
          borderColor: '#1e2a4a',
          borderWidth: 1,
          titleColor: '#e8eeff',
          bodyColor: '#8899cc',
          padding: 10,
        },
      },
      scales: {
        x: {
          grid: { color: 'rgba(30,45,90,0.3)', drawBorder: false },
          ticks: { color: '#4a5a7a', maxTicksLimit: 7 },
        },
        y: {
          grid: { color: 'rgba(30,45,90,0.3)', drawBorder: false },
          ticks: { color: '#4a5a7a', stepSize: 1 },
          beginAtZero: true,
        },
      },
    },
  });
}

// ── Reset Charts to Zero (called before a new scan) ───────────────────
function resetCharts() {
  if (severityChart) {
    severityChart.data.datasets[0].data = [0, 0, 0, 0];
    severityChart.update('none');
  }
  if (resourceChart) {
    resourceChart.data.labels = [];
    resourceChart.data.datasets[0].data = [];
    resourceChart.update('none');
  }
  if (trendChart) {
    trendChart.data.labels = [];
    trendChart.data.datasets[0].data = [];
    trendChart.update('none');
  }
}

// ── Update Charts with Real Data ───────────────────────────────────────
function updateCharts(stats) {
  // Severity donut
  if (severityChart) {
    severityChart.data.datasets[0].data = [
      stats.critical, stats.high, stats.medium, stats.low,
    ];
    severityChart.update('active');
  }

  // Resource bar
  if (resourceChart && stats.findings_by_resource) {
    const labels = Object.keys(stats.findings_by_resource).map(k =>
      k === 'SECURITY_GROUP' ? 'Sec. Group' : k
    );
    const values = Object.values(stats.findings_by_resource);
    resourceChart.data.labels = labels;
    resourceChart.data.datasets[0].data = values;
    resourceChart.update('active');
  }

  // Trend line
  if (trendChart && stats.findings_trend && stats.findings_trend.length) {
    trendChart.data.labels = stats.findings_trend.map(r => {
      const d = new Date(r.date.replace(' ', 'T') + 'Z');
      return d.toLocaleTimeString(undefined, { hour: 'numeric' });
    });
    trendChart.data.datasets[0].data = stats.findings_trend.map(r => r.count);
    trendChart.update('active');
  }
}
