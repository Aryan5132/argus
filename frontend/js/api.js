/**
 * Sentinel – API Client
 * All calls to the FastAPI backend go through here.
 */

const API_BASE = '';  // Same origin, served by FastAPI

const api = {
  async request(method, path, body = null) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
    };
    if (body) opts.body = JSON.stringify(body);
    const resp = await fetch(`${API_BASE}${path}`, opts);
    if (!resp.ok) {
      const err = await resp.text();
      throw new Error(err || `HTTP ${resp.status}`);
    }
    return resp.json();
  },

  // Stats
  getStats: ()          => api.request('GET', '/api/v1/stats'),
  getAWSStatus: ()      => api.request('GET', '/api/v1/stats/aws-status'),

  // Findings
  getFindings: (params) => api.request('GET', `/api/v1/findings?${new URLSearchParams(params)}`),
  getFinding: (id)      => api.request('GET', `/api/v1/findings/${id}`),
  updateFindingStatus: (id, status) =>
    api.request('PUT', `/api/v1/findings/${id}/status`, { status }),

  // Scans
  getScans: (page = 1, size = 10) =>
    api.request('GET', `/api/v1/scans?page=${page}&page_size=${size}`),
  triggerScan: ()    => api.request('POST', '/api/v1/scans/trigger'),
  getScheduler: ()   => api.request('GET', '/api/v1/scans/scheduler/status'),

  // Alerts
  getAlerts: ()      => api.request('GET', '/api/v1/alerts'),
  createAlert: (body) => api.request('POST', '/api/v1/alerts', body),
  deleteAlert: (id)  => api.request('DELETE', `/api/v1/alerts/${id}`),
  testAlert: (type)  => api.request('POST', '/api/v1/alerts/test', { alert_type: type }),

  // Health
  getHealth: ()      => api.request('GET', '/health'),
};
