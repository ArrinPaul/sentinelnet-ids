import axios from 'axios';

const API_BASE = 'http://localhost:8000';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
});

// ── Traffic ─────────────────────────────────────────────────────────────────
export const getRecentTraffic = (limit = 50) =>
  api.get(`/traffic/recent?limit=${limit}`);

export const ingestTraffic = (data) =>
  api.post('/traffic/ingest', data);

export const simulateTraffic = (mode = 'random', count = 1) =>
  api.post(`/traffic/simulate?mode=${mode}&count=${count}`);

// ── Alerts ──────────────────────────────────────────────────────────────────
export const getCurrentAlerts = () =>
  api.get('/alerts/current');

export const getAlertHistory = (limit = 100) =>
  api.get(`/alerts/history?limit=${limit}`);

// ── Policies ────────────────────────────────────────────────────────────────
export const getGeneratedPolicies = (limit = 50) =>
  api.get(`/policies/generated?limit=${limit}`);

export const getLatestPolicy = () =>
  api.get('/policies/latest');

// ── System ──────────────────────────────────────────────────────────────────
export const getSystemStatus = () =>
  api.get('/system/status');

export const getSystemStats = () =>
  api.get('/system/stats');

export default api;
