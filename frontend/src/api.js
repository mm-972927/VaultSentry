// api.js — All calls to the VaultSentry Java backend
const BASE = 'http://localhost:8080/api';

export const api = {
  getScans:     async ()           => fetchJson(`${BASE}/scans`),
  getScan:      async (id)         => fetchJson(`${BASE}/scan/${id}`),
  getStats:     async ()           => fetchJson(`${BASE}/stats`),
  deleteScan:   async (id)         => fetchJson(`${BASE}/scan/${id}`, { method: 'DELETE' }),
  submitScan:   async (scanName, targetPath, requestedBy) =>
    fetchJson(`${BASE}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scanName, targetPath, requestedBy }),
    }),
};

async function fetchJson(url, opts = {}) {
  const res = await fetch(url, opts);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}
