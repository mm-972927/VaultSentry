import React, { useState } from 'react';

const EXAMPLES = [
  { name: 'ecommerce-api',   path: '/home/projects/ecommerce-api',   by: 'alice' },
  { name: 'auth-service',    path: '/home/projects/auth-service',    by: 'bob' },
  { name: 'payment-gateway', path: '/home/projects/payment-gateway', by: 'charlie' },
];

export function SubmitForm({ onSubmit }) {
  const [name, setName]   = useState('');
  const [path, setPath]   = useState('');
  const [by, setBy]       = useState('');
  const [busy, setBusy]   = useState(false);

  const fill = (ex) => { setName(ex.name); setPath(ex.path); setBy(ex.by); };

  const run = async () => {
    if (!name || !path || !by) return;
    setBusy(true);
    try { await onSubmit(name, path, by); setName(''); setPath(''); setBy(''); }
    finally { setBusy(false); }
  };

  return (
    <div className="submit-box">
      <div className="submit-title">🔍 Submit New Scan</div>

      {/* Quick-fill example buttons */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 12 }}>
        <span style={{ fontSize: 10, color: 'var(--muted)', fontFamily: 'var(--mono)', alignSelf: 'center' }}>Quick fill:</span>
        {EXAMPLES.map(ex => (
          <button key={ex.name} className="btn" onClick={() => fill(ex)}
            style={{ padding: '3px 10px', fontSize: 11, background: 'var(--bg)', border: '1px solid var(--border)', color: 'var(--text2)', borderRadius: 5, cursor: 'pointer' }}>
            {ex.name}
          </button>
        ))}
      </div>

      <div className="submit-row">
        <div className="field">
          <label className="field-label">Scan Name</label>
          <input className="field-input" placeholder="e.g. user-service" value={name} onChange={e => setName(e.target.value)} />
        </div>
        <div className="field">
          <label className="field-label">Target Path</label>
          <input className="field-input" placeholder="/path/to/project" value={path} onChange={e => setPath(e.target.value)} />
        </div>
        <div className="field">
          <label className="field-label">Requested By</label>
          <input className="field-input" placeholder="your name" value={by} onChange={e => setBy(e.target.value)} />
        </div>
        <button className="btn btn-scan" onClick={run} disabled={busy || !name || !path || !by}>
          {busy ? '...' : '🔐 Scan'}
        </button>
      </div>
    </div>
  );
}
