import React, { useState } from 'react';

function FindingItem({ f }) {
  const [open, setOpen] = useState(false);

  const categoryIcon = {
    SECRET_KEY:     '🔑',
    PASSWORD:       '🔐',
    PII:            '🪪',
    SENSITIVE_FILE: '📄',
    PRIVATE_KEY:    '🗝️',
    TOKEN:          '🎟️',
    DATABASE_URL:   '🗄️',
  };

  const categoryLabel = {
    SECRET_KEY:     'Secret Key',
    PASSWORD:       'Password',
    PII:            'PII',
    SENSITIVE_FILE: 'Sensitive File',
    PRIVATE_KEY:    'Private Key',
    TOKEN:          'Token',
    DATABASE_URL:   'Database URL',
  };

  const icon  = categoryIcon[f.category]  || '⚠️';
  const label = categoryLabel[f.category] || f.category;
  return (
    <div className="finding-item">
      <div className="finding-hd" onClick={() => setOpen(o => !o)}>
        <div className="finding-left">
          <span className="finding-rule">{icon} {f.ruleName}</span>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span className="finding-file">
              {f.filePath}{f.lineNumber > 0 ? `:${f.lineNumber}` : ''}
            </span>
            <span style={{ fontSize: 10, fontFamily: 'var(--mono)', color: 'var(--muted)',
              background: 'rgba(255,255,255,.03)', border: '1px solid var(--border)',
              padding: '1px 6px', borderRadius: 4 }}>
              {label}
            </span>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
          <span className={`risk risk-${f.severity}`}>{f.severity}</span>
          <span style={{ color: 'var(--muted)', fontSize: 11 }}>{open ? '▲' : '▼'}</span>
        </div>
      </div>
      {open && (
        <div className="finding-body">
          <div className="finding-matched">{f.matchedLine}</div>
          <div className="finding-desc">⚠️ {f.description}</div>
          <div className="finding-fix"><strong>Fix: </strong>{f.remediation}</div>
        </div>
      )}
    </div>
  );
}

export function DetailPanel({ scan }) {
  const [filter, setFilter] = useState('ALL');

  if (!scan) return (
    <div className="detail-panel">
      <div className="detail-empty">
        <div className="detail-empty-icon">🔐</div>
        <div style={{ fontSize: 12, color: 'var(--muted)' }}>Select a scan to view findings</div>
      </div>
    </div>
  );

  const findings = scan.findings || [];
  const visible  = filter === 'ALL' ? findings : findings.filter(f => f.severity === filter);

  return (
    <div className="detail-panel">
      {/* Header */}
      <div className="detail-head">
        <div className="detail-head-id">SCAN ID: {scan.id}</div>
        <div className="detail-head-name">{scan.scanName}</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className={`risk risk-${scan.riskLevel}`}>{scan.riskLevel}</span>
          <span className={`status status-${scan.status}`}>{scan.status}</span>
        </div>

        {/* Risk meter */}
        <div className="risk-meter">
          <div className="meter-label">Risk Score: {scan.riskScore}/100</div>
          <div className="meter-track">
            <div className={`meter-fill fill-${scan.riskLevel}`}
              style={{ width: `${scan.riskScore}%` }} />
          </div>
        </div>

        <div className="detail-meta-row">
          <span>👤 {scan.requestedBy}</span>
          <span>📄 {scan.filesScanned} scanned</span>
          <span>⏭ {scan.filesSkipped} skipped</span>
          <span>🕐 {scan.startedAt}</span>
        </div>

        {/* Severity filter */}
        <div style={{ display: 'flex', gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
            <button key={s} onClick={() => setFilter(s)}
              style={{
                padding: '2px 9px', borderRadius: 5, fontSize: 10,
                fontFamily: 'var(--mono)', cursor: 'pointer', border: '1px solid',
                borderColor: filter === s ? 'var(--blue)' : 'var(--border)',
                background: filter === s ? 'rgba(96,165,250,.1)' : 'transparent',
                color: filter === s ? 'var(--blue)' : 'var(--muted)',
              }}>
              {s} ({s === 'ALL' ? findings.length : findings.filter(f => f.severity === s).length})
            </button>
          ))}
        </div>
        {/* Category breakdown */}
        <div style={{ display: 'flex', gap: 6, marginTop: 6, flexWrap: 'wrap' }}>
          {[
            ['SENSITIVE_FILE', '📄 Files'],
            ['SECRET_KEY',     '🔑 Keys'],
            ['PASSWORD',       '🔐 Passwords'],
            ['TOKEN',          '🎟 Tokens'],
            ['PRIVATE_KEY',    '🗝 Private Keys'],
            ['PII',            '🪪 PII'],
            ['DATABASE_URL',   '🗄 DB URLs'],
          ].map(([cat, label]) => {
            const count = findings.filter(f => f.category === cat).length;
            if (count === 0) return null;
            return (
              <span key={cat} style={{
                fontSize: 10, fontFamily: 'var(--mono)',
                color: 'var(--text2)', background: 'rgba(255,255,255,.03)',
                border: '1px solid var(--border)', padding: '2px 8px', borderRadius: 4
              }}>
                {label}: {count}
              </span>
            );
          })}
        </div>
      </div>

      {/* Findings */}
      <div className="findings-list">
        {visible.length === 0 ? (
          <div className="findings-empty">
            {findings.length === 0 ? '✅ No secrets detected — clean scan!' : `No ${filter} findings`}
          </div>
        ) : (
          visible.map((f, i) => <FindingItem key={i} f={f} />)
        )}
      </div>
    </div>
  );
}
