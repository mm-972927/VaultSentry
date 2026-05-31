import React from 'react';

export function ScanCard({ scan, active, onClick, onDelete }) {
  const sc = scan.severityCounts || {};
  return (
    <div className={`scan-card risk-${scan.riskLevel} ${active ? 'active' : ''}`} onClick={onClick}>
      <div className="scan-card-top">
        <span className="scan-name">
          📁 {scan.scanName}
          <span className="scan-id">#{scan.id}</span>
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span className={`risk risk-${scan.riskLevel}`}>{scan.riskLevel}</span>
          <span className={`status status-${scan.status}`}>{scan.status}</span>
          <button className="btn btn-del" onClick={e => { e.stopPropagation(); onDelete(scan.id); }}>✕</button>
        </div>
      </div>

      <div className="scan-card-meta">
        <span className="meta">👤 {scan.requestedBy}</span>
        <span className="meta">📂 {scan.targetPath}</span>
        <span className="meta">🕐 {scan.startedAt}</span>
        <span className="meta">📄 {scan.filesScanned} files</span>
      </div>

      <div className="sev-row">
        {[['CRITICAL', sc.CRITICAL], ['HIGH', sc.HIGH], ['MEDIUM', sc.MEDIUM], ['LOW', sc.LOW]].map(([sev, count]) => (
          count > 0 && (
            <div key={sev} className="sev-chip">
              <div className={`sev-dot dot-${sev}`} />
              <span>{sev}: {count}</span>
            </div>
          )
        ))}
        {scan.totalFindings === 0 && scan.status === 'COMPLETED' && (
          <span style={{ fontSize: 11, color: 'var(--clean)', fontFamily: 'var(--mono)' }}>✓ No secrets found</span>
        )}
      </div>
    </div>
  );
}
