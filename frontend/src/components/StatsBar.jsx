// StatsBar.jsx
import React from 'react';

export function StatsBar({ stats }) {
  const items = [
    { key: 'totalScans',    label: 'Total Scans',    cls: 'scans' },
    { key: 'clean',         label: 'Clean',          cls: 'clean' },
    { key: 'critical',      label: 'Critical Risk',  cls: 'crit' },
    { key: 'scanning',      label: 'Scanning',       cls: 'active' },
    { key: 'totalFindings', label: 'Total Findings', cls: 'finds' },
    { key: 'rulesActive',   label: 'Rules Active',   cls: 'rules' },
  ];
  return (
    <div className="stats-row">
      {items.map(({ key, label, cls }) => (
        <div key={key} className={`stat ${cls}`}>
          <div className="stat-l">{label}</div>
          <div className="stat-v">{stats[key] ?? 0}</div>
        </div>
      ))}
    </div>
  );
}
