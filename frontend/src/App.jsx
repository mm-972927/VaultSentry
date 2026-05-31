import React, { useState } from 'react';
import './styles/App.css';
import { useScans } from './hooks/useScans';
import { StatsBar } from './components/StatsBar';
import { SubmitForm } from './components/SubmitForm';
import { ScanCard } from './components/ScanCard';
import { DetailPanel } from './components/DetailPanel';

export default function App() {
  const { scans, stats, loading, error, submitScan, deleteScan } = useScans();
  const [selectedId, setSelectedId] = useState(null);
  const selected = scans.find(s => s.id === selectedId) || null;

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">🔐</div>
          <div>
            <div className="brand-name">VAULT SENTRY</div>
            <div className="brand-tag">Secret & Sensitive File Detection Engine</div>
          </div>
        </div>
        <div className="topbar-right">
          <span className="pill pill-rules">⚙ {stats.rulesActive || '60+'} rules active</span>
          <span className="pill pill-live"><span className="pulse" /> LIVE</span>
        </div>
      </header>

      <main className="main">
        {error && (
          <div className="error-bar">
            ⚠️ Cannot reach Java backend at localhost:8080 —
            run: <code>chmod +x run-backend.sh && ./run-backend.sh</code>
          </div>
        )}

        <StatsBar stats={stats} />
        <SubmitForm onSubmit={submitScan} />

        <div className="grid">
          <div>
            <div className="section-hd">
              <span className="section-title">Scan Results ({scans.length})</span>
            </div>
            {loading && scans.length === 0 ? (
              <div className="loading"><span className="spin" />Connecting to Java backend...</div>
            ) : scans.length === 0 ? (
              <div className="loading">No scans yet — submit a path above to start.</div>
            ) : (
              <div className="scan-list">
                {scans.map(s => (
                  <ScanCard key={s.id} scan={s}
                    active={s.id === selectedId}
                    onClick={() => setSelectedId(s.id === selectedId ? null : s.id)}
                    onDelete={deleteScan}
                  />
                ))}
              </div>
            )}
          </div>

          <div>
            <div className="section-hd">
              <span className="section-title">Findings & Details</span>
            </div>
            <DetailPanel scan={selected} />
          </div>
        </div>
      </main>
    </div>
  );
}
