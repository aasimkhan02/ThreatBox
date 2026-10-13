import React, { useState } from 'react';
import './analyze.css';

export default function AnalyzePage({ onNavigateHome, onOpenResult }) {
  const [activeNav, setActiveNav] = useState('Analyze');
  const [executionTime, setExecutionTime] = useState('5 min');
  const [networkMode, setNetworkMode] = useState('Simulated Internet');
  const [captureTraffic, setCaptureTraffic] = useState(true);
  const [collectFullTelemetry, setCollectFullTelemetry] = useState(true);
  const [enableScreenRecording, setEnableScreenRecording] = useState(false);
  const [useTorHoneypot, setUseTorHoneypot] = useState(false);
  const [stagedFile, setStagedFile] = useState({
    name: 'sample.exe',
    specs: 'PE32+ • 2.4 MB • SHA-256: a3f5...9d2e',
  });
  const [isDragOver, setIsDragOver] = useState(false);

  const navItems = [
    { id: 'Home', label: 'Home', icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>
        <polyline points="9 22 9 12 15 12 15 22"/>
      </svg>
    )},
    { id: 'Analyze', label: 'Analyze', icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polyline points="16 16 12 12 8 16"/>
        <line x1="12" y1="12" x2="12" y2="21"/>
        <path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/>
      </svg>
    )},
    { id: 'Dashboard', label: 'Dashboard', icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="3" y="3" width="7" height="9" rx="1"/>
        <rect x="14" y="3" width="7" height="5" rx="1"/>
        <rect x="14" y="12" width="7" height="9" rx="1"/>
        <rect x="3" y="16" width="7" height="5" rx="1"/>
      </svg>
    )},
    { id: 'History', label: 'History', icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10"/>
        <polyline points="12 6 12 12 16 14"/>
      </svg>
    )},
    { id: 'Features', label: 'Features', icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <polygon points="12 2 2 7 12 12 22 7 12 2"/>
        <polyline points="2 17 12 22 22 17"/>
        <polyline points="2 12 12 17 22 12"/>
      </svg>
    )},
    { id: 'Docs', label: 'Docs', icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/>
        <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>
      </svg>
    )},
  ];

  const recentAnalyses = [
    { name: 'sample.exe', tag: 'malicious', active: true },
    { name: 'invoice.pdf', tag: 'clean', active: false },
    { name: 'setup.exe', tag: 'suspicious', active: false },
    { name: 'update.dll', tag: 'clean', active: false },
    { name: 'game.exe', tag: 'suspicious', active: false },
  ];

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setStagedFile({
        name: file.name,
        specs: `${(file.size / (1024 * 1024)).toFixed(1)} MB • SHA-256: calculating...`
      });
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setStagedFile({
        name: file.name,
        specs: `${(file.size / (1024 * 1024)).toFixed(1)} MB • SHA-256: calculating...`
      });
    }
  };

  const handleAnalyzeClick = () => {
    if (onOpenResult) {
      onOpenResult();
    }
  };

  return (
    <div className="analyze-page-container">
      {/* SIDEBAR NAVIGATION (Matching exact structure) */}
      <aside className="sidebar">
        <div className="sidebar-top">
          {/* Brand Logo */}
          <div className="brand-section" onClick={onNavigateHome} style={{ cursor: 'pointer' }}>
            <svg className="brand-logo-icon" viewBox="0 0 32 32" fill="none" stroke="currentColor">
              <rect x="5" y="5" width="22" height="22" rx="4" stroke="#ff334b" strokeWidth="2.5"/>
              <path d="M11 11L21 21M21 11L11 21" stroke="#ff334b" strokeWidth="2.5" strokeLinecap="round"/>
            </svg>
            <span className="brand-title">THREATBOX</span>
          </div>

          {/* Primary Nav Menu with Dashboard / Result navigation */}
          <nav className="nav-menu">
            {navItems.map((item) => (
              <button
                key={item.id}
                className={`nav-item ${activeNav === item.id ? 'active' : ''}`}
                onClick={() => {
                  setActiveNav(item.id);
                  if (item.id === 'Home' && onNavigateHome) onNavigateHome();
                  if (item.id === 'Dashboard' && onOpenResult) onOpenResult();
                }}
              >
                <span className="nav-icon">{item.icon}</span>
                <span>{item.label}</span>
              </button>
            ))}
          </nav>

          {/* Recent Analyses List */}
          <div className="recent-section">
            <div className="recent-header">Recent Analyses</div>
            <div className="recent-list">
              {recentAnalyses.map((rec, i) => (
                <div
                  key={i}
                  className={`recent-item ${rec.active ? 'active' : ''}`}
                  onClick={() => onOpenResult && onOpenResult()}
                >
                  <div className="recent-item-left">
                    <svg className="recent-item-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>
                      <polyline points="13 2 13 9 20 9"/>
                    </svg>
                    <span className="recent-name">{rec.name}</span>
                  </div>
                  <span className={`tag-badge ${rec.tag}`}>{rec.tag}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Sidebar Footer */}
        <div className="sidebar-footer">
          <div className="sandbox-status-card">
            <span className="status-dot"></span>
            <div className="sandbox-status-text">
              <span className="status-title">Windows Sandbox</span>
              <span className="status-sub">Ready • Isolated • Safe</span>
            </div>
          </div>
          <a
            href="https://github.com/aasimkhan02/ThreatBox"
            target="_blank"
            rel="noreferrer"
            className="github-link"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
            </svg>
            <span>View on GitHub</span>
          </a>
        </div>
      </aside>

      {/* MAIN VIEWPORT WITH GLOW */}
      <main className="analyze-viewport">
        {/* Sticky Header Bar */}
        <header className="top-header">
          <div className="breadcrumbs">
            <span className="bc-link" onClick={onNavigateHome}>ThreatBox</span>
            <span className="bc-sep">&gt;</span>
            <span className="bc-current">Analyze Sample</span>
          </div>

          <div className="header-actions">
            <div className="search-bar">
              <svg className="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <input type="text" placeholder="Search by hash, filename..." />
              <span className="kbd-shortcut">Ctrl K</span>
            </div>

            <button className="icon-btn" title="Light / Dark mode">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="5"/>
                <line x1="12" y1="1" x2="12" y2="3"/>
                <line x1="12" y1="21" x2="12" y2="23"/>
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
                <line x1="1" y1="12" x2="3" y2="12"/>
                <line x1="21" y1="12" x2="23" y2="12"/>
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
              </svg>
            </button>

            <div className="user-avatar">A</div>
          </div>
        </header>

        {/* ANALYZE PAGE CONTENT */}
        <div className="analyze-content-wrap">
          {/* Header Row */}
          <div className="analyze-header-row">
            <div className="analyze-title-col">
              <div className="analyze-kicker-tag">
                <span className="kicker-dash"></span>
                <span>ANALYZE</span>
              </div>
              <h1 className="analyze-headline">
                Submit a file.<br />
                Uncover its behavior.
              </h1>
              <p className="analyze-subtext">
                Detonate suspicious files in an isolated Windows Sandbox environment and get detailed behavioral analysis with real evidence.
              </p>
            </div>

            {/* Side Motto */}
            <div className="side-motto-box">
              <div className="motto-line"></div>
              <div className="motto-text-group">
                <span className="motto-seq">01</span>
                <span className="motto-item">SAME FILE</span>
                <span className="motto-item">DIFFERENT BEHAVIOR</span>
                <span className="motto-item">REAL EVIDENCE</span>
              </div>
            </div>
          </div>

          {/* Main Grid: Dropzone (Left) + Options (Right) */}
          <div className="analyze-main-grid">
            {/* Left: Dropzone Area */}
            <div className="dropzone-outer-card">
              <input
                type="file"
                id="file-upload-input"
                style={{ display: 'none' }}
                onChange={handleFileUpload}
              />

              <div
                className={`dropzone-inner-box ${isDragOver ? 'is-dragover' : ''}`}
                onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
                onDragLeave={() => setIsDragOver(false)}
                onDrop={handleDrop}
                onClick={() => document.getElementById('file-upload-input').click()}
              >
                <div className="upload-cloud-icon-wrap">
                  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
                    <path d="M16 16l-4-4-4 4M12 12v9" strokeLinecap="round" strokeLinejoin="round"/>
                    <path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3" strokeLinecap="round" strokeLinejoin="round"/>
                  </svg>
                </div>
                <div className="dropzone-callout">
                  Drag &amp; drop a file here or <span className="browse-link">click to browse</span>
                </div>
                <div className="dropzone-sub-info">
                  Supports .exe, .dll, .sys and other Windows binaries (max 100MB)
                </div>
              </div>

              {/* Staged File Card & Analyze CTA */}
              {stagedFile && (
                <div className="staged-file-row">
                  <div className="staged-file-card">
                    <div className="staged-left-meta">
                      <svg className="staged-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>
                        <polyline points="13 2 13 9 20 9"/>
                      </svg>
                      <div className="staged-name-meta">
                        <span className="staged-filename">{stagedFile.name}</span>
                        <span className="staged-specs">{stagedFile.specs}</span>
                      </div>
                    </div>
                    <button
                      className="staged-remove-btn"
                      title="Clear sample"
                      onClick={() => setStagedFile(null)}
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <line x1="18" y1="6" x2="6" y2="18"/>
                        <line x1="6" y1="6" x2="18" y2="18"/>
                      </svg>
                    </button>
                  </div>

                  <button className="btn-analyze-execute" onClick={handleAnalyzeClick}>
                    <span>Analyze File</span>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <line x1="5" y1="12" x2="19" y2="12"/>
                      <polyline points="12 5 19 12 12 19"/>
                    </svg>
                  </button>
                </div>
              )}
            </div>

            {/* Right: Configuration Panels */}
            <div className="analyze-options-col">
              {/* Execution Time */}
              <div className="config-card">
                <div className="config-header-row">
                  <svg className="config-header-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="10"/>
                    <polyline points="12 6 12 12 16 14"/>
                  </svg>
                  <div className="config-title-wrap">
                    <span className="config-title">Execution Time</span>
                    <span className="config-desc">How long the sample will run in the sandbox.</span>
                  </div>
                </div>

                <div className="segmented-control">
                  {['2 min', '5 min', '15 min', 'Custom'].map((t) => (
                    <button
                      key={t}
                      className={`segment-btn ${executionTime === t ? 'active' : ''}`}
                      onClick={() => setExecutionTime(t)}
                    >
                      {t}
                    </button>
                  ))}
                </div>
              </div>

              {/* Network Mode */}
              <div className="config-card">
                <div className="config-header-row">
                  <svg className="config-header-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="18" cy="5" r="3"/>
                    <circle cx="6" cy="12" r="3"/>
                    <circle cx="18" cy="19" r="3"/>
                    <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
                    <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
                  </svg>
                  <div className="config-title-wrap">
                    <span className="config-title">Network Mode</span>
                    <span className="config-desc">Control the network environment.</span>
                  </div>
                </div>

                <div className="segmented-control">
                  {['Simulated Internet', 'Isolated (No Internet)', 'Tor Honeypot'].map((m) => (
                    <button
                      key={m}
                      className={`segment-btn ${networkMode === m ? 'active' : ''}`}
                      onClick={() => setNetworkMode(m)}
                    >
                      {m}
                    </button>
                  ))}
                </div>
              </div>

              {/* Additional Options */}
              <div className="config-card">
                <div className="config-header-row">
                  <svg className="config-header-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="12" cy="12" r="3"/>
                    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                  </svg>
                  <div className="config-title-wrap">
                    <span className="config-title">Additional Options</span>
                  </div>
                </div>

                <div className="checkbox-matrix">
                  <label className="custom-checkbox-row">
                    <input
                      type="checkbox"
                      checked={captureTraffic}
                      onChange={(e) => setCaptureTraffic(e.target.checked)}
                    />
                    <span>Capture network traffic</span>
                  </label>

                  <label className="custom-checkbox-row">
                    <input
                      type="checkbox"
                      checked={enableScreenRecording}
                      onChange={(e) => setEnableScreenRecording(e.target.checked)}
                    />
                    <span>Enable screen recording</span>
                  </label>

                  <label className="custom-checkbox-row">
                    <input
                      type="checkbox"
                      checked={collectFullTelemetry}
                      onChange={(e) => setCollectFullTelemetry(e.target.checked)}
                    />
                    <span>Collect full telemetry</span>
                    <svg className="info-tooltip-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10"/>
                      <line x1="12" y1="16" x2="12" y2="12"/>
                      <line x1="12" y1="8" x2="12.01" y2="8"/>
                    </svg>
                  </label>

                  <label className="custom-checkbox-row">
                    <input
                      type="checkbox"
                      checked={useTorHoneypot}
                      onChange={(e) => setUseTorHoneypot(e.target.checked)}
                    />
                    <span>Use Tor honeypot</span>
                    <svg className="info-tooltip-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10"/>
                      <line x1="12" y1="16" x2="12" y2="12"/>
                      <line x1="12" y1="8" x2="12.01" y2="8"/>
                    </svg>
                  </label>
                </div>
              </div>
            </div>
          </div>

          {/* Bottom Features Strip */}
          <div className="features-strip-card">
            <div className="feature-pill-item">
              <div className="feature-icon-box blue">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
                </svg>
              </div>
              <div className="feature-text-block">
                <span className="feature-headline">Isolated Execution</span>
                <span className="feature-description">Runs inside Windows Sandbox for maximum safety.</span>
              </div>
            </div>

            <div className="feature-pill-item">
              <div className="feature-icon-box cyan">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="20" x2="18" y2="10"/>
                  <line x1="12" y1="20" x2="12" y2="4"/>
                  <line x1="6" y1="20" x2="6" y2="14"/>
                </svg>
              </div>
              <div className="feature-text-block">
                <span className="feature-headline">Real-time Telemetry</span>
                <span className="feature-description">Process, file, registry, network and DNS activity.</span>
              </div>
            </div>

            <div className="feature-pill-item">
              <div className="feature-icon-box green">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                  <polyline points="9 12 11 14 15 10"/>
                </svg>
              </div>
              <div className="feature-text-block">
                <span className="feature-headline">MITRE ATT&amp;CK Mapping</span>
                <span className="feature-description">Maps observed behavior to known techniques.</span>
              </div>
            </div>

            <div className="feature-pill-item">
              <div className="feature-icon-box purple">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                  <polyline points="14 2 14 8 20 8"/>
                  <line x1="16" y1="13" x2="8" y2="13"/>
                  <line x1="16" y1="17" x2="8" y2="17"/>
                  <polyline points="10 9 9 9 8 9"/>
                </svg>
              </div>
              <div className="feature-text-block">
                <span className="feature-headline">Detailed Reports</span>
                <span className="feature-description">Clear, structured analysis with real forensic evidence.</span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
