import React, { useState } from 'react';
import './report.css';

export default function AnalysisReport({ onNavigateHome, onNavigateAnalyze }) {
  const [activeTab, setActiveTab] = useState('Overview');
  const [activeIocTab, setActiveIocTab] = useState('IPs');
  const [treeViewMode, setTreeViewMode] = useState('tree');
  const [activeNav, setActiveNav] = useState('Dashboard');

  // Static/Demo state modeled directly from ThreatBox backend analysis output
  const sampleData = {
    filename: 'sample.exe',
    sha256: 'a3f5e2c4...9d2e',
    sha256Full: 'a3f5e2c4b89f01ab92e079a4561234bc567890def123456789abcdef01234567',
    md5: '7f1d2a9e...4b1c',
    fileSize: '2.4 MB (2,516,992 bytes)',
    fileType: 'PE32+ (Windows Executable)',
    firstSeen: 'Oct 11, 2026, 14:32',
    runtime: '4 min 52 sec',
    score: 87,
    verdict: 'Malicious',
    verdictConfidence: 'High confidence of malicious behavior.'
  };

  const threatScoreBreakdown = [
    { label: 'Suspicious process activity', val: '+25', pct: 85 },
    { label: 'Registry persistence', val: '+20', pct: 68 },
    { label: 'Network communication', val: '+18', pct: 60 },
    { label: 'Suspicious file modifications', val: '+15', pct: 50 },
    { label: 'Evasion techniques', val: '+9', pct: 30 },
  ];

  const quickStats = [
    { icon: 'proc', label: 'Processes created', count: 12, color: 'cyan' },
    { icon: 'file', label: 'Files modified', count: 37, color: 'orange' },
    { icon: 'net', label: 'Network endpoints', count: 8, color: 'blue' },
    { icon: 'reg', label: 'Registry keys', count: 14, color: 'purple' },
    { icon: 'dns', label: 'DNS queries', count: 6, color: 'blue' },
    { icon: 'mod', label: 'Modules loaded', count: 21, color: 'purple' },
  ];

  const liveEvents = [
    { time: '14:32:18', type: 'Process Create', icon: 'proc', text: 'sample.exe (PID: 432)' },
    { time: '14:32:21', type: 'Registry Set', icon: 'reg', text: 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\sample' },
    { time: '14:32:25', type: 'Network Connect', icon: 'net', text: '185.199.110.133:443 (TCP)' },
    { time: '14:32:27', type: 'File Create', icon: 'file', text: 'C:\\Users\\...\\AppData\\Roaming\\sample.tmp' },
    { time: '14:32:31', type: 'DNS Query', icon: 'dns', text: 'api.telegram.org' },
    { time: '14:32:33', type: 'Process Create', icon: 'proc', text: 'cmd.exe (PID: 448)' },
    { time: '14:32:36', type: 'File Write', icon: 'file', text: 'C:\\Users\\...\\Documents\\encrypted.docx' },
    { time: '14:32:41', type: 'Network Connect', icon: 'net', text: '149.154.167.220:443 (TCP)' },
    { time: '14:32:44', type: 'Registry Set', icon: 'reg', text: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\sample' },
    { time: '14:32:47', type: 'Process Exit', icon: 'proc', text: 'cmd.exe (PID: 448)' },
  ];

  const mitreTechniques = [
    {
      id: 'T1059.001',
      name: 'Command and Scripting Interpreter',
      tactic: 'Execution',
      tacticClass: 'execution',
      color: 'red'
    },
    {
      id: 'T1547.001',
      name: 'Registry Run Keys / Startup Folder',
      tactic: 'Persistence',
      tacticClass: 'persistence',
      color: 'orange'
    },
    {
      id: 'T1071.001',
      name: 'Application Layer Protocol',
      tactic: 'Command & Control',
      tacticClass: 'c2',
      color: 'blue'
    },
    {
      id: 'T1027',
      name: 'Obfuscated Files or Information',
      tactic: 'Defense Evasion',
      tacticClass: 'defense',
      color: 'purple'
    }
  ];

  const iocData = {
    IPs: [
      { endpoint: '185.199.110.133', port: 443, protocol: 'TCP', rep: 'Suspicious' },
      { endpoint: '149.154.167.220', port: 443, protocol: 'TCP', rep: 'Suspicious' },
      { endpoint: '8.8.8.8', port: 53, protocol: 'UDP', rep: 'Benign' },
    ],
    Domains: [
      { endpoint: 'api.telegram.org', port: 443, protocol: 'HTTPS', rep: 'Suspicious' },
      { endpoint: 'dns.google', port: 53, protocol: 'DoH', rep: 'Benign' },
    ],
    Files: [
      { endpoint: 'sample.tmp', port: 'AppData', protocol: 'CREATE', rep: 'Suspicious' },
      { endpoint: 'encrypted.docx', port: 'Documents', protocol: 'WRITE', rep: 'Suspicious' },
    ],
    Registry: [
      { endpoint: '...\\CurrentVersion\\Run\\sample', port: 'HKCU', protocol: 'SET_VALUE', rep: 'Suspicious' },
    ]
  };

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

  const tabs = [
    'Overview',
    'Behavior',
    'Process Tree',
    'File Activity',
    'Network',
    'Registry',
    'DNS',
    'Modules',
    'MITRE ATT&CK',
    'Raw Data'
  ];

  return (
    <div className="report-dashboard-container">
      {/* SIDEBAR NAVIGATION */}
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

          {/* Primary Nav Menu */}
          <nav className="nav-menu">
            {navItems.map((item) => (
              <button
                key={item.id}
                className={`nav-item ${activeNav === item.id ? 'active' : ''}`}
                onClick={() => {
                  setActiveNav(item.id);
                  if (item.id === 'Home' && onNavigateHome) onNavigateHome();
                  if (item.id === 'Analyze' && onNavigateAnalyze) onNavigateAnalyze();
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
                <div key={i} className={`recent-item ${rec.active ? 'active' : ''}`}>
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

      {/* MAIN VIEWPORT */}
      <main className="main-viewport">
        {/* Sticky Header Bar */}
        <header className="top-header">
          <div className="breadcrumbs">
            <span className="bc-link" onClick={onNavigateHome}>History</span>
            <span className="bc-sep">&gt;</span>
            <span className="bc-link">{sampleData.filename}</span>
            <span className="bc-sep">&gt;</span>
            <span className="bc-current">Analysis Report</span>
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

            <button className="icon-btn" title="Toggle theme">
              <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
              </svg>
            </button>

            <div className="user-avatar">A</div>
          </div>
        </header>

        {/* REPORT CONTENT BODY */}
        <div className="report-content">
          {/* SAMPLE HERO BANNER */}
          <div className="sample-banner">
            <div className="sample-meta-left">
              <div className="sample-file-icon-box">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/>
                  <polyline points="13 2 13 9 20 9"/>
                </svg>
              </div>

              <div className="sample-titles">
                <div className="sample-name-row">
                  <h1 className="sample-name-title">{sampleData.filename}</h1>
                  <span className="tag-badge malicious">Malicious</span>
                </div>

                <div className="sample-specs-row">
                  <span className="hash-snippet" title={sampleData.sha256Full}>
                    {sampleData.sha256}
                    <svg className="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                    </svg>
                  </span>
                  <span className="spec-pill">PE32+</span>
                  <span className="spec-pill">2.4 MB</span>
                  <span className="spec-pill">Analyzed on {sampleData.firstSeen}</span>
                  <span className="runtime-badge">
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="12" r="10"/>
                      <polyline points="12 6 12 12 16 14"/>
                    </svg>
                    Runtime: 5 min
                  </span>
                </div>
              </div>
            </div>

            <div className="sample-actions-right">
              <button className="action-btn-outline">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="1 4 1 10 7 10"/>
                  <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"/>
                </svg>
                <span>Re-analyze</span>
              </button>
              <button className="action-btn-outline">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
                  <polyline points="7 10 12 15 17 10"/>
                  <line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                <span>Download Report</span>
              </button>
              <button className="action-btn-outline">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="18" cy="5" r="3"/>
                  <circle cx="6" cy="12" r="3"/>
                  <circle cx="18" cy="19" r="3"/>
                  <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
                  <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
                </svg>
              </button>
              <button className="action-btn-outline">
                <span>•••</span>
              </button>
            </div>
          </div>

          {/* TAB NAVIGATION */}
          <nav className="tabs-navigation-bar">
            {tabs.map((tab) => (
              <button
                key={tab}
                className={`tab-nav-btn ${activeTab === tab ? 'active' : ''}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab}
              </button>
            ))}
          </nav>

          {/* ROW 1: SCORE & BREAKDOWN | SAMPLE INFO | QUICK STATS */}
          <div className="report-row-top">
            {/* Score Card + Breakdown */}
            <div className="tactical-card score-card">
              <div className="score-dial-wrap">
                <div className="gauge-relative-box">
                  <svg className="gauge-svg" viewBox="0 0 180 140">
                    {/* Background Track arc */}
                    <path
                      d="M 30 115 A 60 60 0 1 1 150 115"
                      fill="none"
                      stroke="#1e2433"
                      strokeWidth="14"
                      strokeLinecap="round"
                    />
                    {/* Gauge Value arc */}
                    <path
                      d="M 30 115 A 60 60 0 1 1 150 115"
                      fill="none"
                      stroke="#ff334b"
                      strokeWidth="14"
                      strokeDasharray="260"
                      strokeDashoffset="35"
                      strokeLinecap="round"
                    />
                  </svg>
                  <div className="gauge-center-text">
                    <span className="score-number">{sampleData.score}</span>
                    <span className="score-scale">/100</span>
                  </div>
                </div>
                <div className="verdict-text-label">{sampleData.verdict}</div>
                <div className="verdict-subtext">{sampleData.verdictConfidence}</div>
              </div>

              <div className="score-breakdown-panel">
                <div className="breakdown-title">Threat Score Breakdown</div>
                {threatScoreBreakdown.map((item, idx) => (
                  <div key={idx} className="breakdown-item">
                    <span className="breakdown-label">{item.label}</span>
                    <span className="breakdown-val">{item.val}</span>
                    <div className="breakdown-bar-bg">
                      <div className="breakdown-bar-fill" style={{ width: `${item.pct}%` }}></div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Sample Information Card */}
            <div className="tactical-card info-card">
              <div className="card-title">Sample Information</div>
              <div className="info-grid">
                <div className="info-row">
                  <span className="info-label">Filename</span>
                  <span className="info-val">{sampleData.filename}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">SHA-256</span>
                  <span className="info-val mono">
                    {sampleData.sha256}
                    <svg className="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                    </svg>
                  </span>
                </div>
                <div className="info-row">
                  <span className="info-label">MD5</span>
                  <span className="info-val mono">
                    {sampleData.md5}
                    <svg className="copy-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                      <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                    </svg>
                  </span>
                </div>
                <div className="info-row">
                  <span className="info-label">File size</span>
                  <span className="info-val">{sampleData.fileSize}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">File type</span>
                  <span className="info-val">{sampleData.fileType}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">First seen</span>
                  <span className="info-val">{sampleData.firstSeen}</span>
                </div>
                <div className="info-row">
                  <span className="info-label">Analysis duration</span>
                  <span className="info-val">{sampleData.runtime}</span>
                </div>
              </div>
            </div>

            {/* Quick Stats Card */}
            <div className="tactical-card stats-card">
              <div className="card-title">Quick Stats</div>
              <div className="stats-grid">
                {quickStats.map((stat, i) => (
                  <div key={i} className="stat-metric-box">
                    <svg className={`stat-icon ${stat.color}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      {stat.icon === 'proc' && (
                        <>
                          <circle cx="12" cy="12" r="3"/>
                          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                        </>
                      )}
                      {stat.icon === 'file' && (
                        <>
                          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                          <polyline points="14 2 14 8 20 8"/>
                        </>
                      )}
                      {stat.icon === 'net' && (
                        <>
                          <circle cx="18" cy="5" r="3"/>
                          <circle cx="6" cy="12" r="3"/>
                          <circle cx="18" cy="19" r="3"/>
                          <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/>
                          <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
                        </>
                      )}
                      {stat.icon === 'reg' && (
                        <>
                          <polygon points="12 2 2 7 12 12 22 7 12 2"/>
                          <polyline points="2 17 12 22 22 17"/>
                          <polyline points="2 12 12 17 22 12"/>
                        </>
                      )}
                      {stat.icon === 'dns' && (
                        <>
                          <circle cx="12" cy="12" r="10"/>
                          <line x1="2" y1="12" x2="22" y2="12"/>
                          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
                        </>
                      )}
                      {stat.icon === 'mod' && (
                        <>
                          <rect x="2" y="2" width="20" height="8" rx="2" ry="2"/>
                          <rect x="2" y="14" width="20" height="8" rx="2" ry="2"/>
                          <line x1="6" y1="6" x2="6.01" y2="6"/>
                          <line x1="6" y1="18" x2="6.01" y2="18"/>
                        </>
                      )}
                    </svg>
                    <div className="stat-content">
                      <span className="stat-number">{stat.count}</span>
                      <span className="stat-label">{stat.label}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ROW 2: TIMELINE & LIVE EVENTS | PROCESS TREE */}
          <div className="report-row-mid">
            {/* Behavior Timeline & Live Events */}
            <div className="tactical-card timeline-card">
              <div className="card-title">Behavior Timeline</div>
              
              {/* Stepper bar */}
              <div className="stepper-track-wrap">
                <div className="stepper-line"></div>
                <div className="stepper-line-active"></div>
                <div className="stepper-steps">
                  <div className="stepper-node">
                    <span className="step-dot c-red"></span>
                    <span className="step-name">Sandbox Setup</span>
                    <span className="step-time">12s</span>
                  </div>
                  <div className="stepper-node">
                    <span className="step-dot c-orange"></span>
                    <span className="step-name">Sample Execution</span>
                    <span className="step-time">2m 14s</span>
                  </div>
                  <div className="stepper-node">
                    <span className="step-dot c-purple"></span>
                    <span className="step-name">Data Collection</span>
                    <span className="step-time">1m 53s</span>
                  </div>
                  <div className="stepper-node">
                    <span className="step-dot c-purple"></span>
                    <span className="step-name">Analysis &amp; Scoring</span>
                    <span className="step-time">45s</span>
                  </div>
                  <div className="stepper-node">
                    <span className="step-dot c-green"></span>
                    <span className="step-name">Completed</span>
                    <span className="step-time">4m 52s</span>
                  </div>
                </div>
              </div>

              {/* Live Events Log */}
              <div className="events-section-header">
                <span className="events-title">Live Events (first 10)</span>
                <button className="events-view-all">View All →</button>
              </div>

              <div className="live-events-table">
                {liveEvents.map((evt, idx) => (
                  <div key={idx} className="event-row">
                    <span className="event-timestamp">{evt.time}</span>
                    <div className={`event-badge-group ${
                      evt.icon === 'proc' ? 'type-process' :
                      evt.icon === 'reg' ? 'type-registry' :
                      evt.icon === 'net' ? 'type-network' :
                      evt.icon === 'file' ? 'type-file' : 'type-dns'
                    }`}>
                      <svg className="event-badge-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        {evt.icon === 'proc' && <polygon points="5 3 19 12 5 21 5 3"/>}
                        {evt.icon === 'reg' && <polygon points="12 2 2 7 12 12 22 7 12 2"/>}
                        {evt.icon === 'net' && <circle cx="12" cy="12" r="10"/>}
                        {evt.icon === 'file' && <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>}
                        {evt.icon === 'dns' && <circle cx="12" cy="12" r="4"/>}
                      </svg>
                      <span>{evt.type}</span>
                    </div>
                    <span className="event-details">{evt.text}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Process Tree */}
            <div className="tactical-card process-tree-card">
              <div className="tree-header-row">
                <div className="card-title">Process Tree</div>
                <div className="toggle-switch-pills">
                  <button
                    className={`pill-toggle-btn ${treeViewMode === 'tree' ? 'active' : ''}`}
                    onClick={() => setTreeViewMode('tree')}
                  >
                    Tree
                  </button>
                  <button
                    className={`pill-toggle-btn ${treeViewMode === 'table' ? 'active' : ''}`}
                    onClick={() => setTreeViewMode('table')}
                  >
                    Table
                  </button>
                </div>
              </div>

              <div className="process-tree-viewport">
                <div className="tree-branch">
                  {/* Root System node */}
                  <div className="tree-node">
                    <span className="tree-node-line">⌄ </span>
                    <svg className="tree-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                      <line x1="8" y1="21" x2="16" y2="21"/>
                      <line x1="12" y1="17" x2="12" y2="21"/>
                    </svg>
                    <span className="tree-node-title">System (PID 4)</span>
                  </div>

                  {/* Explorer parent */}
                  <div className="tree-node" style={{ paddingLeft: '20px' }}>
                    <span className="tree-node-line">↳ </span>
                    <svg className="tree-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
                    </svg>
                    <span className="tree-node-title">explorer.exe (PID 312)</span>
                  </div>

                  {/* Target Sample */}
                  <div className="tree-node" style={{ paddingLeft: '40px' }}>
                    <span className="tree-node-line">↳ </span>
                    <svg className="tree-icon" viewBox="0 0 24 24" fill="none" stroke="#ff334b" strokeWidth="2">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                      <polyline points="14 2 14 8 20 8"/>
                    </svg>
                    <span className="tree-node-title malicious-node">sample.exe (PID 432)</span>
                    <span className="tag-badge malicious" style={{ marginLeft: '6px' }}>Malicious</span>
                  </div>

                  {/* Child CMD */}
                  <div className="tree-node" style={{ paddingLeft: '60px' }}>
                    <span className="tree-node-line">↳ </span>
                    <svg className="tree-icon" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" strokeWidth="2">
                      <polyline points="4 17 10 11 4 5"/>
                      <line x1="12" y1="19" x2="20" y2="19"/>
                    </svg>
                    <span className="tree-node-title child-node">cmd.exe (PID 448)</span>
                  </div>

                  {/* Powershell & Rundll32 under CMD */}
                  <div className="tree-node" style={{ paddingLeft: '80px' }}>
                    <span className="tree-node-line">↳ </span>
                    <svg className="tree-icon" viewBox="0 0 24 24" fill="none" stroke="#34d399" strokeWidth="2">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    </svg>
                    <span className="tree-node-title leaf-node">powershell.exe (PID 612)</span>
                  </div>

                  <div className="tree-node" style={{ paddingLeft: '80px' }}>
                    <span className="tree-node-line">↳ </span>
                    <svg className="tree-icon" viewBox="0 0 24 24" fill="none" stroke="#34d399" strokeWidth="2">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    </svg>
                    <span className="tree-node-title leaf-node">rundll32.exe (PID 736)</span>
                  </div>

                  {/* Reg.exe */}
                  <div className="tree-node" style={{ paddingLeft: '60px' }}>
                    <span className="tree-node-line">↳ </span>
                    <svg className="tree-icon" viewBox="0 0 24 24" fill="none" stroke="#34d399" strokeWidth="2">
                      <polygon points="12 2 2 7 12 12 22 7 12 2"/>
                    </svg>
                    <span className="tree-node-title leaf-node">reg.exe (PID 520)</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* ROW 3: MITRE ATT&CK TECHNIQUES | DETECTED IOCS */}
          <div className="report-row-bottom">
            {/* MITRE ATT&CK Techniques */}
            <div className="tactical-card mitre-card">
              <div className="mitre-header-row">
                <div className="card-title">MITRE ATT&amp;CK Techniques</div>
                <button className="matrix-view-link">View in Matrix →</button>
              </div>

              <div className="mitre-grid">
                {mitreTechniques.map((tech) => (
                  <div key={tech.id} className="technique-box">
                    <span className={`tech-id ${tech.color}`}>{tech.id}</span>
                    <span className="tech-name">{tech.name}</span>
                    <span className={`tactic-tag ${tech.tacticClass}`}>{tech.tactic}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Detected IOCs */}
            <div className="tactical-card iocs-card">
              <div className="iocs-header-row">
                <div className="card-title">Detected IOCs</div>
                <div className="ioc-pills-filter">
                  {['IPs', 'Domains', 'Files', 'Registry'].map((f) => (
                    <button
                      key={f}
                      className={`ioc-filter-btn ${activeIocTab === f ? 'active' : ''}`}
                      onClick={() => setActiveIocTab(f)}
                    >
                      {f}
                    </button>
                  ))}
                </div>
              </div>

              <div className="iocs-table-wrap">
                <table className="iocs-table">
                  <thead>
                    <tr>
                      <th>
                        {activeIocTab === 'IPs' ? 'IP Address' :
                         activeIocTab === 'Domains' ? 'Domain Name' :
                         activeIocTab === 'Files' ? 'File Name' : 'Registry Path'}
                      </th>
                      <th>{activeIocTab === 'Files' ? 'Location' : 'Port'}</th>
                      <th>{activeIocTab === 'Files' ? 'Action' : 'Protocol'}</th>
                      <th>Reputation</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(iocData[activeIocTab] || []).map((row, i) => (
                      <tr key={i}>
                        <td className="mono">{row.endpoint}</td>
                        <td className="mono">{row.port}</td>
                        <td className="mono">{row.protocol}</td>
                        <td>
                          <span className={`rep-tag ${row.rep.toLowerCase()}`}>{row.rep}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
