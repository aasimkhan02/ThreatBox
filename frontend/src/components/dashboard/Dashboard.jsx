import React, { useState } from 'react'
import './dashboard.css'
import Sidebar from '../layout/Sidebar'

const Dashboard = ({
  sampleData,
  onNavigateHome,
  onNavigateUpload,
  onNavigateTab
}) => {
  const [activeTab, setActiveTab] = useState('Overview')
  const [searchQuery, setSearchQuery] = useState('')

  // Default mock sample matching screenshot exactly
  const sample = sampleData || {
    fileName: 'sample_malware.exe',
    status: 'Malicious',
    sha256: '37a8e5c6b0d3e9f72ca9d6e1f78b3c4d56e7f906a1b2c3d4e5f6a7b8c9d0e1f2',
    fileType: 'PE32+ (EXE)',
    fileSize: '412 KB',
    analysisTime: '2m 34s',
    submitted: 'Oct 11, 2026, 14:22',
    environment: 'Windows Sandbox'
  }

  const tabs = [
    'Overview',
    'Behavior',
    'Processes',
    'File System',
    'Network',
    'DNS',
    'Modules',
    'MITRE ATT&CK',
    'IOCs',
    'Raw Events'
  ]

  // Circular Gauge Math for score 92/100 (Semi-circle or ~240deg arc)
  // Radius = 54, circumference of 180-deg arc = PI * 54 = ~169.6
  const score = 92
  const arcLength = 170
  const strokeDashoffset = arcLength - (score / 100) * arcLength

  return (
    <div className="dashboard-layout">
      {/* ---------------- 1. Sidebar Component ---------------- */}
      <Sidebar
        activeTab="analyses"
        onNavigate={(tab) => {
          if (tab === 'new-analysis') onNavigateUpload && onNavigateUpload()
          else if (onNavigateTab) onNavigateTab(tab)
        }}
        onNavigateHome={onNavigateHome}
      />

      {/* ---------------- 2. Main Dashboard Area ---------------- */}
      <div className="dashboard-main-view">
        {/* Top Navbar: Breadcrumbs + Search + Avatar */}
        <header className="dashboard-header-bar">
          <div className="dashboard-breadcrumbs">
            <button
              type="button"
              className="breadcrumb-link"
              onClick={onNavigateUpload}
            >
              Analyses
            </button>
            <span className="breadcrumb-separator">&gt;</span>
            <span className="breadcrumb-current">{sample.fileName}</span>
          </div>

          <div className="dashboard-header-right">
            <div className="search-input-wrapper">
              <span className="search-icon">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="11" cy="11" r="8" />
                  <line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
              </span>
              <input
                type="text"
                placeholder="Search analyses..."
                className="search-analyses-input"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            <div className="user-avatar-circle" title="User Profile">
              <span>M</span>
            </div>
          </div>
        </header>

        {/* Dashboard Main Content Body */}
        <main className="dashboard-body">
          {/* Sample Hero Header */}
          <section className="sample-hero-header">
            <div className="sample-title-group">
              <div className="sample-main-file-icon">
                <svg width="40" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                  <polyline points="14 2 14 8 20 8" />
                </svg>
              </div>

              <div className="sample-heading-col">
                <div className="sample-title-row">
                  <h1 className="sample-file-name">{sample.fileName}</h1>
                  <span className="badge-malicious-pill">{sample.status}</span>
                </div>
                <p className="sample-sha256">{sample.sha256}</p>
              </div>
            </div>

            <div className="sample-actions-group">
              <button type="button" className="btn-download-report">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                  <polyline points="7 10 12 15 17 10" />
                  <line x1="12" y1="15" x2="12" y2="3" />
                </svg>
                <span>Download Report</span>
              </button>

              <button type="button" className="btn-more-options" title="More Options">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
                  <circle cx="12" cy="12" r="1.5" />
                  <circle cx="6" cy="12" r="1.5" />
                  <circle cx="18" cy="12" r="1.5" />
                </svg>
              </button>
            </div>
          </section>

          {/* Sample Metadata Horizontal Strip */}
          <section className="sample-specs-strip">
            <div className="spec-cell">
              <span className="spec-cell-label">File Type</span>
              <span className="spec-cell-val">{sample.fileType}</span>
            </div>

            <div className="spec-cell">
              <span className="spec-cell-label">File Size</span>
              <span className="spec-cell-val">{sample.fileSize}</span>
            </div>

            <div className="spec-cell">
              <span className="spec-cell-label">Analysis Time</span>
              <span className="spec-cell-val">{sample.analysisTime}</span>
            </div>

            <div className="spec-cell">
              <span className="spec-cell-label">Submitted</span>
              <span className="spec-cell-val">{sample.submitted}</span>
            </div>

            <div className="spec-cell">
              <span className="spec-cell-label">Environment</span>
              <span className="spec-cell-val">
                <span className="win-icon">
                  <svg width="16" height="16" viewBox="0 0 88 88" fill="currentColor">
                    <path d="M0 12.402l35.689-4.86v35.031H0V12.402zm0 37.375h35.689v35.056L0 79.972V49.777zm40.548-35.702L87.994 0v42.573H40.548V14.075zm47.446 35.702L40.548 49.777v28.513l47.446 6.643V49.777z"/>
                  </svg>
                </span>
                <span>{sample.environment}</span>
              </span>
            </div>
          </section>

          {/* Navigation Tabs Bar */}
          <nav className="dashboard-tabs-bar">
            {tabs.map((tab) => (
              <button
                key={tab}
                type="button"
                className={`dash-tab-btn ${activeTab === tab ? 'active' : ''}`}
                onClick={() => setActiveTab(tab)}
              >
                {tab}
              </button>
            ))}
          </nav>

          {/* ===================== OVERVIEW TAB CONTENT ===================== */}
          {activeTab === 'Overview' && (
            <>
              {/* Row 1: Threat Score | Key Findings | Sample Classification */}
              <div className="overview-top-grid">
                {/* 1. Threat Score Gauge */}
                <div className="dashboard-card">
                  <div className="card-header-row">
                    <span className="card-title-text">
                      <span>Threat Score</span>
                      <span className="card-info-icon" title="Aggregated risk score">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="10" />
                          <line x1="12" y1="16" x2="12" y2="12" />
                          <line x1="12" y1="8" x2="12.01" y2="8" />
                        </svg>
                      </span>
                    </span>
                  </div>

                  <div className="threat-score-content">
                    {/* Semi-circular Gauge Arc */}
                    <div className="gauge-svg-wrapper">
                      <svg width="140" height="90" viewBox="0 0 140 90">
                        {/* Background track arc */}
                        <path
                          d="M 16 80 A 54 54 0 0 1 124 80"
                          fill="none"
                          stroke="#EAEAEA"
                          strokeWidth="10"
                          strokeLinecap="round"
                        />
                        {/* Red fill arc */}
                        <path
                          d="M 16 80 A 54 54 0 0 1 124 80"
                          fill="none"
                          stroke="#FF1744"
                          strokeWidth="10"
                          strokeLinecap="round"
                          strokeDasharray={arcLength}
                          strokeDashoffset={strokeDashoffset}
                        />
                      </svg>

                      <div className="gauge-center-text">
                        <span className="gauge-score-number">{score}</span>
                        <span className="gauge-score-max">/ 100</span>
                      </div>
                    </div>

                    {/* Legend */}
                    <div className="gauge-legend-list">
                      <div className="legend-item">
                        <span className="legend-dot dot-malicious"></span>
                        <span>Malicious</span>
                      </div>
                      <div className="legend-item">
                        <span className="legend-dot dot-suspicious"></span>
                        <span>Suspicious</span>
                      </div>
                      <div className="legend-item">
                        <span className="legend-dot dot-lowrisk"></span>
                        <span>Low Risk</span>
                      </div>
                      <div className="legend-item">
                        <span className="legend-dot dot-clean"></span>
                        <span>Clean</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 2. Key Findings */}
                <div className="dashboard-card">
                  <div className="card-header-row">
                    <span className="card-title-text">Key Findings</span>
                  </div>

                  <div className="findings-list">
                    <div className="finding-row">
                      <div className="finding-left">
                        <span className="finding-icon-wrap icon-red">
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <rect x="3" y="3" width="18" height="18" rx="2" />
                            <circle cx="8.5" cy="8.5" r="1.5" />
                            <polyline points="21 15 16 10 5 21" />
                          </svg>
                        </span>
                        <span className="finding-count">5</span>
                      </div>
                      <span className="finding-label">Malicious indicators</span>
                    </div>

                    <div className="finding-row">
                      <div className="finding-left">
                        <span className="finding-icon-wrap icon-amber">
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                            <line x1="12" y1="9" x2="12" y2="13" />
                            <line x1="12" y1="17" x2="12.01" y2="17" />
                          </svg>
                        </span>
                        <span className="finding-count">3</span>
                      </div>
                      <span className="finding-label">Suspicious behaviors</span>
                    </div>

                    <div className="finding-row">
                      <div className="finding-left">
                        <span className="finding-icon-wrap icon-slate">
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="12" cy="12" r="10" />
                            <line x1="12" y1="16" x2="12" y2="12" />
                            <line x1="12" y1="8" x2="12.01" y2="8" />
                          </svg>
                        </span>
                        <span className="finding-count">2</span>
                      </div>
                      <span className="finding-label">Low risk indicators</span>
                    </div>

                    <div className="finding-row">
                      <div className="finding-left">
                        <span className="finding-icon-wrap icon-dark">
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                          </svg>
                        </span>
                        <span className="finding-count">12</span>
                      </div>
                      <span className="finding-label">Total detections</span>
                    </div>
                  </div>
                </div>

                {/* 3. Sample Classification */}
                <div className="dashboard-card">
                  <div className="card-header-row">
                    <span className="card-title-text">Sample Classification</span>
                  </div>

                  <div className="classification-table">
                    <div className="class-row">
                      <span className="class-label">Family</span>
                      <span className="class-value">Generic.Malware</span>
                    </div>

                    <div className="class-row">
                      <span className="class-label">Type</span>
                      <span className="class-value">Trojan / Downloader</span>
                    </div>

                    <div className="class-row">
                      <span className="class-label">Capabilities</span>
                      <div className="capabilities-pill-group">
                        <span className="cap-badge cap-persistence">Persistence</span>
                        <span className="cap-badge cap-network">Network</span>
                        <span className="cap-badge cap-files">File Operations</span>
                      </div>
                    </div>

                    <div className="class-row">
                      <span className="class-label">Confidence</span>
                      <span className="badge-confidence-high">High</span>
                    </div>

                    <div className="class-row">
                      <span className="class-label">First Seen</span>
                      <span className="class-value">Oct 11, 2026</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Row 2: Behavior Summary | MITRE ATT&CK Techniques */}
              <div className="overview-mid-grid">
                {/* Behavior Summary */}
                <div className="dashboard-card">
                  <div className="card-title-with-desc">
                    <span className="card-icon-lead">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                        <line x1="16" y1="13" x2="8" y2="13" />
                        <line x1="16" y1="17" x2="8" y2="17" />
                        <polyline points="10 9 9 9 8 9" />
                      </svg>
                    </span>
                    <div className="title-desc-wrap">
                      <span className="card-title-text">Behavior Summary</span>
                      <span className="card-desc-sub">High-level overview of observed behavior during execution.</span>
                    </div>
                  </div>

                  <div className="behavior-metric-boxes">
                    <div className="metric-mini-box box-soft-pink">
                      <span className="metric-mini-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="3" />
                          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                        </svg>
                      </span>
                      <span className="metric-mini-num">37</span>
                      <span className="metric-mini-label">Processes Created</span>
                    </div>

                    <div className="metric-mini-box">
                      <span className="metric-mini-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="18" cy="5" r="3" />
                          <circle cx="6" cy="12" r="3" />
                          <circle cx="18" cy="19" r="3" />
                          <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                          <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                        </svg>
                      </span>
                      <span className="metric-mini-num">14</span>
                      <span className="metric-mini-label">Network Connections</span>
                    </div>

                    <div className="metric-mini-box box-soft-yellow">
                      <span className="metric-mini-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <span className="metric-mini-num">8</span>
                      <span className="metric-mini-label">Files Dropped</span>
                    </div>

                    <div className="metric-mini-box">
                      <span className="metric-mini-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="3" y="3" width="7" height="7" />
                          <rect x="14" y="3" width="7" height="7" />
                          <rect x="14" y="14" width="7" height="7" />
                          <rect x="3" y="14" width="7" height="7" />
                        </svg>
                      </span>
                      <span className="metric-mini-num">12</span>
                      <span className="metric-mini-label">Registry Modifications</span>
                    </div>
                  </div>
                </div>

                {/* MITRE ATT&CK Techniques */}
                <div className="dashboard-card">
                  <div className="card-header-row" style={{ marginBottom: '0.5rem' }}>
                    <div className="card-title-with-desc">
                      <span className="card-icon-lead">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="18" cy="5" r="3" />
                          <circle cx="6" cy="12" r="3" />
                          <circle cx="18" cy="19" r="3" />
                          <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                          <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                        </svg>
                      </span>
                      <div className="title-desc-wrap">
                        <span className="card-title-text">MITRE ATT&amp;CK Techniques</span>
                        <span className="card-desc-sub">Identified techniques based on observed behavior.</span>
                      </div>
                    </div>

                    <button type="button" className="btn-card-viewall">
                      <span>View All</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="5" y1="12" x2="19" y2="12" />
                        <polyline points="12 5 19 12 12 19" />
                      </svg>
                    </button>
                  </div>

                  <div className="mitre-techniques-list">
                    <div className="mitre-item-row">
                      <div className="mitre-left-id">
                        <span className="mitre-side-indicator indicator-red"></span>
                        <span className="mitre-id-code">T1059.003</span>
                        <span className="mitre-name-text">Command and Scripting Interpreter</span>
                      </div>
                      <span className="badge-severity-high">High</span>
                    </div>

                    <div className="mitre-item-row">
                      <div className="mitre-left-id">
                        <span className="mitre-side-indicator indicator-red"></span>
                        <span className="mitre-id-code">T1547.001</span>
                        <span className="mitre-name-text">Registry Run Keys / Startup Folder</span>
                      </div>
                      <span className="badge-severity-high">High</span>
                    </div>

                    <div className="mitre-item-row">
                      <div className="mitre-left-id">
                        <span className="mitre-side-indicator indicator-blue"></span>
                        <span className="mitre-id-code">T1071.001</span>
                        <span className="mitre-name-text">Application Layer Protocol</span>
                      </div>
                      <span className="badge-severity-medium">Medium</span>
                    </div>

                    <div className="mitre-item-row">
                      <div className="mitre-left-id">
                        <span className="mitre-side-indicator indicator-orange"></span>
                        <span className="mitre-id-code">T1562.001</span>
                        <span className="mitre-name-text">Disable or Modify Tools</span>
                      </div>
                      <span className="badge-severity-medium">Medium</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Row 3: Process Tree | Network Activity */}
              <div className="overview-bottom-grid">
                {/* Process Tree */}
                <div className="dashboard-card">
                  <div className="card-header-row" style={{ marginBottom: '0.5rem' }}>
                    <div className="card-title-with-desc">
                      <span className="card-icon-lead">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="3" y="3" width="6" height="5" rx="1" />
                          <rect x="15" y="16" width="6" height="5" rx="1" />
                          <rect x="3" y="16" width="6" height="5" rx="1" />
                          <path d="M6 8v5a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1v-2" />
                        </svg>
                      </span>
                      <div className="title-desc-wrap">
                        <span className="card-title-text">Process Tree</span>
                        <span className="card-desc-sub">Hierarchical view of spawned processes.</span>
                      </div>
                    </div>

                    <button type="button" className="btn-card-viewall">
                      <span>View Full Tree</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="5" y1="12" x2="19" y2="12" />
                        <polyline points="12 5 19 12 12 19" />
                      </svg>
                    </button>
                  </div>

                  <div className="process-tree-body">
                    {/* Level 0: Root Process */}
                    <div className="tree-node">
                      <span className="node-caret">▼</span>
                      <span className="node-icon">📁</span>
                      <span className="node-name">sample_malware.exe</span>
                      <span className="node-pid">(PID 4320)</span>
                      <span className="node-badge-malicious">Malicious</span>
                    </div>

                    {/* Level 1: cmd.exe */}
                    <div className="tree-node tree-level-1">
                      <span className="node-caret">▼</span>
                      <span className="node-icon">📁</span>
                      <span className="node-name">cmd.exe</span>
                      <span className="node-pid">(PID 5184)</span>
                    </div>

                    {/* Level 2: powershell.exe */}
                    <div className="tree-node tree-level-2">
                      <span className="node-caret">▼</span>
                      <span className="node-icon">📁</span>
                      <span className="node-name">powershell.exe</span>
                      <span className="node-pid">(PID 7260)</span>
                    </div>

                    {/* Level 3: rundll32.exe */}
                    <div className="tree-node tree-level-3">
                      <span className="node-caret">▼</span>
                      <span className="node-icon">📁</span>
                      <span className="node-name">rundll32.exe</span>
                      <span className="node-pid">(PID 8912)</span>
                      <span className="node-badge-suspicious">Suspicious</span>
                    </div>

                    {/* Level 4: regsvr32.exe */}
                    <div className="tree-node tree-level-4">
                      <span className="node-icon">📄</span>
                      <span className="node-name">regsvr32.exe</span>
                      <span className="node-pid">(PID 9012)</span>
                    </div>
                  </div>
                </div>

                {/* Network Activity Table */}
                <div className="dashboard-card">
                  <div className="card-header-row" style={{ marginBottom: '0.5rem' }}>
                    <div className="card-title-with-desc">
                      <span className="card-icon-lead">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="10" />
                          <line x1="2" y1="12" x2="22" y2="12" />
                          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                        </svg>
                      </span>
                      <div className="title-desc-wrap">
                        <span className="card-title-text">Network Activity</span>
                        <span className="card-desc-sub">External connections made during execution.</span>
                      </div>
                    </div>

                    <button type="button" className="btn-card-viewall">
                      <span>View All</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="5" y1="12" x2="19" y2="12" />
                        <polyline points="12 5 19 12 12 19" />
                      </svg>
                    </button>
                  </div>

                  <div className="network-table-card">
                    <table className="network-activity-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Domain / IP</th>
                          <th>Port</th>
                          <th>Protocol</th>
                          <th>Reputation</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td className="table-code-text">14:22:18</td>
                          <td className="table-domain-bold">api.example.com</td>
                          <td>443</td>
                          <td>HTTPS</td>
                          <td>
                            <span className="badge-net-malicious">Malicious</span>
                          </td>
                        </tr>
                        <tr>
                          <td className="table-code-text">14:22:20</td>
                          <td className="table-domain-bold">185.199.110.43</td>
                          <td>80</td>
                          <td>HTTP</td>
                          <td>
                            <span className="badge-net-suspicious">Suspicious</span>
                          </td>
                        </tr>
                        <tr>
                          <td className="table-code-text">14:22:31</td>
                          <td className="table-domain-bold">cdn.example.net</td>
                          <td>443</td>
                          <td>HTTPS</td>
                          <td>
                            <span className="badge-net-unknown">Unknown</span>
                          </td>
                        </tr>
                        <tr>
                          <td className="table-code-text">14:22:45</td>
                          <td className="table-domain-bold">91.213.21.34</td>
                          <td>53</td>
                          <td>DNS</td>
                          <td>
                            <span className="badge-net-suspicious">Suspicious</span>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </>
          )}

          {/* ===================== BEHAVIOR TAB CONTENT ===================== */}
          {activeTab === 'Behavior' && (
            <div className="behavior-tab-content">
              {/* 1. Behavior Timeline Card */}
              <div className="dashboard-card behavior-timeline-card">
                <div className="card-header-row">
                  <div className="card-title-with-desc">
                    <span className="card-icon-lead">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10" />
                        <polyline points="12 6 12 12 16 14" />
                      </svg>
                    </span>
                    <div className="title-desc-wrap">
                      <span className="card-title-text">Behavior Timeline</span>
                      <span className="card-desc-sub">Key actions observed during execution, in chronological order.</span>
                    </div>
                  </div>

                  <div className="timeline-filter-select-wrap">
                    <div className="timeline-severity-dropdown">
                      <span>All severities</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>
                  </div>
                </div>

                {/* Timeline Items List */}
                <div className="behavior-timeline-list">
                  {/* Event 1 */}
                  <div className="timeline-row-item">
                    <div className="timeline-indicator-col">
                      <span className="timeline-dot dot-red"></span>
                      <span className="timeline-vert-line"></span>
                    </div>
                    <span className="timeline-timestamp">00:00.000</span>
                    <div className="timeline-action-icon">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="3" />
                        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                      </svg>
                    </div>
                    <div className="timeline-details-col">
                      <div className="timeline-title-line">
                        <span className="timeline-event-name">Process started</span>
                        <span className="timeline-event-extra">sample_malware.exe (PID 4320) spawned in suspended state and resumed execution.</span>
                      </div>
                      <span className="timeline-code-quote">"C:\Users\WDAGUtilityAccount\Desktop\sample_malware.exe"</span>
                    </div>
                    <div className="timeline-right-pill">
                      <span className="badge-severity-high">High</span>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="chevron-icon">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </div>
                  </div>

                  {/* Event 2 */}
                  <div className="timeline-row-item">
                    <div className="timeline-indicator-col">
                      <span className="timeline-dot dot-orange"></span>
                      <span className="timeline-vert-line"></span>
                    </div>
                    <span className="timeline-timestamp">00:01.213</span>
                    <div className="timeline-action-icon">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                        <polyline points="14 2 14 8 20 8" />
                      </svg>
                    </div>
                    <div className="timeline-details-col">
                      <div className="timeline-title-line">
                        <span className="timeline-event-name">File created</span>
                        <span className="timeline-event-extra">Creates and writes a file to disk.</span>
                      </div>
                      <span className="timeline-code-quote">"C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost\payload.dll"</span>
                    </div>
                    <div className="timeline-right-pill">
                      <span className="badge-severity-high">High</span>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="chevron-icon">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </div>
                  </div>

                  {/* Event 3 */}
                  <div className="timeline-row-item">
                    <div className="timeline-indicator-col">
                      <span className="timeline-dot dot-red"></span>
                      <span className="timeline-vert-line"></span>
                    </div>
                    <span className="timeline-timestamp">00:03.102</span>
                    <div className="timeline-action-icon">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="2" y="3" width="20" height="14" rx="2" />
                        <line x1="8" y1="21" x2="16" y2="21" />
                        <line x1="12" y1="17" x2="12" y2="21" />
                      </svg>
                    </div>
                    <div className="timeline-details-col">
                      <div className="timeline-title-line">
                        <span className="timeline-event-name">Command executed</span>
                        <span className="timeline-event-extra">Spawns powershell.exe with encoded command.</span>
                      </div>
                      <span className="timeline-code-quote">"powershell.exe -EncodedCommand SQBFAFGA...AAgA..."</span>
                    </div>
                    <div className="timeline-right-pill">
                      <span className="badge-severity-high">High</span>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="chevron-icon">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </div>
                  </div>

                  {/* Event 4 */}
                  <div className="timeline-row-item">
                    <div className="timeline-indicator-col">
                      <span className="timeline-dot dot-orange"></span>
                      <span className="timeline-vert-line"></span>
                    </div>
                    <span className="timeline-timestamp">00:06.451</span>
                    <div className="timeline-action-icon">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="3" y="3" width="7" height="7" />
                        <rect x="14" y="3" width="7" height="7" />
                        <rect x="14" y="14" width="7" height="7" />
                        <rect x="3" y="14" width="7" height="7" />
                      </svg>
                    </div>
                    <div className="timeline-details-col">
                      <div className="timeline-title-line">
                        <span className="timeline-event-name">Registry modified</span>
                        <span className="timeline-event-extra">Adds a value to run at startup (persistence).</span>
                      </div>
                      <span className="timeline-code-quote">"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\svchost"</span>
                    </div>
                    <div className="timeline-right-pill">
                      <span className="badge-severity-medium">Medium</span>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="chevron-icon">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </div>
                  </div>

                  {/* Event 5 */}
                  <div className="timeline-row-item">
                    <div className="timeline-indicator-col">
                      <span className="timeline-dot dot-orange"></span>
                      <span className="timeline-vert-line"></span>
                    </div>
                    <span className="timeline-timestamp">00:10.872</span>
                    <div className="timeline-action-icon">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="2" y1="12" x2="22" y2="12" />
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                      </svg>
                    </div>
                    <div className="timeline-details-col">
                      <div className="timeline-title-line">
                        <span className="timeline-event-name">Network connection</span>
                        <span className="timeline-event-extra">Establishes outbound HTTPS connection to a remote IP address.</span>
                      </div>
                      <span className="timeline-code-quote">185.199.110.133:443</span>
                    </div>
                    <div className="timeline-right-pill">
                      <span className="badge-severity-medium">Medium</span>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="chevron-icon">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </div>
                  </div>

                  {/* Event 6 */}
                  <div className="timeline-row-item">
                    <div className="timeline-indicator-col">
                      <span className="timeline-dot dot-red"></span>
                    </div>
                    <span className="timeline-timestamp">00:15.672</span>
                    <div className="timeline-action-icon">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        <polyline points="9 12 11 14 15 10" />
                      </svg>
                    </div>
                    <div className="timeline-details-col">
                      <div className="timeline-title-line">
                        <span className="timeline-event-name">Privilege escalation attempt</span>
                        <span className="timeline-event-extra">Attempts UAC bypass using eventvwr.exe technique.</span>
                      </div>
                      <span className="timeline-code-quote">"eventvwr.exe /s /n /u:C:\Users\WDAGUtilityAccount\AppData\Roaming\payload.dll"</span>
                    </div>
                    <div className="timeline-right-pill">
                      <span className="badge-severity-high">High</span>
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="chevron-icon">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </div>
                  </div>
                </div>
              </div>

              {/* 2. Bottom Row: Notable Behaviors (Left) + Behavior Categories (Right) */}
              <div className="behavior-bottom-grid">
                {/* Notable Behaviors Card */}
                <div className="dashboard-card">
                  <div className="card-header-row" style={{ marginBottom: '0.75rem' }}>
                    <div className="card-title-with-desc">
                      <span className="card-icon-lead">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                          <line x1="12" y1="9" x2="12" y2="13" />
                          <line x1="12" y1="17" x2="12.01" y2="17" />
                        </svg>
                      </span>
                      <div className="title-desc-wrap">
                        <span className="card-title-text">Notable Behaviors</span>
                        <span className="card-desc-sub">Important behavioral indicators identified during analysis.</span>
                      </div>
                    </div>
                  </div>

                  <div className="notable-behaviors-table-wrap">
                    <table className="notable-behaviors-table">
                      <thead>
                        <tr>
                          <th>Behavior</th>
                          <th>Evidence</th>
                          <th>Severity</th>
                        </tr>
                      </thead>
                      <tbody>
                        <tr>
                          <td>
                            <div className="notable-behavior-cell">
                              <span className="notable-name-strong">Persistence</span>
                              <span className="notable-sub-text">Run key created for svchost</span>
                            </div>
                          </td>
                          <td className="notable-evidence-cell">
                            HKCU\Software\Microsoft\Windows\CurrentVersion\Run
                          </td>
                          <td className="notable-sev-cell">
                            <span className="badge-severity-high">High</span>
                          </td>
                        </tr>

                        <tr>
                          <td>
                            <div className="notable-behavior-cell">
                              <span className="notable-name-strong">Command execution</span>
                              <span className="notable-sub-text">Encoded PowerShell command</span>
                            </div>
                          </td>
                          <td className="notable-evidence-cell">
                            powershell.exe -EncodedCommand ...
                          </td>
                          <td className="notable-sev-cell">
                            <span className="badge-severity-high">High</span>
                          </td>
                        </tr>

                        <tr>
                          <td>
                            <div className="notable-behavior-cell">
                              <span className="notable-name-strong">File drop</span>
                              <span className="notable-sub-text">Writes payload.dll to disk</span>
                            </div>
                          </td>
                          <td className="notable-evidence-cell">
                            C:\...\AppData\Roaming\svchost\payload.dll
                          </td>
                          <td className="notable-sev-cell">
                            <span className="badge-severity-high">High</span>
                          </td>
                        </tr>

                        <tr>
                          <td>
                            <div className="notable-behavior-cell">
                              <span className="notable-name-strong">Defense evasion</span>
                              <span className="notable-sub-text">Disables Windows Defender</span>
                            </div>
                          </td>
                          <td className="notable-evidence-cell">
                            powershell.exe Set-MpPreference ...
                          </td>
                          <td className="notable-sev-cell">
                            <span className="badge-severity-medium">Medium</span>
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Behavior Categories Distribution Card */}
                <div className="dashboard-card">
                  <div className="card-header-row" style={{ marginBottom: '1.25rem' }}>
                    <div className="card-title-with-desc">
                      <span className="card-icon-lead">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <line x1="18" y1="20" x2="18" y2="10" />
                          <line x1="12" y1="20" x2="12" y2="4" />
                          <line x1="6" y1="20" x2="6" y2="14" />
                        </svg>
                      </span>
                      <div className="title-desc-wrap">
                        <span className="card-title-text">Behavior Categories</span>
                        <span className="card-desc-sub">Distribution of observed behaviors.</span>
                      </div>
                    </div>
                  </div>

                  <div className="behavior-categories-list">
                    {/* Execution */}
                    <div className="category-bar-row">
                      <span className="category-name">Execution</span>
                      <div className="category-track">
                        <div className="category-fill fill-red" style={{ width: '85%' }}></div>
                      </div>
                      <span className="category-count">12</span>
                    </div>

                    {/* Persistence */}
                    <div className="category-bar-row">
                      <span className="category-name">Persistence</span>
                      <div className="category-track">
                        <div className="category-fill fill-orange" style={{ width: '42%' }}></div>
                      </div>
                      <span className="category-count">5</span>
                    </div>

                    {/* Defense Evasion */}
                    <div className="category-bar-row">
                      <span className="category-name">Defense Evasion</span>
                      <div className="category-track">
                        <div className="category-fill fill-orange" style={{ width: '35%' }}></div>
                      </div>
                      <span className="category-count">4</span>
                    </div>

                    {/* Discovery */}
                    <div className="category-bar-row">
                      <span className="category-name">Discovery</span>
                      <div className="category-track">
                        <div className="category-fill fill-orange" style={{ width: '25%' }}></div>
                      </div>
                      <span className="category-count">3</span>
                    </div>

                    {/* Command & Control */}
                    <div className="category-bar-row">
                      <span className="category-name">Command &amp; Control</span>
                      <div className="category-track">
                        <div className="category-fill fill-orange" style={{ width: '35%' }}></div>
                      </div>
                      <span className="category-count">4</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===================== PROCESSES TAB CONTENT ===================== */}
          {activeTab === 'Processes' && (
            <div className="processes-tab-content">
              {/* 1. Process Tree Table Card */}
              <div className="dashboard-card process-tree-main-card">
                <div className="card-header-row process-header-controls">
                  <div className="card-title-with-desc">
                    <span className="card-icon-lead">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="3" y="3" width="6" height="5" rx="1" />
                        <rect x="15" y="16" width="6" height="5" rx="1" />
                        <rect x="3" y="16" width="6" height="5" rx="1" />
                        <path d="M6 8v5a1 1 0 0 0 1 1h11a1 1 0 0 0 1-1v-2" />
                      </svg>
                    </span>
                    <div className="title-desc-wrap">
                      <span className="card-title-text">Process Tree</span>
                      <span className="card-desc-sub">Hierarchical view of all spawned processes.</span>
                    </div>
                  </div>

                  <div className="process-header-right-tools">
                    {/* Search processes */}
                    <div className="process-search-wrapper">
                      <span className="search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search processes..."
                        className="process-search-input"
                      />
                    </div>

                    {/* Filter All Processes */}
                    <div className="process-filter-dropdown">
                      <span>All Processes</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>

                    {/* Expand All */}
                    <button type="button" className="btn-expand-all">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="15 3 21 3 21 9" />
                        <polyline points="9 21 3 21 3 15" />
                        <line x1="21" y1="3" x2="14" y2="10" />
                        <line x1="3" y1="21" x2="10" y2="14" />
                      </svg>
                      <span>Expand All</span>
                    </button>
                  </div>
                </div>

                {/* Process Tree Data Table */}
                <div className="process-table-wrapper">
                  <table className="process-tree-table">
                    <thead>
                      <tr>
                        <th>Process Name</th>
                        <th>PID</th>
                        <th>PPID</th>
                        <th>Image Path</th>
                        <th>Command Line</th>
                        <th>Start Time</th>
                        <th>Status</th>
                        <th>Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {/* 1. sample_malware.exe */}
                      <tr className="row-selected-process">
                        <td>
                          <div className="proc-tree-name-cell level-0">
                            <span className="tree-arrow">▼</span>
                            <span className="proc-icon">📁</span>
                            <span className="proc-name-text">sample_malware.exe</span>
                          </div>
                        </td>
                        <td>4320</td>
                        <td>4008</td>
                        <td className="proc-path-text">C:\Users\WDAGUtilityAccount\Desktop\sample_malware.exe</td>
                        <td className="proc-cmd-text">"sample_malware.exe"</td>
                        <td>14:22:18</td>
                        <td><span className="badge-status-running">Running</span></td>
                        <td><span className="badge-severity-high">High</span></td>
                      </tr>

                      {/* 2. cmd.exe */}
                      <tr>
                        <td>
                          <div className="proc-tree-name-cell level-1">
                            <span className="tree-arrow">▼</span>
                            <span className="proc-icon">📁</span>
                            <span className="proc-name-text">cmd.exe</span>
                          </div>
                        </td>
                        <td>5184</td>
                        <td>4320</td>
                        <td className="proc-path-text">C:\Windows\System32\cmd.exe</td>
                        <td className="proc-cmd-text">"cmd.exe /c ..."</td>
                        <td>14:22:20</td>
                        <td><span className="badge-status-exited">Exited</span></td>
                        <td><span className="badge-severity-high">High</span></td>
                      </tr>

                      {/* 3. powershell.exe */}
                      <tr>
                        <td>
                          <div className="proc-tree-name-cell level-2">
                            <span className="tree-arrow">▼</span>
                            <span className="proc-icon">📁</span>
                            <span className="proc-name-text">powershell.exe</span>
                          </div>
                        </td>
                        <td>7260</td>
                        <td>5184</td>
                        <td className="proc-path-text">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</td>
                        <td className="proc-cmd-text">powershell.exe -Enc...</td>
                        <td>14:22:21</td>
                        <td><span className="badge-status-exited">Exited</span></td>
                        <td><span className="badge-severity-high">High</span></td>
                      </tr>

                      {/* 4. rundll32.exe */}
                      <tr>
                        <td>
                          <div className="proc-tree-name-cell level-3">
                            <span className="tree-arrow">▼</span>
                            <span className="proc-icon">📁</span>
                            <span className="proc-name-text">rundll32.exe</span>
                          </div>
                        </td>
                        <td>8912</td>
                        <td>7260</td>
                        <td className="proc-path-text">C:\Windows\System32\rundll32.exe</td>
                        <td className="proc-cmd-text">rundll32.exe C:\...\pa...</td>
                        <td>14:22:23</td>
                        <td><span className="badge-status-exited">Exited</span></td>
                        <td><span className="badge-severity-suspicious">Suspicious</span></td>
                      </tr>

                      {/* 5. regsvr32.exe */}
                      <tr>
                        <td>
                          <div className="proc-tree-name-cell level-4">
                            <span className="proc-icon">📄</span>
                            <span className="proc-name-text">regsvr32.exe</span>
                          </div>
                        </td>
                        <td>9012</td>
                        <td>8912</td>
                        <td className="proc-path-text">C:\Windows\System32\regsvr32.exe</td>
                        <td className="proc-cmd-text">regsvr32.exe /s C:\...</td>
                        <td>14:22:24</td>
                        <td><span className="badge-status-exited">Exited</span></td>
                        <td><span className="badge-severity-suspicious">Suspicious</span></td>
                      </tr>

                      {/* 6. svchost.exe */}
                      <tr>
                        <td>
                          <div className="proc-tree-name-cell level-1">
                            <span className="tree-arrow">▼</span>
                            <span className="proc-icon">📁</span>
                            <span className="proc-name-text">svchost.exe</span>
                          </div>
                        </td>
                        <td>6540</td>
                        <td>4320</td>
                        <td className="proc-path-text">C:\Windows\System32\svchost.exe</td>
                        <td className="proc-cmd-text">svchost.exe -k netsvcs</td>
                        <td>14:22:25</td>
                        <td><span className="badge-status-running">Running</span></td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 7. conhost.exe */}
                      <tr>
                        <td>
                          <div className="proc-tree-name-cell level-2">
                            <span className="proc-icon">📄</span>
                            <span className="proc-name-text">conhost.exe</span>
                          </div>
                        </td>
                        <td>7176</td>
                        <td>6540</td>
                        <td className="proc-path-text">C:\Windows\System32\conhost.exe</td>
                        <td className="proc-cmd-text">conhost.exe 0x4</td>
                        <td>14:22:25</td>
                        <td><span className="badge-status-running">Running</span></td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 8. wscript.exe */}
                      <tr>
                        <td>
                          <div className="proc-tree-name-cell level-1">
                            <span className="tree-arrow">▼</span>
                            <span className="proc-icon">📁</span>
                            <span className="proc-name-text">wscript.exe</span>
                          </div>
                        </td>
                        <td>8124</td>
                        <td>4320</td>
                        <td className="proc-path-text">C:\Windows\System32\wscript.exe</td>
                        <td className="proc-cmd-text">wscript.exe C:\...\sc...</td>
                        <td>14:22:26</td>
                        <td><span className="badge-status-exited">Exited</span></td>
                        <td><span className="badge-severity-suspicious">Suspicious</span></td>
                      </tr>

                      {/* 9. tasklist.exe */}
                      <tr>
                        <td>
                          <div className="proc-tree-name-cell level-1">
                            <span className="proc-icon">📄</span>
                            <span className="proc-name-text">tasklist.exe</span>
                          </div>
                        </td>
                        <td>9340</td>
                        <td>4320</td>
                        <td className="proc-path-text">C:\Windows\System32\tasklist.exe</td>
                        <td className="proc-cmd-text">tasklist.exe</td>
                        <td>14:22:28</td>
                        <td><span className="badge-status-exited">Exited</span></td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* 2. Process Inspection Bottom Split Card */}
              <div className="dashboard-card process-detail-split-card">
                {/* Left Detail Column */}
                <div className="proc-detail-left">
                  <div className="proc-detail-heading-row">
                    <div className="proc-detail-file-icon">
                      <svg width="22" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                        <polyline points="14 2 14 8 20 8" />
                      </svg>
                    </div>
                    <span className="proc-detail-title">sample_malware.exe</span>
                    <span className="proc-detail-pid-tag">(PID 4320)</span>
                    <span className="badge-malicious-pill">Malicious</span>
                  </div>

                  <div className="proc-metadata-kv-list">
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">Image Path</span>
                      <span className="proc-kv-val mono-path">C:\Users\WDAGUtilityAccount\Desktop\sample_malware.exe</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">Command Line</span>
                      <span className="proc-kv-val mono-path">"sample_malware.exe"</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">Parent Process</span>
                      <span className="proc-kv-val">explorer.exe (PID 4008)</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">Start Time</span>
                      <span className="proc-kv-val">Oct 11, 2026, 14:22:18</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">Status</span>
                      <span className="proc-kv-val">Running</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">Integrity Level</span>
                      <span className="proc-kv-val">Medium</span>
                    </div>
                  </div>
                </div>

                {/* Right Process Characteristics Column */}
                <div className="proc-detail-right">
                  <div className="proc-chars-header">
                    <span className="proc-chars-icon">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="3" />
                        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                      </svg>
                    </span>
                    <span className="proc-chars-title">Process Characteristics</span>
                  </div>

                  <div className="proc-chars-kv-list">
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">Signed</span>
                      <span className="proc-kv-val signed-no">No</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">Publisher</span>
                      <span className="proc-kv-val">N/A</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">File Version</span>
                      <span className="proc-kv-val">N/A</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">Subsystem</span>
                      <span className="proc-kv-val">Windows GUI</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">Bitness</span>
                      <span className="proc-kv-val">64-bit</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">MD5</span>
                      <span className="proc-kv-val mono-hash">e4d9a7c1b8f3e6d0a9c2b5f7e1d6c4a8</span>
                    </div>
                    <div className="proc-kv-row">
                      <span className="proc-kv-key">SHA256</span>
                      <div className="proc-sha256-wrap">
                        <span className="proc-kv-val mono-hash truncate-hash">37a8e5c6b0d3e9f72ca9d6e1f78b3c4d56e7f906a1b2c3d4e5f...</span>
                        <button type="button" className="btn-copy-hash" title="Copy SHA256">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===================== FILE SYSTEM TAB CONTENT ===================== */}
          {activeTab === 'File System' && (
            <div className="filesystem-tab-layout">
              {/* Left Column: File System Activity Card */}
              <div className="dashboard-card filesystem-main-card">
                {/* Header row */}
                <div className="fs-header-row">
                  <div className="fs-title-with-desc">
                    <span className="fs-icon-lead">
                      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z"/>
                      </svg>
                    </span>
                    <div className="fs-title-text-wrap">
                      <span className="fs-card-title">File System Activity</span>
                      <span className="fs-card-subtitle">Files and directories created, modified, or deleted during execution.</span>
                    </div>
                  </div>

                  {/* Right Header Tools & Legend */}
                  <div className="fs-header-right-tools">
                    <div className="fs-search-box">
                      <span className="fs-search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search files or paths..."
                        className="fs-search-input"
                      />
                    </div>

                    <div className="fs-action-filter-dropdown">
                      <span>All Actions</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>

                    {/* Dot Legend */}
                    <div className="fs-legend-dots">
                      <div className="fs-legend-item">
                        <span className="fs-dot fs-dot-created"></span>
                        <span>Created</span>
                      </div>
                      <div className="fs-legend-item">
                        <span className="fs-dot fs-dot-modified"></span>
                        <span>Modified</span>
                      </div>
                      <div className="fs-legend-item">
                        <span className="fs-dot fs-dot-deleted"></span>
                        <span>Deleted</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div className="fs-table-wrap">
                  <table className="fs-activity-table">
                    <thead>
                      <tr>
                        <th>Path</th>
                        <th>Action</th>
                        <th>Size</th>
                        <th>Timestamp</th>
                        <th style={{ width: '40px' }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {/* Row 1 */}
                      <tr>
                        <td>
                          <div className="fs-path-cell">
                            <span className="fs-file-icon fs-icon-folder">📁</span>
                            <span className="fs-path-text">C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost\</span>
                          </div>
                        </td>
                        <td><span className="badge-fs-created">Created</span></td>
                        <td className="fs-dim-text">-</td>
                        <td>14:22:01</td>
                        <td className="fs-chevron-cell">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                      </tr>

                      {/* Row 2 - Selected payload.dll */}
                      <tr className="row-selected-fs">
                        <td>
                          <div className="fs-path-cell">
                            <span className="fs-file-icon fs-icon-doc">📄</span>
                            <span className="fs-path-text font-medium">C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost\payload.dll</span>
                          </div>
                        </td>
                        <td><span className="badge-fs-created">Created</span></td>
                        <td>243 KB</td>
                        <td>14:22:02</td>
                        <td className="fs-chevron-cell">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                      </tr>

                      {/* Row 3 */}
                      <tr>
                        <td>
                          <div className="fs-path-cell">
                            <span className="fs-file-icon fs-icon-doc">📄</span>
                            <span className="fs-path-text">C:\Users\WDAGUtilityAccount\AppData\Local\Temp\config.dat</span>
                          </div>
                        </td>
                        <td><span className="badge-fs-modified">Modified</span></td>
                        <td>4 KB</td>
                        <td>14:22:05</td>
                        <td className="fs-chevron-cell">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                      </tr>

                      {/* Row 4 */}
                      <tr>
                        <td>
                          <div className="fs-path-cell">
                            <span className="fs-file-icon fs-icon-doc">📄</span>
                            <span className="fs-path-text">C:\Windows\System32\drivers\etc\hosts</span>
                          </div>
                        </td>
                        <td><span className="badge-fs-modified">Modified</span></td>
                        <td>824 B</td>
                        <td>14:22:10</td>
                        <td className="fs-chevron-cell">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                      </tr>

                      {/* Row 5 */}
                      <tr>
                        <td>
                          <div className="fs-path-cell">
                            <span className="fs-file-icon fs-icon-doc">📄</span>
                            <span className="fs-path-text">C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost\log.txt</span>
                          </div>
                        </td>
                        <td><span className="badge-fs-created">Created</span></td>
                        <td>12 KB</td>
                        <td>14:22:11</td>
                        <td className="fs-chevron-cell">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                      </tr>

                      {/* Row 6 */}
                      <tr>
                        <td>
                          <div className="fs-path-cell">
                            <span className="fs-file-icon fs-icon-doc">📄</span>
                            <span className="fs-path-text">C:\ProgramData\Microsoft\Windows\Start Menu\Programs\startup.ps1</span>
                          </div>
                        </td>
                        <td><span className="badge-fs-created">Created</span></td>
                        <td>1.2 KB</td>
                        <td>14:22:14</td>
                        <td className="fs-chevron-cell">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                      </tr>

                      {/* Row 7 */}
                      <tr>
                        <td>
                          <div className="fs-path-cell">
                            <span className="fs-file-icon fs-icon-doc">📄</span>
                            <span className="fs-path-text">C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost\temp.tmp</span>
                          </div>
                        </td>
                        <td><span className="badge-fs-deleted">Deleted</span></td>
                        <td>0 B</td>
                        <td>14:22:18</td>
                        <td className="fs-chevron-cell">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                      </tr>

                      {/* Row 8 */}
                      <tr>
                        <td>
                          <div className="fs-path-cell">
                            <span className="fs-file-icon fs-icon-folder">📁</span>
                            <span className="fs-path-text">C:\Users\WDAGUtilityAccount\AppData\Local\Microsoft\Windows\INetCache\</span>
                          </div>
                        </td>
                        <td><span className="badge-fs-created">Created</span></td>
                        <td className="fs-dim-text">-</td>
                        <td>14:22:21</td>
                        <td className="fs-chevron-cell">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                      </tr>

                      {/* Row 9 */}
                      <tr>
                        <td>
                          <div className="fs-path-cell">
                            <span className="fs-file-icon fs-icon-doc">📄</span>
                            <span className="fs-path-text">C:\Users\WDAGUtilityAccount\AppData\Local\Microsoft\Windows\INetCache\ie\abc.tmp</span>
                          </div>
                        </td>
                        <td><span className="badge-fs-created">Created</span></td>
                        <td>56 KB</td>
                        <td>14:22:23</td>
                        <td className="fs-chevron-cell">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                      </tr>

                      {/* Row 10 */}
                      <tr>
                        <td>
                          <div className="fs-path-cell">
                            <span className="fs-file-icon fs-icon-doc">📄</span>
                            <span className="fs-path-text">C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost\config.json</span>
                          </div>
                        </td>
                        <td><span className="badge-fs-modified">Modified</span></td>
                        <td>2 KB</td>
                        <td>14:22:25</td>
                        <td className="fs-chevron-cell">
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <polyline points="9 18 15 12 9 6" />
                          </svg>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {/* Pagination footer */}
                <div className="fs-pagination-footer">
                  <span className="fs-pagination-info">Showing 1 to 10 of 28 files</span>
                  <div className="fs-pagination-controls">
                    <button type="button" className="btn-page-arrow" disabled>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="15 18 9 12 15 6" />
                      </svg>
                    </button>
                    <button type="button" className="btn-page-number active">1</button>
                    <button type="button" className="btn-page-number">2</button>
                    <button type="button" className="btn-page-number">3</button>
                    <button type="button" className="btn-page-arrow">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>

              {/* Right Column: File Details Inspection Panel */}
              <div className="dashboard-card fs-detail-panel">
                <div className="fs-detail-header">
                  <div className="fs-detail-file-title-group">
                    <div className="fs-detail-icon">
                      <svg width="22" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                        <polyline points="14 2 14 8 20 8" />
                      </svg>
                    </div>
                    <div>
                      <h4 className="fs-detail-filename">payload.dll</h4>
                      <p className="fs-detail-filepath">C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost\payload.dll</p>
                    </div>
                  </div>
                  <button type="button" className="btn-close-fs-detail" title="Close details">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <line x1="18" y1="6" x2="6" y2="18" />
                      <line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                  </button>
                </div>

                {/* 3 mini stats columns */}
                <div className="fs-detail-stats-row">
                  <div className="fs-detail-stat-col">
                    <span className="fs-stat-label">Action</span>
                    <div><span className="badge-fs-created">Created</span></div>
                  </div>
                  <div className="fs-detail-stat-col">
                    <span className="fs-stat-label">Size</span>
                    <span className="fs-stat-val">243 KB</span>
                  </div>
                  <div className="fs-detail-stat-col">
                    <span className="fs-stat-label">Timestamp</span>
                    <span className="fs-stat-val">Oct 11, 2026, 14:22:02</span>
                  </div>
                </div>

                {/* File Information Section */}
                <div className="fs-section-block">
                  <h5 className="fs-section-subtitle">File Information</h5>
                  <div className="fs-kv-list">
                    <div className="fs-kv-row">
                      <span className="fs-kv-key">Type</span>
                      <span className="fs-kv-val">Dynamic Link Library (DLL)</span>
                    </div>
                    <div className="fs-kv-row">
                      <span className="fs-kv-key">SHA256</span>
                      <div className="fs-hash-copy-wrap">
                        <span className="fs-kv-val mono-hash truncate-hash">c6b2d9f4a1e8c3d7b0f5a9e2...</span>
                        <button type="button" className="btn-copy-hash" title="Copy SHA256">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                          </svg>
                        </button>
                      </div>
                    </div>
                    <div className="fs-kv-row">
                      <span className="fs-kv-key">MD5</span>
                      <div className="fs-hash-copy-wrap">
                        <span className="fs-kv-val mono-hash truncate-hash">5f2a3c9d4e7b1a8c6d0e2f1a...</span>
                        <button type="button" className="btn-copy-hash" title="Copy MD5">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                          </svg>
                        </button>
                      </div>
                    </div>
                    <div className="fs-kv-row">
                      <span className="fs-kv-key">First Seen</span>
                      <span className="fs-kv-val">Oct 11, 2026, 14:22:02</span>
                    </div>
                    <div className="fs-kv-row">
                      <span className="fs-kv-key">Last Modified</span>
                      <span className="fs-kv-val">Oct 11, 2026, 14:22:02</span>
                    </div>
                  </div>
                </div>

                {/* Classification */}
                <div className="fs-section-block fs-classification-row">
                  <span className="fs-classification-label">Classification</span>
                  <span className="badge-severity-suspicious">Suspicious</span>
                </div>

                {/* YARA Matches */}
                <div className="fs-section-block">
                  <h5 className="fs-section-subtitle">YARA Matches</h5>
                  <div className="fs-yara-pill-row">
                    <span className="fs-yara-name">Generic_Malware_DLL</span>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="9 18 15 12 9 6" />
                    </svg>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===================== NETWORK TAB CONTENT ===================== */}
          {activeTab === 'Network' && (
            <div className="network-tab-layout">
              {/* Top Stat Cards Row */}
              <div className="network-stats-strip">
                <div className="dashboard-card net-stat-box">
                  <div className="net-stat-icon-wrap icon-blue-bg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="2" y1="12" x2="22" y2="12" />
                      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                    </svg>
                  </div>
                  <div className="net-stat-info">
                    <span className="net-stat-label">Total Connections</span>
                    <span className="net-stat-val">14</span>
                  </div>
                </div>

                <div className="dashboard-card net-stat-box">
                  <div className="net-stat-icon-wrap icon-blue-bg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="18" cy="5" r="3" />
                      <circle cx="6" cy="12" r="3" />
                      <circle cx="18" cy="19" r="3" />
                      <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                      <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                    </svg>
                  </div>
                  <div className="net-stat-info">
                    <span className="net-stat-label">Unique Domains</span>
                    <span className="net-stat-val">6</span>
                  </div>
                </div>

                <div className="dashboard-card net-stat-box">
                  <div className="net-stat-icon-wrap icon-purple-bg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
                      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
                      <line x1="6" y1="6" x2="6.01" y2="6" />
                      <line x1="6" y1="18" x2="6.01" y2="18" />
                    </svg>
                  </div>
                  <div className="net-stat-info">
                    <span className="net-stat-label">Unique IPs</span>
                    <span className="net-stat-val">8</span>
                  </div>
                </div>

                <div className="dashboard-card net-stat-box">
                  <div className="net-stat-icon-wrap icon-red-bg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <line x1="12" y1="19" x2="12" y2="5" />
                      <polyline points="5 12 12 5 19 12" />
                    </svg>
                  </div>
                  <div className="net-stat-info">
                    <span className="net-stat-label">Data Sent</span>
                    <span className="net-stat-val">1.2 MB</span>
                  </div>
                </div>

                <div className="dashboard-card net-stat-box">
                  <div className="net-stat-icon-wrap icon-green-bg">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <line x1="12" y1="5" x2="12" y2="19" />
                      <polyline points="19 12 12 19 5 12" />
                    </svg>
                  </div>
                  <div className="net-stat-info">
                    <span className="net-stat-label">Data Received</span>
                    <span className="net-stat-val">5.6 MB</span>
                  </div>
                </div>
              </div>

              {/* Main Content Split: Left Table vs Right Sidebar Widgets */}
              <div className="net-split-grid">
                {/* Left: Network Connections Table Card */}
                <div className="dashboard-card net-main-table-card">
                  <div className="net-table-header-row">
                    <div className="net-title-with-desc">
                      <span className="net-lead-icon">
                        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="10" />
                          <line x1="2" y1="12" x2="22" y2="12" />
                          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                        </svg>
                      </span>
                      <div className="net-title-text-wrap">
                        <span className="net-card-title">Network Connections</span>
                        <span className="net-card-subtitle">All outbound and inbound network activity.</span>
                      </div>
                    </div>

                    <div className="net-table-header-tools">
                      <div className="net-search-box">
                        <span className="net-search-icon">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                            <circle cx="11" cy="11" r="8" />
                            <line x1="21" y1="21" x2="16.65" y2="16.65" />
                          </svg>
                        </span>
                        <input
                          type="text"
                          placeholder="Search by domain, IP, or port..."
                          className="net-search-input"
                        />
                      </div>

                      <div className="net-filter-dropdown">
                        <span>All Protocols</span>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="6 9 12 15 18 9" />
                        </svg>
                      </div>
                    </div>
                  </div>

                  {/* Table */}
                  <div className="net-table-wrapper">
                    <table className="net-connections-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Direction</th>
                          <th>Domain / IP</th>
                          <th>Port</th>
                          <th>Protocol</th>
                          <th>Bytes Sent</th>
                          <th>Bytes Received</th>
                          <th>Reputation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {/* 1 */}
                        <tr>
                          <td>14:22:10</td>
                          <td>
                            <span className="dir-arrow arrow-up" title="Outbound">↑</span>
                          </td>
                          <td className="net-target-cell font-semibold">api.example.com</td>
                          <td>443</td>
                          <td>HTTPS</td>
                          <td>24 KB</td>
                          <td>312 KB</td>
                          <td><span className="badge-rep-malicious">Malicious</span></td>
                        </tr>

                        {/* 2 */}
                        <tr>
                          <td>14:22:12</td>
                          <td>
                            <span className="dir-arrow arrow-up" title="Outbound">↑</span>
                          </td>
                          <td className="net-target-cell mono-font">185.199.110.43</td>
                          <td>80</td>
                          <td>HTTP</td>
                          <td>4 KB</td>
                          <td>0 B</td>
                          <td><span className="badge-rep-suspicious">Suspicious</span></td>
                        </tr>

                        {/* 3 */}
                        <tr>
                          <td>14:22:14</td>
                          <td>
                            <span className="dir-arrow arrow-up" title="Outbound">↑</span>
                          </td>
                          <td className="net-target-cell font-semibold">cdn.example.net</td>
                          <td>443</td>
                          <td>HTTPS</td>
                          <td>8 KB</td>
                          <td>1.1 MB</td>
                          <td><span className="badge-rep-suspicious">Suspicious</span></td>
                        </tr>

                        {/* 4 */}
                        <tr>
                          <td>14:22:18</td>
                          <td>
                            <span className="dir-arrow arrow-up" title="Outbound">↑</span>
                          </td>
                          <td className="net-target-cell mono-font">91.213.21.34</td>
                          <td>53</td>
                          <td>DNS</td>
                          <td>512 B</td>
                          <td>1.2 KB</td>
                          <td><span className="badge-rep-unknown">Unknown</span></td>
                        </tr>

                        {/* 5 */}
                        <tr>
                          <td>14:22:21</td>
                          <td>
                            <span className="dir-arrow arrow-up" title="Outbound">↑</span>
                          </td>
                          <td className="net-target-cell">update.microsoft.com</td>
                          <td>443</td>
                          <td>HTTPS</td>
                          <td>16 KB</td>
                          <td>220 KB</td>
                          <td><span className="badge-rep-benign">Benign</span></td>
                        </tr>

                        {/* 6 */}
                        <tr>
                          <td>14:22:25</td>
                          <td>
                            <span className="dir-arrow arrow-up" title="Outbound">↑</span>
                          </td>
                          <td className="net-target-cell mono-font">185.220.101.12</td>
                          <td>8080</td>
                          <td>HTTP</td>
                          <td>2 KB</td>
                          <td>12 KB</td>
                          <td><span className="badge-rep-malicious">Malicious</span></td>
                        </tr>

                        {/* 7 */}
                        <tr>
                          <td>14:22:27</td>
                          <td>
                            <span className="dir-arrow arrow-down" title="Inbound">↓</span>
                          </td>
                          <td className="net-target-cell mono-font">104.18.31.12</td>
                          <td>443</td>
                          <td>HTTPS</td>
                          <td>0 B</td>
                          <td>420 KB</td>
                          <td><span className="badge-rep-suspicious">Suspicious</span></td>
                        </tr>

                        {/* 8 */}
                        <tr>
                          <td>14:22:31</td>
                          <td>
                            <span className="dir-arrow arrow-up" title="Outbound">↑</span>
                          </td>
                          <td className="net-target-cell">ntp.windows.com</td>
                          <td>123</td>
                          <td>NTP</td>
                          <td>84 B</td>
                          <td>84 B</td>
                          <td><span className="badge-rep-benign">Benign</span></td>
                        </tr>

                        {/* 9 */}
                        <tr>
                          <td>14:22:33</td>
                          <td>
                            <span className="dir-arrow arrow-up" title="Outbound">↑</span>
                          </td>
                          <td className="net-target-cell mono-font">142.250.190.78</td>
                          <td>443</td>
                          <td>HTTPS</td>
                          <td>6 KB</td>
                          <td>380 KB</td>
                          <td><span className="badge-rep-unknown">Unknown</span></td>
                        </tr>

                        {/* 10 */}
                        <tr>
                          <td>14:22:35</td>
                          <td>
                            <span className="dir-arrow arrow-down" title="Inbound">↓</span>
                          </td>
                          <td className="net-target-cell mono-font">8.8.8.8</td>
                          <td>53</td>
                          <td>DNS</td>
                          <td>512 B</td>
                          <td>1.1 KB</td>
                          <td><span className="badge-rep-benign">Benign</span></td>
                        </tr>
                      </tbody>
                    </table>
                  </div>

                  {/* Pagination Footer */}
                  <div className="net-pagination-footer">
                    <span className="net-pagination-info">Showing 1 to 10 of 14 connections</span>
                    <div className="net-pagination-controls">
                      <button type="button" className="btn-page-arrow" disabled>
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="15 18 9 12 15 6" />
                        </svg>
                      </button>
                      <button type="button" className="btn-page-number active">1</button>
                      <button type="button" className="btn-page-number">2</button>
                      <button type="button" className="btn-page-arrow">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="9 18 15 12 9 6" />
                        </svg>
                      </button>
                    </div>
                  </div>
                </div>

                {/* Right: Widgets Column */}
                <div className="net-widgets-col">
                  {/* Widget 1: Destination Countries */}
                  <div className="dashboard-card net-widget-card">
                    <h4 className="net-widget-title">Destination Countries</h4>
                    <div className="net-world-map-wrapper">
                      {/* Stylized SVG World Map */}
                      <svg viewBox="0 0 380 180" className="net-world-map-svg">
                        <path
                          className="map-continent"
                          d="M 40 45 Q 60 30 85 45 Q 110 50 115 75 Q 90 90 75 75 Z"
                          fill="#E5E9F0"
                        />
                        <path
                          className="map-continent"
                          d="M 85 90 Q 110 95 105 135 Q 90 155 75 120 Z"
                          fill="#E5E9F0"
                        />
                        <path
                          className="map-continent"
                          d="M 160 35 Q 195 25 210 45 Q 200 70 170 65 Z"
                          fill="#E5E9F0"
                        />
                        <path
                          className="map-continent"
                          d="M 165 75 Q 205 75 200 125 Q 180 145 165 110 Z"
                          fill="#E5E9F0"
                        />
                        <path
                          className="map-continent"
                          d="M 220 30 Q 310 20 325 65 Q 290 95 235 75 Z"
                          fill="#E5E9F0"
                        />
                        <path
                          className="map-continent"
                          d="M 280 115 Q 325 110 320 145 Q 285 150 280 125 Z"
                          fill="#E5E9F0"
                        />

                        {/* Ping / Marker on United States */}
                        <circle cx="82" cy="58" r="14" fill="#EF4444" fillOpacity="0.2" />
                        <circle cx="82" cy="58" r="5" fill="#EF4444" />
                        <circle cx="82" cy="58" r="2" fill="#FFFFFF" />

                        {/* Ping / Marker on Europe */}
                        <circle cx="185" cy="48" r="4" fill="#F59E0B" />

                        {/* Ping / Marker on East Asia / Singapore */}
                        <circle cx="270" cy="98" r="5" fill="#10B981" />
                      </svg>
                    </div>

                    <div className="net-countries-legend-grid">
                      <div className="country-legend-item">
                        <span className="legend-dot-country dot-red"></span>
                        <span className="country-name-txt">United States</span>
                        <span className="country-count-txt">6</span>
                      </div>
                      <div className="country-legend-item">
                        <span className="legend-dot-country dot-green"></span>
                        <span className="country-name-txt">Singapore</span>
                        <span className="country-count-txt">1</span>
                      </div>
                      <div className="country-legend-item">
                        <span className="legend-dot-country dot-orange"></span>
                        <span className="country-name-txt">Germany</span>
                        <span className="country-count-txt">3</span>
                      </div>
                      <div className="country-legend-item">
                        <span className="legend-dot-country dot-grey"></span>
                        <span className="country-name-txt">Unknown</span>
                        <span className="country-count-txt">2</span>
                      </div>
                      <div className="country-legend-item">
                        <span className="legend-dot-country dot-yellow"></span>
                        <span className="country-name-txt">Netherlands</span>
                        <span className="country-count-txt">2</span>
                      </div>
                    </div>
                  </div>

                  {/* Widget 2: Top Domains */}
                  <div className="dashboard-card net-widget-card">
                    <h4 className="net-widget-title">Top Domains</h4>
                    <div className="net-progress-bars-list">
                      <div className="net-progress-row">
                        <span className="prog-item-name">api.example.com</span>
                        <div className="prog-track">
                          <div className="prog-bar bg-red" style={{ width: '85%' }}></div>
                        </div>
                        <span className="prog-count-val">6</span>
                      </div>

                      <div className="net-progress-row">
                        <span className="prog-item-name">cdn.example.net</span>
                        <div className="prog-track">
                          <div className="prog-bar bg-orange" style={{ width: '60%' }}></div>
                        </div>
                        <span className="prog-count-val">4</span>
                      </div>

                      <div className="net-progress-row">
                        <span className="prog-item-name">update.microsoft.com</span>
                        <div className="prog-track">
                          <div className="prog-bar bg-yellow" style={{ width: '35%' }}></div>
                        </div>
                        <span className="prog-count-val">2</span>
                      </div>

                      <div className="net-progress-row">
                        <span className="prog-item-name">ntp.windows.com</span>
                        <div className="prog-track">
                          <div className="prog-bar bg-teal" style={{ width: '20%' }}></div>
                        </div>
                        <span className="prog-count-val">1</span>
                      </div>

                      <div className="net-progress-row">
                        <span className="prog-item-name">Others</span>
                        <div className="prog-track">
                          <div className="prog-bar bg-grey" style={{ width: '45%' }}></div>
                        </div>
                        <span className="prog-count-val">3</span>
                      </div>
                    </div>
                  </div>

                  {/* Widget 3: Top IP Addresses */}
                  <div className="dashboard-card net-widget-card">
                    <h4 className="net-widget-title">Top IP Addresses</h4>
                    <div className="net-progress-bars-list">
                      <div className="net-progress-row">
                        <span className="prog-item-name mono-font">185.199.110.43</span>
                        <div className="prog-track">
                          <div className="prog-bar bg-red" style={{ width: '80%' }}></div>
                        </div>
                        <span className="prog-count-val">4</span>
                      </div>

                      <div className="net-progress-row">
                        <span className="prog-item-name mono-font">104.18.31.12</span>
                        <div className="prog-track">
                          <div className="prog-bar bg-orange" style={{ width: '60%' }}></div>
                        </div>
                        <span className="prog-count-val">3</span>
                      </div>

                      <div className="net-progress-row">
                        <span className="prog-item-name mono-font">91.213.21.34</span>
                        <div className="prog-track">
                          <div className="prog-bar bg-yellow" style={{ width: '45%' }}></div>
                        </div>
                        <span className="prog-count-val">2</span>
                      </div>

                      <div className="net-progress-row">
                        <span className="prog-item-name mono-font">142.250.190.78</span>
                        <div className="prog-track">
                          <div className="prog-bar bg-teal" style={{ width: '25%' }}></div>
                        </div>
                        <span className="prog-count-val">1</span>
                      </div>

                      <div className="net-progress-row">
                        <span className="prog-item-name">Others</span>
                        <div className="prog-track">
                          <div className="prog-bar bg-grey" style={{ width: '60%' }}></div>
                        </div>
                        <span className="prog-count-val">3</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Placeholder for other tabs */}
          {activeTab !== 'Overview' && activeTab !== 'Behavior' && activeTab !== 'Processes' && activeTab !== 'File System' && activeTab !== 'Network' && (
            <div className="dashboard-card" style={{ padding: '3.5rem', textAlign: 'center' }}>
              <h3 style={{ fontSize: '1.2rem', color: '#111418', marginBottom: '0.5rem' }}>{activeTab} Telemetry</h3>
              <p style={{ color: '#727a85', fontSize: '0.9rem' }}>Detailed inspection logs for {activeTab} will appear here.</p>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}

export default Dashboard
