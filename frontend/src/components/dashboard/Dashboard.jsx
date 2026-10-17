import React, { useState, useEffect } from 'react'
import './dashboard.css'
import Sidebar from '../layout/Sidebar'
import { getJobDetails } from '../../api/client'
import { transformAnalysisData } from '../../utils/formatAnalysis'

const Dashboard = ({
  sampleData,
  onNavigateHome,
  onNavigateUpload,
  onNavigateTab
}) => {
  const [activeTab, setActiveTab] = useState('Overview')
  const [searchQuery, setSearchQuery] = useState('')
  const [loadedJob, setLoadedJob] = useState(null)
  const [loading, setLoading] = useState(false)

  // If a sample with only an ID was passed, fetch the full job details
  useEffect(() => {
    if (sampleData?.id && !sampleData?.rawDetails?.analysis_result && !sampleData?.analysis_result) {
      setLoading(true)
      getJobDetails(sampleData.id)
        .then((data) => {
          setLoadedJob(data)
        })
        .catch((err) => {
          console.warn('Failed to load full job details:', err)
        })
        .finally(() => {
          setLoading(false)
        })
    }
  }, [sampleData?.id])

  // Transformed sample data with real backend payload or fallback
  const fallbackSample = {
    fileName: 'sample_malware.exe',
    status: 'Malicious',
    sha256: '37a8e5c6b0d3e9f72ca9d6e1f78b3c4d56e7f906a1b2c3d4e5f6a7b8c9d0e1f2',
    fileType: 'PE32+ (EXE)',
    fileSize: '412 KB',
    analysisTime: '2m 34s',
    submitted: 'Oct 11, 2026, 14:22',
    environment: 'Windows Sandbox',
    score: 92
  }

  const sample = transformAnalysisData(loadedJob || sampleData?.rawDetails || sampleData, fallbackSample)

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

  // Circular Gauge Math based on dynamic score
  const score = sample.score != null ? sample.score : 0
  const arcLength = 170
  const strokeDashoffset = arcLength - (score / 100) * arcLength

  const handleDownloadReport = () => {
    const reportData = sample.rawJson || JSON.stringify(sample, null, 2)
    const blob = new Blob([reportData], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `threatbox-report-${sample.fileName}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

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
              <button
                type="button"
                className="btn-download-report"
                onClick={handleDownloadReport}
              >
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
                      <span className="metric-mini-num">{sample.processCount}</span>
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
                      <span className="metric-mini-num">{sample.networkCount}</span>
                      <span className="metric-mini-label">Network Connections</span>
                    </div>

                    <div className="metric-mini-box box-soft-yellow">
                      <span className="metric-mini-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <span className="metric-mini-num">{sample.fileCount}</span>
                      <span className="metric-mini-label">File Operations</span>
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
                      <span className="metric-mini-num">{sample.registryCount}</span>
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

                {/* Horizontal 2-Column Body */}
                <div className="fs-detail-horizontal-body">
                  {/* Left Column: File Information */}
                  <div className="fs-detail-body-left">
                    <h5 className="fs-section-subtitle">File Information</h5>
                    <div className="fs-kv-list">
                      <div className="fs-kv-row">
                        <span className="fs-kv-key">Type</span>
                        <span className="fs-kv-val">Dynamic Link Library (DLL)</span>
                      </div>
                      <div className="fs-kv-row">
                        <span className="fs-kv-key">SHA256</span>
                        <div className="fs-hash-copy-wrap">
                          <span className="fs-kv-val mono-hash truncate-hash">c6b2d9f4a1e8c3d7b0f5a9e2c4d6a7f1b8e3c0d9a2f4e6b7c1d3e5f...</span>
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
                          <span className="fs-kv-val mono-hash truncate-hash">5f2a3c9d4e7b1a8c6d0e2f1a3b4c5d6e</span>
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

                  {/* Right Column: Classification & YARA Matches */}
                  <div className="fs-detail-body-right">
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

          {/* ===================== DNS TAB CONTENT ===================== */}
          {activeTab === 'DNS' && (
            <div className="dns-tab-layout">
              {/* Left Column: DNS Queries Main Card */}
              <div className="dashboard-card dns-main-card">
                <div className="dns-header-row">
                  <div className="dns-title-with-desc">
                    <span className="dns-lead-icon">
                      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10" />
                        <line x1="2" y1="12" x2="22" y2="12" />
                        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                      </svg>
                    </span>
                    <div className="dns-title-text-wrap">
                      <span className="dns-card-title">DNS Queries</span>
                      <span className="dns-card-subtitle">Domain name queries made during execution.</span>
                    </div>
                  </div>

                  <div className="dns-header-right-tools">
                    <div className="dns-search-box">
                      <span className="dns-search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search domains..."
                        className="dns-search-input"
                      />
                    </div>

                    <div className="dns-filter-dropdown">
                      <span>All Types</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div className="dns-table-wrapper">
                  <table className="dns-queries-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Domain</th>
                        <th>Type</th>
                        <th>Resolved IP</th>
                        <th>Query Count</th>
                        <th>Reputation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {/* 1 */}
                      <tr>
                        <td>00:02:14</td>
                        <td className="dns-domain-bold">api.example.com</td>
                        <td className="dns-type-cell">A</td>
                        <td className="dns-ip-mono">185.199.110.43</td>
                        <td>3</td>
                        <td><span className="badge-rep-malicious">Malicious</span></td>
                      </tr>

                      {/* 2 */}
                      <tr>
                        <td>00:02:16</td>
                        <td className="dns-domain-bold">cdn.example.net</td>
                        <td className="dns-type-cell">A</td>
                        <td className="dns-ip-mono">91.213.21.34</td>
                        <td>2</td>
                        <td><span className="badge-rep-suspicious">Suspicious</span></td>
                      </tr>

                      {/* 3 */}
                      <tr>
                        <td>00:02:19</td>
                        <td className="dns-domain-bold">update.microsoft.com</td>
                        <td className="dns-type-cell">A</td>
                        <td className="dns-ip-mono">104.18.31.12</td>
                        <td>1</td>
                        <td><span className="badge-rep-benign">Benign</span></td>
                      </tr>

                      {/* 4 */}
                      <tr>
                        <td>00:02:21</td>
                        <td className="dns-domain-bold">ntp.windows.com</td>
                        <td className="dns-type-cell">A</td>
                        <td className="dns-ip-mono">20.189.173.8</td>
                        <td>1</td>
                        <td><span className="badge-rep-benign">Benign</span></td>
                      </tr>

                      {/* 5 */}
                      <tr>
                        <td>00:02:24</td>
                        <td className="dns-domain-bold">track.example.org</td>
                        <td className="dns-type-cell">A</td>
                        <td className="dns-ip-mono">142.250.190.78</td>
                        <td>4</td>
                        <td><span className="badge-rep-suspicious">Suspicious</span></td>
                      </tr>

                      {/* 6 */}
                      <tr>
                        <td>00:02:27</td>
                        <td className="dns-domain-bold">malicious-domain.xyz</td>
                        <td className="dns-type-cell">A</td>
                        <td className="dns-ip-mono">8.8.8.8</td>
                        <td>1</td>
                        <td><span className="badge-rep-malicious">Malicious</span></td>
                      </tr>

                      {/* 7 */}
                      <tr>
                        <td>00:02:31</td>
                        <td className="dns-domain-bold">data.example.com</td>
                        <td className="dns-type-cell">A</td>
                        <td className="dns-ip-mono">185.220.101.12</td>
                        <td>3</td>
                        <td><span className="badge-rep-suspicious">Suspicious</span></td>
                      </tr>

                      {/* 8 */}
                      <tr>
                        <td>00:02:34</td>
                        <td className="dns-domain-bold">staging.example.net</td>
                        <td className="dns-type-cell">A</td>
                        <td className="dns-ip-mono">93.184.216.34</td>
                        <td>1</td>
                        <td><span className="badge-rep-unknown">Unknown</span></td>
                      </tr>

                      {/* 9 */}
                      <tr>
                        <td>00:02:36</td>
                        <td className="dns-domain-bold">detectportal.firefox.com</td>
                        <td className="dns-type-cell">A</td>
                        <td className="dns-ip-mono">34.107.221.82</td>
                        <td>1</td>
                        <td><span className="badge-rep-benign">Benign</span></td>
                      </tr>

                      {/* 10 */}
                      <tr>
                        <td>00:02:41</td>
                        <td className="dns-domain-bold">schemas.microsoft.com</td>
                        <td className="dns-type-cell">A</td>
                        <td className="dns-ip-mono">23.48.99.120</td>
                        <td>1</td>
                        <td><span className="badge-rep-benign">Benign</span></td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="dns-pagination-footer">
                  <span className="dns-pagination-info">Showing 1 to 10 of 18 domains</span>
                  <div className="dns-pagination-controls">
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

              {/* Right Column: Widgets */}
              <div className="dns-widgets-col">
                {/* 1. DNS Summary Card */}
                <div className="dashboard-card dns-widget-card">
                  <div className="dns-widget-title-row">
                    <span className="dns-title-icon">
                      <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                        <line x1="8" y1="21" x2="16" y2="21" />
                        <line x1="12" y1="17" x2="12" y2="21" />
                      </svg>
                    </span>
                    <h4 className="dns-widget-title">DNS Summary</h4>
                  </div>

                  <div className="dns-summary-mini-grid">
                    {/* Total Queries */}
                    <div className="dns-mini-box">
                      <div className="dns-mini-icon-wrap icon-blue-bg">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="12" cy="12" r="10" />
                          <line x1="2" y1="12" x2="22" y2="12" />
                          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                        </svg>
                      </div>
                      <span className="dns-mini-num">18</span>
                      <span className="dns-mini-txt">Total Queries</span>
                    </div>

                    {/* Unique Domains */}
                    <div className="dns-mini-box">
                      <div className="dns-mini-icon-wrap icon-blue-bg">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="18" cy="5" r="3" />
                          <circle cx="6" cy="12" r="3" />
                          <circle cx="18" cy="19" r="3" />
                          <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                          <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                        </svg>
                      </div>
                      <span className="dns-mini-num">6</span>
                      <span className="dns-mini-txt">Unique Domains</span>
                    </div>

                    {/* Unique IPs */}
                    <div className="dns-mini-box">
                      <div className="dns-mini-icon-wrap icon-purple-bg">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
                          <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
                          <line x1="6" y1="6" x2="6.01" y2="6" />
                          <line x1="6" y1="18" x2="6.01" y2="18" />
                        </svg>
                      </div>
                      <span className="dns-mini-num">8</span>
                      <span className="dns-mini-txt">Unique IPs</span>
                    </div>

                    {/* Suspicious Domains */}
                    <div className="dns-mini-box">
                      <div className="dns-mini-icon-wrap icon-yellow-bg">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                          <line x1="12" y1="9" x2="12" y2="13" />
                          <line x1="12" y1="17" x2="12.01" y2="17" />
                        </svg>
                      </div>
                      <span className="dns-mini-num">3</span>
                      <span className="dns-mini-txt">Suspicious Domains</span>
                    </div>
                  </div>
                </div>

                {/* 2. Top Queried Domains Card */}
                <div className="dashboard-card dns-widget-card">
                  <div className="dns-widget-title-row between">
                    <div className="dns-title-with-lead">
                      <span className="dns-title-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <h4 className="dns-widget-title">Top Queried Domains</h4>
                    </div>
                    <span className="dns-arrow-right">→</span>
                  </div>

                  <div className="dns-bars-header-row">
                    <span>Domain</span>
                    <span>Query Count</span>
                  </div>

                  <div className="dns-progress-bars-list">
                    <div className="dns-progress-row">
                      <span className="prog-domain-name">api.example.com</span>
                      <div className="prog-track">
                        <div className="prog-bar bg-red" style={{ width: '85%' }}></div>
                      </div>
                      <span className="prog-count-val">3</span>
                    </div>

                    <div className="dns-progress-row">
                      <span className="prog-domain-name">data.example.com</span>
                      <div className="prog-track">
                        <div className="prog-bar bg-orange" style={{ width: '85%' }}></div>
                      </div>
                      <span className="prog-count-val">3</span>
                    </div>

                    <div className="dns-progress-row">
                      <span className="prog-domain-name">cdn.example.net</span>
                      <div className="prog-track">
                        <div className="prog-bar bg-orange" style={{ width: '60%' }}></div>
                      </div>
                      <span className="prog-count-val">2</span>
                    </div>

                    <div className="dns-progress-row">
                      <span className="prog-domain-name">update.microsoft.com</span>
                      <div className="prog-track">
                        <div className="prog-bar bg-yellow" style={{ width: '30%' }}></div>
                      </div>
                      <span className="prog-count-val">1</span>
                    </div>

                    <div className="dns-progress-row">
                      <span className="prog-domain-name">ntp.windows.com</span>
                      <div className="prog-track">
                        <div className="prog-bar bg-grey" style={{ width: '30%' }}></div>
                      </div>
                      <span className="prog-count-val">1</span>
                    </div>
                  </div>
                </div>

                {/* 3. Top Resolved IPs Card */}
                <div className="dashboard-card dns-widget-card">
                  <div className="dns-widget-title-row between">
                    <div className="dns-title-with-lead">
                      <span className="dns-title-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <h4 className="dns-widget-title">Top Resolved IPs</h4>
                    </div>
                    <span className="dns-arrow-right">→</span>
                  </div>

                  <div className="dns-bars-header-row">
                    <span>IP Address</span>
                    <span>Query Count</span>
                  </div>

                  <div className="dns-progress-bars-list">
                    <div className="dns-progress-row">
                      <span className="prog-domain-name mono-font">185.199.110.43</span>
                      <div className="prog-track">
                        <div className="prog-bar bg-red" style={{ width: '85%' }}></div>
                      </div>
                      <span className="prog-count-val">3</span>
                    </div>

                    <div className="dns-progress-row">
                      <span className="prog-domain-name mono-font">185.220.101.12</span>
                      <div className="prog-track">
                        <div className="prog-bar bg-orange" style={{ width: '85%' }}></div>
                      </div>
                      <span className="prog-count-val">3</span>
                    </div>

                    <div className="dns-progress-row">
                      <span className="prog-domain-name mono-font">91.213.21.34</span>
                      <div className="prog-track">
                        <div className="prog-bar bg-orange" style={{ width: '60%' }}></div>
                      </div>
                      <span className="prog-count-val">2</span>
                    </div>

                    <div className="dns-progress-row">
                      <span className="prog-domain-name mono-font">104.18.31.12</span>
                      <div className="prog-track">
                        <div className="prog-bar bg-yellow" style={{ width: '30%' }}></div>
                      </div>
                      <span className="prog-count-val">1</span>
                    </div>

                    <div className="dns-progress-row">
                      <span className="prog-domain-name mono-font">20.189.173.8</span>
                      <div className="prog-track">
                        <div className="prog-bar bg-grey" style={{ width: '30%' }}></div>
                      </div>
                      <span className="prog-count-val">1</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===================== MODULES TAB CONTENT ===================== */}
          {activeTab === 'Modules' && (
            <div className="modules-tab-content">
              {/* 1. Loaded Modules Table Card */}
              <div className="dashboard-card modules-main-card">
                <div className="card-header-row modules-header-controls">
                  <div className="card-title-with-desc">
                    <span className="card-icon-lead">
                      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="18" cy="5" r="3" />
                        <circle cx="6" cy="12" r="3" />
                        <circle cx="18" cy="19" r="3" />
                        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                      </svg>
                    </span>
                    <div className="title-desc-wrap">
                      <span className="card-title-text">Loaded Modules</span>
                      <span className="card-desc-sub">Modules observed in the sample's process activity.</span>
                    </div>
                  </div>

                  <div className="modules-header-right-tools">
                    <div className="modules-search-wrapper">
                      <span className="search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search modules..."
                        className="modules-search-input"
                      />
                    </div>

                    <div className="modules-filter-dropdown">
                      <span>All Modules</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>

                    <div className="modules-count-pill">
                      <span>21 modules</span>
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div className="modules-table-wrapper">
                  <table className="modules-data-table">
                    <thead>
                      <tr>
                        <th>Module</th>
                        <th>Loaded By</th>
                        <th>Image Path</th>
                        <th>Base Address</th>
                        <th>Size</th>
                        <th>Signature</th>
                        <th>SHA-256</th>
                        <th>Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {/* 1 */}
                      <tr>
                        <td>
                          <div className="mod-name-cell">
                            <span className="mod-file-icon">📄</span>
                            <span className="mod-name-text">ntdll.dll</span>
                          </div>
                        </td>
                        <td className="mod-loaded-text">sample_malware.exe</td>
                        <td className="mod-path-text">C:\Windows\System32\ntdll.dll</td>
                        <td className="mod-mono-cell">0x7ffb10000000</td>
                        <td>1.8 MB</td>
                        <td><span className="badge-sig-verified">Microsoft Windows</span></td>
                        <td className="mod-mono-cell truncate-sha">3f2e5a9c0d7b...</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 2 */}
                      <tr>
                        <td>
                          <div className="mod-name-cell">
                            <span className="mod-file-icon">📄</span>
                            <span className="mod-name-text">kernel32.dll</span>
                          </div>
                        </td>
                        <td className="mod-loaded-text">sample_malware.exe</td>
                        <td className="mod-path-text">C:\Windows\System32\kernel32.dll</td>
                        <td className="mod-mono-cell">0x7ffb11000000</td>
                        <td>1.1 MB</td>
                        <td><span className="badge-sig-verified">Microsoft Windows</span></td>
                        <td className="mod-mono-cell truncate-sha">9a4c7d1e5b2f...</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 3 */}
                      <tr>
                        <td>
                          <div className="mod-name-cell">
                            <span className="mod-file-icon">📄</span>
                            <span className="mod-name-text">advapi32.dll</span>
                          </div>
                        </td>
                        <td className="mod-loaded-text">sample_malware.exe</td>
                        <td className="mod-path-text">C:\Windows\System32\advapi32.dll</td>
                        <td className="mod-mono-cell">0x7ffb12000000</td>
                        <td>712 KB</td>
                        <td><span className="badge-sig-verified">Microsoft Windows</span></td>
                        <td className="mod-mono-cell truncate-sha">d1f9c3a2e7b6...</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 4 */}
                      <tr>
                        <td>
                          <div className="mod-name-cell">
                            <span className="mod-file-icon">📄</span>
                            <span className="mod-name-text">ws2_32.dll</span>
                          </div>
                        </td>
                        <td className="mod-loaded-text">sample_malware.exe</td>
                        <td className="mod-path-text">C:\Windows\System32\ws2_32.dll</td>
                        <td className="mod-mono-cell">0x7ffb13000000</td>
                        <td>436 KB</td>
                        <td><span className="badge-sig-verified">Microsoft Windows</span></td>
                        <td className="mod-mono-cell truncate-sha">7c9e1f4d8a3b...</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 5 - payload.dll (SELECTED) */}
                      <tr className="row-selected-module">
                        <td>
                          <div className="mod-name-cell">
                            <span className="mod-file-icon">📄</span>
                            <span className="mod-name-text font-bold">payload.dll</span>
                          </div>
                        </td>
                        <td className="mod-loaded-text">sample_malware.exe</td>
                        <td className="mod-path-text">C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost\payload.dll</td>
                        <td className="mod-mono-cell">0x7ffb2a000000</td>
                        <td>243 KB</td>
                        <td><span className="badge-sig-unsigned">Unsigned</span></td>
                        <td className="mod-mono-cell truncate-sha">c6b2d9f4a1e8...</td>
                        <td><span className="badge-severity-high">High</span></td>
                      </tr>

                      {/* 6 */}
                      <tr>
                        <td>
                          <div className="mod-name-cell">
                            <span className="mod-file-icon">📄</span>
                            <span className="mod-name-text">config.dll</span>
                          </div>
                        </td>
                        <td className="mod-loaded-text">sample_malware.exe</td>
                        <td className="mod-path-text">C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost\config.dll</td>
                        <td className="mod-mono-cell">0x7ffb2b000000</td>
                        <td>96 KB</td>
                        <td><span className="badge-sig-unsigned">Unsigned</span></td>
                        <td className="mod-mono-cell truncate-sha">f52a3c9d4e7b...</td>
                        <td><span className="badge-severity-suspicious">Suspicious</span></td>
                      </tr>

                      {/* 7 */}
                      <tr>
                        <td>
                          <div className="mod-name-cell">
                            <span className="mod-file-icon">📄</span>
                            <span className="mod-name-text">user32.dll</span>
                          </div>
                        </td>
                        <td className="mod-loaded-text">sample_malware.exe</td>
                        <td className="mod-path-text">C:\Windows\System32\user32.dll</td>
                        <td className="mod-mono-cell">0x7ffb15000000</td>
                        <td>1.3 MB</td>
                        <td><span className="badge-sig-verified">Microsoft Windows</span></td>
                        <td className="mod-mono-cell truncate-sha">9e3d7a1b6c4f...</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 8 */}
                      <tr>
                        <td>
                          <div className="mod-name-cell">
                            <span className="mod-file-icon">📄</span>
                            <span className="mod-name-text">gdi32.dll</span>
                          </div>
                        </td>
                        <td className="mod-loaded-text">sample_malware.exe</td>
                        <td className="mod-path-text">C:\Windows\System32\gdi32.dll</td>
                        <td className="mod-mono-cell">0x7ffb16000000</td>
                        <td>980 KB</td>
                        <td><span className="badge-sig-verified">Microsoft Windows</span></td>
                        <td className="mod-mono-cell truncate-sha">a7d3e1c9b5f2...</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 9 */}
                      <tr>
                        <td>
                          <div className="mod-name-cell">
                            <span className="mod-file-icon">📄</span>
                            <span className="mod-name-text">ole32.dll</span>
                          </div>
                        </td>
                        <td className="mod-loaded-text">sample_malware.exe</td>
                        <td className="mod-path-text">C:\Windows\System32\ole32.dll</td>
                        <td className="mod-mono-cell">0x7ffb17000000</td>
                        <td>1.0 MB</td>
                        <td><span className="badge-sig-verified">Microsoft Windows</span></td>
                        <td className="mod-mono-cell truncate-sha">b4e6c5d7a8f1...</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 10 */}
                      <tr>
                        <td>
                          <div className="mod-name-cell">
                            <span className="mod-file-icon">📄</span>
                            <span className="mod-name-text">oleaut32.dll</span>
                          </div>
                        </td>
                        <td className="mod-loaded-text">sample_malware.exe</td>
                        <td className="mod-path-text">C:\Windows\System32\oleaut32.dll</td>
                        <td className="mod-mono-cell">0x7ffb18000000</td>
                        <td>704 KB</td>
                        <td><span className="badge-sig-verified">Microsoft Windows</span></td>
                        <td className="mod-mono-cell truncate-sha">c9f1e2d3a4b6...</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* 2. Bottom Inspection Card */}
              <div className="dashboard-card module-detail-split-card">
                {/* Left Detail Column */}
                <div className="mod-detail-left">
                  <div className="mod-detail-heading-row">
                    <div className="mod-detail-file-icon">
                      <svg width="22" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                        <polyline points="14 2 14 8 20 8" />
                      </svg>
                    </div>
                    <span className="mod-detail-title">payload.dll</span>
                    <span className="badge-severity-high">High Risk</span>
                  </div>

                  <div className="mod-metadata-kv-list">
                    <div className="mod-kv-row">
                      <span className="mod-kv-key">Full Path</span>
                      <span className="mod-kv-val mono-path">C:\Users\WDAGUtilityAccount\AppData\Roaming\svchost\payload.dll</span>
                    </div>
                    <div className="mod-kv-row">
                      <span className="mod-kv-key">Loaded By</span>
                      <span className="mod-kv-val">sample_malware.exe (PID 4320)</span>
                    </div>
                    <div className="mod-kv-row">
                      <span className="mod-kv-key">Base Address</span>
                      <span className="mod-kv-val mono-val">0x7ffb2a000000</span>
                    </div>
                    <div className="mod-kv-row">
                      <span className="mod-kv-key">Size</span>
                      <span className="mod-kv-val">243 KB (248,832 bytes)</span>
                    </div>
                    <div className="mod-kv-row">
                      <span className="mod-kv-key">Signature</span>
                      <span className="badge-sig-unsigned">Unsigned</span>
                    </div>
                    <div className="mod-kv-row">
                      <span className="mod-kv-key">SHA-256</span>
                      <div className="mod-sha256-wrap">
                        <span className="mod-kv-val mono-hash truncate-hash">c6b2d9f4a1e8c3d7b0f5a9e2c4d6a7f1b8e3c0d9a2f4e6b7c1d3e5f8a9b2c4d6e</span>
                        <button type="button" className="btn-copy-hash" title="Copy SHA-256">
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                            <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                            <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                          </svg>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Right Details Column: Why Flagged & Additional Information */}
                <div className="mod-detail-right">
                  <div className="why-flagged-section">
                    <div className="why-flagged-header">
                      <span className="why-flagged-icon">
                        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#DC2626" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
                          <line x1="12" y1="9" x2="12" y2="13" />
                          <line x1="12" y1="17" x2="12.01" y2="17" />
                        </svg>
                      </span>
                      <span className="why-flagged-title">Why Flagged</span>
                    </div>
                    <p className="why-flagged-desc">
                      This module is loaded from a non-standard, user-writable directory (AppData\Roaming) and is not digitally signed. Such behavior is common in malware for executing malicious code.
                    </p>
                  </div>

                  <div className="additional-info-section">
                    <h5 className="additional-info-title">Additional Information</h5>
                    <div className="mod-metadata-kv-list">
                      <div className="mod-kv-row">
                        <span className="mod-kv-key">Compilation Timestamp</span>
                        <span className="mod-kv-val">N/A</span>
                      </div>
                      <div className="mod-kv-row">
                        <span className="mod-kv-key">Linker Version</span>
                        <span className="mod-kv-val">N/A</span>
                      </div>
                      <div className="mod-kv-row">
                        <span className="mod-kv-key">File Type</span>
                        <span className="mod-kv-val">Dynamic Link Library (DLL)</span>
                      </div>
                      <div className="mod-kv-row">
                        <span className="mod-kv-key">Entropy</span>
                        <span className="mod-kv-val">6.8 (High)</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===================== MITRE ATT&CK TAB CONTENT ===================== */}
          {activeTab === 'MITRE ATT&CK' && (
            <div className="mitre-tab-layout">
              {/* Main Card: Header, Tactic Pills, and Table */}
              <div className="dashboard-card mitre-main-card">
                {/* Header Controls */}
                <div className="mitre-header-row">
                  <div className="mitre-title-with-desc">
                    <span className="mitre-lead-icon">
                      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="18" cy="5" r="3" />
                        <circle cx="6" cy="12" r="3" />
                        <circle cx="18" cy="19" r="3" />
                        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                      </svg>
                    </span>
                    <div className="mitre-title-text-wrap">
                      <span className="mitre-card-title">MITRE ATT&amp;CK Mapping</span>
                      <span className="mitre-card-subtitle">Identified techniques based on observed behavior.</span>
                    </div>
                  </div>

                  <div className="mitre-header-right-tools">
                    <div className="mitre-search-box">
                      <span className="mitre-search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search techniques..."
                        className="mitre-search-input"
                      />
                    </div>

                    <div className="mitre-filter-dropdown">
                      <span>All Tactics</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>

                    <div className="mitre-legend-dots">
                      <div className="mitre-legend-item">
                        <span className="mitre-dot dot-red"></span>
                        <span>High</span>
                      </div>
                      <div className="mitre-legend-item">
                        <span className="mitre-dot dot-orange"></span>
                        <span>Medium</span>
                      </div>
                      <div className="mitre-legend-item">
                        <span className="mitre-dot dot-blue"></span>
                        <span>Low</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Top Tactics Pills Strip (6 items) */}
                <div className="mitre-tactics-strip">
                  {/* 1. Initial Access */}
                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-red-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="3" />
                        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">5</span>
                      <span className="tactic-name">Initial Access</span>
                    </div>
                  </div>

                  {/* 2. Execution */}
                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-orange-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <ellipse cx="12" cy="5" rx="9" ry="3" />
                        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
                        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">4</span>
                      <span className="tactic-name">Execution</span>
                    </div>
                  </div>

                  {/* 3. Persistence */}
                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-blue-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="m12 2 9 4.5V17l-9 5-9-5V6.5L12 2Z" />
                        <polyline points="12 12 12 22" />
                        <polyline points="12 12 21 7.5" />
                        <polyline points="12 12 3 7.5" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">3</span>
                      <span className="tactic-name">Persistence</span>
                    </div>
                  </div>

                  {/* 4. Defense Evasion */}
                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-purple-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">4</span>
                      <span className="tactic-name">Defense Evasion</span>
                    </div>
                  </div>

                  {/* 5. Discovery */}
                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-green-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="18" cy="5" r="3" />
                        <circle cx="6" cy="12" r="3" />
                        <circle cx="18" cy="19" r="3" />
                        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">2</span>
                      <span className="tactic-name">Discovery</span>
                    </div>
                  </div>

                  {/* 6. Other */}
                  <div className="tactic-pill-card">
                    <div className="tactic-icon-wrap icon-grey-tint">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="1" />
                        <circle cx="19" cy="12" r="1" />
                        <circle cx="5" cy="12" r="1" />
                      </svg>
                    </div>
                    <div className="tactic-text-info">
                      <span className="tactic-count">3</span>
                      <span className="tactic-name">Other</span>
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div className="mitre-table-wrapper">
                  <table className="mitre-mapping-table">
                    <thead>
                      <tr>
                        <th>Technique ID</th>
                        <th>Technique Name</th>
                        <th>Tactic</th>
                        <th>Evidence Count</th>
                        <th>Severity</th>
                      </tr>
                    </thead>
                    <tbody>
                      {/* 1 - Selected T1059.003 */}
                      <tr className="row-selected-mitre">
                        <td className="mitre-id-bold">T1059.003</td>
                        <td className="mitre-tech-name font-medium">Command and Scripting Interpreter: Windows Command Shell</td>
                        <td><span className="badge-tactic-execution">Execution</span></td>
                        <td>12</td>
                        <td><span className="badge-severity-high">High</span></td>
                      </tr>

                      {/* 2 */}
                      <tr>
                        <td className="mitre-id-bold">T1547.001</td>
                        <td className="mitre-tech-name">Registry Run Keys / Startup Folder</td>
                        <td><span className="badge-tactic-persistence">Persistence</span></td>
                        <td>8</td>
                        <td><span className="badge-severity-high">High</span></td>
                      </tr>

                      {/* 3 */}
                      <tr>
                        <td className="mitre-id-bold">T1071.001</td>
                        <td className="mitre-tech-name">Application Layer Protocol: Web Protocols</td>
                        <td><span className="badge-tactic-c2">Command and Control</span></td>
                        <td>6</td>
                        <td><span className="badge-severity-medium">Medium</span></td>
                      </tr>

                      {/* 4 */}
                      <tr>
                        <td className="mitre-id-bold">T1562.001</td>
                        <td className="mitre-tech-name">Disable or Modify Tools</td>
                        <td><span className="badge-tactic-defense">Defense Evasion</span></td>
                        <td>5</td>
                        <td><span className="badge-severity-medium">Medium</span></td>
                      </tr>

                      {/* 5 */}
                      <tr>
                        <td className="mitre-id-bold">T1047</td>
                        <td className="mitre-tech-name">Windows Management Instrumentation</td>
                        <td><span className="badge-tactic-execution">Execution</span></td>
                        <td>4</td>
                        <td><span className="badge-severity-medium">Medium</span></td>
                      </tr>

                      {/* 6 */}
                      <tr>
                        <td className="mitre-id-bold">T1105</td>
                        <td className="mitre-tech-name">Ingress Tool Transfer</td>
                        <td><span className="badge-tactic-c2">Command and Control</span></td>
                        <td>4</td>
                        <td><span className="badge-severity-medium">Medium</span></td>
                      </tr>

                      {/* 7 */}
                      <tr>
                        <td className="mitre-id-bold">T1082</td>
                        <td className="mitre-tech-name">System Information Discovery</td>
                        <td><span className="badge-tactic-discovery">Discovery</span></td>
                        <td>3</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 8 */}
                      <tr>
                        <td className="mitre-id-bold">T1027</td>
                        <td className="mitre-tech-name">Obfuscated Files or Information</td>
                        <td><span className="badge-tactic-defense">Defense Evasion</span></td>
                        <td>3</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 9 */}
                      <tr>
                        <td className="mitre-id-bold">T1112</td>
                        <td className="mitre-tech-name">Modify Registry</td>
                        <td><span className="badge-tactic-defense">Defense Evasion</span></td>
                        <td>2</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>

                      {/* 10 */}
                      <tr>
                        <td className="mitre-id-bold">T1041</td>
                        <td className="mitre-tech-name">Exfiltration Over C2 Channel</td>
                        <td><span className="badge-tactic-exfil">Exfiltration</span></td>
                        <td>2</td>
                        <td><span className="badge-severity-low">Low</span></td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="mitre-pagination-footer">
                  <span className="mitre-pagination-info">Showing 1 to 10 of 21 techniques</span>
                  <div className="mitre-pagination-controls">
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

              {/* Bottom Inspection Card: Horizontal Layout */}
              <div className="dashboard-card mitre-detail-card">
                <div className="mitre-detail-split-body">
                  {/* Left Column: Technique Info */}
                  <div className="mitre-detail-left-col">
                    <div className="mitre-detail-header-row">
                      <div className="mitre-detail-title-group">
                        <h3 className="mitre-detail-id">T1059.003</h3>
                        <span className="badge-severity-high">High</span>
                      </div>
                      <a href="https://attack.mitre.org/techniques/T1059/003/" target="_blank" rel="noreferrer" className="mitre-link-icon" title="View on MITRE ATT&CK">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
                          <polyline points="15 3 21 3 21 9" />
                          <line x1="10" y1="14" x2="21" y2="3" />
                        </svg>
                      </a>
                    </div>

                    <p className="mitre-detail-tech-name">Command and Scripting Interpreter: Windows Command Shell</p>

                    {/* Tactic Tag */}
                    <div className="mitre-detail-tactic-row">
                      <span className="mitre-label-txt">Tactic</span>
                      <span className="badge-tactic-execution">Execution</span>
                    </div>

                    {/* Description */}
                    <div className="mitre-detail-desc-block">
                      <span className="mitre-label-txt">Description</span>
                      <p className="mitre-desc-paragraph">
                        Adversaries may abuse Windows command shell for execution of commands and scripts.
                      </p>
                    </div>
                  </div>

                  {/* Right Column: Evidences */}
                  <div className="mitre-detail-right-col">
                    <div className="mitre-evidences-section">
                  <div className="mitre-evidences-header">
                    <h5 className="mitre-evidences-title">Evidences (12)</h5>
                    <button type="button" className="btn-view-all-evidences">
                      <span>View All</span>
                      <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="5" y1="12" x2="19" y2="12" />
                        <polyline points="12 5 19 12 12 19" />
                      </svg>
                    </button>
                  </div>

                  <div className="mitre-evidence-cards-list">
                    {/* Evidence 1 */}
                    <div className="mitre-evidence-item">
                      <span className="evidence-file-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <div className="evidence-info-wrap">
                        <span className="evidence-primary-text">Process created: cmd.exe</span>
                        <span className="evidence-sub-text">PID: 5184 | 14:22:20</span>
                      </div>
                    </div>

                    {/* Evidence 2 */}
                    <div className="mitre-evidence-item">
                      <span className="evidence-file-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <div className="evidence-info-wrap">
                        <span className="evidence-primary-text">Command line</span>
                        <span className="evidence-sub-text mono-code">cmd.exe /c powershell.exe -enc ...</span>
                      </div>
                    </div>

                    {/* Evidence 3 */}
                    <div className="mitre-evidence-item">
                      <span className="evidence-file-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <div className="evidence-info-wrap">
                        <span className="evidence-primary-text">Child process: powershell.exe</span>
                        <span className="evidence-sub-text">PID: 7260 | 14:22:21</span>
                      </div>
                    </div>

                    {/* Evidence 4 */}
                    <div className="mitre-evidence-item">
                      <span className="evidence-file-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <div className="evidence-info-wrap">
                        <span className="evidence-primary-text">Script executed</span>
                        <span className="evidence-sub-text mono-code">C:\Users\... \temp\script.ps1</span>
                      </div>
                    </div>

                    {/* Evidence 5 */}
                    <div className="mitre-evidence-item">
                      <span className="evidence-file-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <div className="evidence-info-wrap">
                        <span className="evidence-primary-text">Suspicious command</span>
                        <span className="evidence-sub-text mono-code">... -EncodedCommand ...</span>
                      </div>
                    </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===================== IOCs TAB CONTENT ===================== */}
          {activeTab === 'IOCs' && (
            <div className="iocs-tab-layout">
              {/* Left Column: Indicators of Compromise Card */}
              <div className="dashboard-card iocs-main-card">
                <div className="iocs-header-row">
                  <div className="iocs-title-with-desc">
                    <span className="iocs-lead-icon">
                      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 2a10 10 0 0 0-1.5 19.88V19.4a8 8 0 1 1 3-15.4" />
                        <path d="M12 6a6 6 0 0 0-1.2 11.88V15.4A4 4 0 1 1 14 8" />
                        <circle cx="12" cy="12" r="1.5" />
                        <path d="M8.5 19.5a10 10 0 0 0 7 0" />
                      </svg>
                    </span>
                    <div className="iocs-title-text-wrap">
                      <span className="iocs-card-title">Indicators of Compromise (IOCs)</span>
                      <span className="iocs-card-subtitle">All extracted indicators from the analysis.</span>
                    </div>
                  </div>

                  <div className="iocs-header-right-tools">
                    <div className="iocs-search-box">
                      <span className="iocs-search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search IOCs..."
                        className="iocs-search-input"
                      />
                    </div>

                    <div className="iocs-filter-dropdown">
                      <span>All Types</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>
                  </div>
                </div>

                {/* IOC Table */}
                <div className="iocs-table-wrapper">
                  <table className="iocs-data-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Confidence</th>
                        <th>Reputation</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th style={{ width: '30px' }}></th>
                      </tr>
                    </thead>
                    <tbody>
                      {/* 1 - IP Address 185.199.110.43 (SELECTED) */}
                      <tr className="row-selected-ioc">
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon text-red">⚠️</span>
                            <span>IP Address</span>
                          </div>
                        </td>
                        <td className="ioc-val-text font-bold">185.199.110.43</td>
                        <td><span className="badge-confidence-high">High</span></td>
                        <td><span className="badge-rep-malicious">Malicious</span></td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 2 - Domain api.example.com */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon">🌐</span>
                            <span>Domain</span>
                          </div>
                        </td>
                        <td className="ioc-val-text">api.example.com</td>
                        <td><span className="badge-confidence-high">High</span></td>
                        <td><span className="badge-rep-malicious">Malicious</span></td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 3 - Domain cdn.example.net */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon">🌐</span>
                            <span>Domain</span>
                          </div>
                        </td>
                        <td className="ioc-val-text">cdn.example.net</td>
                        <td><span className="badge-confidence-medium">Medium</span></td>
                        <td><span className="badge-rep-suspicious">Suspicious</span></td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td>Oct 11, 2026, 14:23</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 4 - IP Address 91.213.21.34 */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon text-red">⚠️</span>
                            <span>IP Address</span>
                          </div>
                        </td>
                        <td className="ioc-val-text font-mono">91.213.21.34</td>
                        <td><span className="badge-confidence-medium">Medium</span></td>
                        <td><span className="badge-rep-suspicious">Suspicious</span></td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td>Oct 11, 2026, 14:23</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 5 - URL http://update-microsoft.com/check */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon text-red">🔗</span>
                            <span>URL</span>
                          </div>
                        </td>
                        <td className="ioc-val-text">http://update-microsoft.com/check</td>
                        <td><span className="badge-confidence-medium">Medium</span></td>
                        <td><span className="badge-rep-suspicious">Suspicious</span></td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 6 - URL hxxp://185.220.101.12/payload */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon text-red">🔗</span>
                            <span>URL</span>
                          </div>
                        </td>
                        <td className="ioc-val-text">hxxp://185.220.101.12/payload</td>
                        <td><span className="badge-confidence-high">High</span></td>
                        <td><span className="badge-rep-malicious">Malicious</span></td>
                        <td>Oct 11, 2026, 14:23</td>
                        <td>Oct 11, 2026, 14:23</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 7 - File Hash (SHA256) */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon text-red">📄</span>
                            <span>File Hash (SHA256)</span>
                          </div>
                        </td>
                        <td className="ioc-val-text font-mono truncate-ioc-hash">c6b2d9f4a1e8c3d7b0f5a9e2c4d6a7f...</td>
                        <td><span className="badge-confidence-high">High</span></td>
                        <td><span className="badge-rep-malicious">Malicious</span></td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 8 - File Hash (MD5) */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon text-red">📄</span>
                            <span>File Hash (MD5)</span>
                          </div>
                        </td>
                        <td className="ioc-val-text font-mono">5f2a3c9d4e7b1a8c6d0e2f1a3b4c5d6e</td>
                        <td><span className="badge-confidence-medium">Medium</span></td>
                        <td><span className="badge-rep-suspicious">Suspicious</span></td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 9 - Mutex */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon text-red">🔄</span>
                            <span>Mutex</span>
                          </div>
                        </td>
                        <td className="ioc-val-text font-mono">Global\{'{'}F3A7B1C2-9D44{'}'}</td>
                        <td><span className="badge-confidence-medium">Medium</span></td>
                        <td><span className="badge-rep-suspicious">Suspicious</span></td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 10 - Registry Key */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon text-red">🔀</span>
                            <span>Registry Key</span>
                          </div>
                        </td>
                        <td className="ioc-val-text font-mono truncate-ioc-hash">HKCU\Software\Microsoft\Windows\...</td>
                        <td><span className="badge-confidence-medium">Medium</span></td>
                        <td><span className="badge-rep-suspicious">Suspicious</span></td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 11 - Domain track.example.org */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon">🌐</span>
                            <span>Domain</span>
                          </div>
                        </td>
                        <td className="ioc-val-text">track.example.org</td>
                        <td><span className="badge-confidence-low">Low</span></td>
                        <td><span className="badge-rep-unknown">Unknown</span></td>
                        <td>Oct 11, 2026, 14:23</td>
                        <td>Oct 11, 2026, 14:23</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>

                      {/* 12 - IP Address 8.8.8.8 */}
                      <tr>
                        <td>
                          <div className="ioc-type-cell">
                            <span className="ioc-type-icon text-red">⚠️</span>
                            <span>IP Address</span>
                          </div>
                        </td>
                        <td className="ioc-val-text font-mono">8.8.8.8</td>
                        <td><span className="badge-confidence-low">Low</span></td>
                        <td><span className="badge-rep-benign">Benign</span></td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td>Oct 11, 2026, 14:22</td>
                        <td className="ioc-arrow-cell">›</td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                <div className="iocs-table-footer">
                  <span className="iocs-pagination-info">Showing 1 to 12 of 12 IOCs</span>
                </div>
              </div>

              {/* Bottom Inspection Card: Horizontal Layout */}
              <div className="dashboard-card iocs-detail-card">
                {/* Header */}
                <div className="ioc-detail-header-row">
                  <div className="ioc-detail-title-group">
                    <span className="ioc-lead-red-icon">
                      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#EF4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="18" cy="5" r="3" />
                        <circle cx="6" cy="12" r="3" />
                        <circle cx="18" cy="19" r="3" />
                        <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
                        <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
                      </svg>
                    </span>
                    <div>
                      <div className="ioc-header-ip-badge-wrap">
                        <h4 className="ioc-detail-ip">185.199.110.43</h4>
                        <span className="badge-rep-malicious">Malicious</span>
                      </div>
                      <span className="ioc-detail-subtitle">Type: IP Address</span>
                    </div>
                  </div>
                  <button type="button" className="btn-close-ioc-detail" title="Close">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <line x1="18" y1="6" x2="6" y2="18" />
                      <line x1="6" y1="6" x2="18" y2="18" />
                    </svg>
                  </button>
                </div>

                {/* Horizontal 3-Column Body */}
                <div className="ioc-detail-horizontal-body">
                  {/* Column 1: Reputation specs */}
                  <div className="ioc-detail-col">
                    <h5 className="ioc-section-title">Reputation</h5>
                    <div className="ioc-kv-list">
                      <div className="ioc-kv-row">
                        <span className="ioc-kv-key">Threat Intelligence</span>
                        <span className="badge-rep-malicious">Malicious</span>
                      </div>
                      <div className="ioc-kv-row">
                        <span className="ioc-kv-key">Confidence</span>
                        <span className="badge-confidence-high">High</span>
                      </div>
                      <div className="ioc-kv-row">
                        <span className="ioc-kv-key">First Seen</span>
                        <span className="ioc-kv-val">Oct 11, 2026, 14:22:10</span>
                      </div>
                      <div className="ioc-kv-row">
                        <span className="ioc-kv-key">Last Seen</span>
                        <span className="ioc-kv-val">Oct 11, 2026, 14:22:45</span>
                      </div>
                      <div className="ioc-kv-row">
                        <span className="ioc-kv-key">Observation Count</span>
                        <span className="ioc-kv-val font-semibold">7</span>
                      </div>
                      <div className="ioc-kv-row">
                        <span className="ioc-kv-key">ASN</span>
                        <span className="ioc-kv-val">AS16276 (OVH SAS)</span>
                      </div>
                      <div className="ioc-kv-row">
                        <span className="ioc-kv-key">Country</span>
                        <span className="ioc-kv-val country-val">
                          <span className="flag-fr">🇫🇷</span> France
                        </span>
                      </div>
                      <div className="ioc-kv-row">
                        <span className="ioc-kv-key">Organization</span>
                        <span className="ioc-kv-val">OVH SAS</span>
                      </div>
                    </div>
                  </div>

                  {/* Column 2: Associated Artifacts */}
                  <div className="ioc-detail-col">
                    <h5 className="ioc-section-title">Associated Artifacts</h5>
                    <div className="ioc-artifacts-list">
                      <div className="ioc-artifact-row">
                        <div className="ioc-art-left">
                          <span className="ioc-art-icon">🌐</span>
                          <span className="ioc-art-name">Domains</span>
                        </div>
                        <div className="ioc-art-right">
                          <span className="ioc-art-count">2</span>
                          <span className="ioc-art-arrow">›</span>
                        </div>
                      </div>

                      <div className="ioc-artifact-row">
                        <div className="ioc-art-left">
                          <span className="ioc-art-icon">🔗</span>
                          <span className="ioc-art-name">URLs</span>
                        </div>
                        <div className="ioc-art-right">
                          <span className="ioc-art-count">1</span>
                          <span className="ioc-art-arrow">›</span>
                        </div>
                      </div>

                      <div className="ioc-artifact-row">
                        <div className="ioc-art-left">
                          <span className="ioc-art-icon">📄</span>
                          <span className="ioc-art-name">Files</span>
                        </div>
                        <div className="ioc-art-right">
                          <span className="ioc-art-count">1</span>
                          <span className="ioc-art-arrow">›</span>
                        </div>
                      </div>

                      <div className="ioc-artifact-row">
                        <div className="ioc-art-left">
                          <span className="ioc-art-icon">⚙️</span>
                          <span className="ioc-art-name">Processes</span>
                        </div>
                        <div className="ioc-art-right">
                          <span className="ioc-art-count">3</span>
                          <span className="ioc-art-arrow">›</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Column 3: Threat Intelligence Sources */}
                  <div className="ioc-detail-col">
                    <h5 className="ioc-section-title">Threat Intelligence Sources</h5>
                    <div className="ioc-ti-sources-list">
                      <div className="ioc-ti-source-row">
                        <div className="ti-source-left">
                          <span className="ti-source-icon text-blue">🛡️</span>
                          <span className="ti-source-name">AlienVault OTX</span>
                        </div>
                        <span className="badge-rep-malicious">Malicious</span>
                      </div>

                      <div className="ioc-ti-source-row">
                        <div className="ti-source-left">
                          <span className="ti-source-icon text-green">🔍</span>
                          <span className="ti-source-name">VirusTotal</span>
                        </div>
                        <span className="badge-vt-score">2 / 89</span>
                      </div>

                      <div className="ioc-ti-source-row">
                        <div className="ti-source-left">
                          <span className="ti-source-icon text-purple">🟣</span>
                          <span className="ti-source-name">AbuseIPDB</span>
                        </div>
                        <span className="badge-rep-malicious">Malicious</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* ===================== RAW EVENTS TAB CONTENT ===================== */}
          {activeTab === 'Raw Events' && (
            <div className="raw-events-tab-layout">
              {/* Left Column: Raw Events Table Card */}
              <div className="dashboard-card raw-events-main-card">
                <div className="raw-header-row">
                  <div className="raw-title-with-desc">
                    <span className="raw-lead-icon">
                      <svg width="22" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                        <polyline points="14 2 14 8 20 8" />
                        <line x1="16" y1="13" x2="8" y2="13" />
                        <line x1="16" y1="17" x2="8" y2="17" />
                        <line x1="10" y1="9" x2="8" y2="9" />
                      </svg>
                    </span>
                    <div className="raw-title-text-wrap">
                      <span className="raw-card-title">Raw Events</span>
                      <span className="raw-card-subtitle">All captured system events during analysis (chronological order).</span>
                    </div>
                  </div>

                  <div className="raw-header-right-tools">
                    <div className="raw-search-box">
                      <span className="raw-search-icon">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <circle cx="11" cy="11" r="8" />
                          <line x1="21" y1="21" x2="16.65" y2="16.65" />
                        </svg>
                      </span>
                      <input
                        type="text"
                        placeholder="Search events..."
                        className="raw-search-input"
                      />
                    </div>

                    <div className="raw-filter-dropdown">
                      <span>All Event Types</span>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="6 9 12 15 18 9" />
                      </svg>
                    </div>
                  </div>
                </div>

                {/* Table */}
                <div className="raw-table-wrapper">
                  <table className="raw-events-data-table">
                    <thead>
                      <tr>
                        <th style={{ width: '40px' }}>#</th>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>Source</th>
                        <th>Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {/* 1 - SELECTED */}
                      <tr className="row-selected-raw">
                        <td className="raw-num-col">1</td>
                        <td className="raw-time-col">14:22:10.123</td>
                        <td className="raw-type-col">process_create</td>
                        <td className="raw-source-col">sysmon</td>
                        <td className="raw-details-col font-medium">sample_malware.exe (PID 4320)</td>
                      </tr>

                      {/* 2 */}
                      <tr>
                        <td className="raw-num-col">2</td>
                        <td className="raw-time-col">14:22:10.245</td>
                        <td className="raw-type-col">file_create</td>
                        <td className="raw-source-col">procmon</td>
                        <td className="raw-details-col font-mono">C:\Users\WDAGUtilityAccount\AppData\Ro...</td>
                      </tr>

                      {/* 3 */}
                      <tr>
                        <td className="raw-num-col">3</td>
                        <td className="raw-time-col">14:22:11.011</td>
                        <td className="raw-type-col">registry_set</td>
                        <td className="raw-source-col">procmon</td>
                        <td className="raw-details-col font-mono">HKCU\Software\Microsoft\Windows\Curr...</td>
                      </tr>

                      {/* 4 */}
                      <tr>
                        <td className="raw-num-col">4</td>
                        <td className="raw-time-col">14:22:11.436</td>
                        <td className="raw-type-col">network_connect</td>
                        <td className="raw-source-col">netmon</td>
                        <td className="raw-details-col font-mono">185.199.110.43:443 (HTTPS)</td>
                      </tr>

                      {/* 5 */}
                      <tr>
                        <td className="raw-num-col">5</td>
                        <td className="raw-time-col">14:22:12.089</td>
                        <td className="raw-type-col">dns_query</td>
                        <td className="raw-source-col">dnscap</td>
                        <td className="raw-details-col">api.example.com (A)</td>
                      </tr>

                      {/* 6 */}
                      <tr>
                        <td className="raw-num-col">6</td>
                        <td className="raw-time-col">14:22:12.412</td>
                        <td className="raw-type-col">file_write</td>
                        <td className="raw-source-col">procmon</td>
                        <td className="raw-details-col font-mono">C:\Windows\Temp\payload.dll</td>
                      </tr>

                      {/* 7 */}
                      <tr>
                        <td className="raw-num-col">7</td>
                        <td className="raw-time-col">14:22:13.005</td>
                        <td className="raw-type-col">module_load</td>
                        <td className="raw-source-col">sysmon</td>
                        <td className="raw-details-col font-mono">payload.dll (0x7ffb2a000000)</td>
                      </tr>

                      {/* 8 */}
                      <tr>
                        <td className="raw-num-col">8</td>
                        <td className="raw-time-col">14:22:13.521</td>
                        <td className="raw-type-col">process_create</td>
                        <td className="raw-source-col">sysmon</td>
                        <td className="raw-details-col">powershell.exe (PID 7260)</td>
                      </tr>

                      {/* 9 */}
                      <tr>
                        <td className="raw-num-col">9</td>
                        <td className="raw-time-col">14:22:13.998</td>
                        <td className="raw-type-col">file_create</td>
                        <td className="raw-source-col">procmon</td>
                        <td className="raw-details-col font-mono">C:\Users\WDAGUtilityAccount\AppData\Lo...</td>
                      </tr>

                      {/* 10 */}
                      <tr>
                        <td className="raw-num-col">10</td>
                        <td className="raw-time-col">14:22:14.662</td>
                        <td className="raw-type-col">network_connect</td>
                        <td className="raw-source-col">netmon</td>
                        <td className="raw-details-col font-mono">91.213.21.34:53 (DNS)</td>
                      </tr>

                      {/* 11 */}
                      <tr>
                        <td className="raw-num-col">11</td>
                        <td className="raw-time-col">14:22:15.210</td>
                        <td className="raw-type-col">registry_set</td>
                        <td className="raw-source-col">procmon</td>
                        <td className="raw-details-col font-mono">HKCU\Software\Microsoft\Windows\Curr...</td>
                      </tr>

                      {/* 12 */}
                      <tr>
                        <td className="raw-num-col">12</td>
                        <td className="raw-time-col">14:22:16.334</td>
                        <td className="raw-type-col">process_terminate</td>
                        <td className="raw-source-col">sysmon</td>
                        <td className="raw-details-col font-medium">sample_malware.exe (PID 4320)</td>
                      </tr>
                    </tbody>
                  </table>
                </div>

                {/* Pagination */}
                <div className="raw-pagination-footer">
                  <span className="raw-pagination-info">Showing 1 to 12 of 342 events</span>
                  <div className="raw-pagination-controls">
                    <button type="button" className="btn-page-arrow" disabled>
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="15 18 9 12 15 6" />
                      </svg>
                    </button>
                    <button type="button" className="btn-page-number active">1</button>
                    <button type="button" className="btn-page-number">2</button>
                    <button type="button" className="btn-page-number">3</button>
                    <button type="button" className="btn-page-number">4</button>
                    <button type="button" className="btn-page-number">5</button>
                    <span className="page-ellipsis">...</span>
                    <button type="button" className="btn-page-number">29</button>
                    <button type="button" className="btn-page-arrow">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>

              {/* Right Column: Event Details & JSON Card */}
              <div className="raw-right-widgets-col">
                {/* 1. Event Details Card */}
                <div className="dashboard-card raw-detail-card">
                  <div className="raw-detail-header">
                    <div className="raw-detail-title-group">
                      <span className="raw-header-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
                          <line x1="8" y1="21" x2="16" y2="21" />
                          <line x1="12" y1="17" x2="12" y2="21" />
                        </svg>
                      </span>
                      <h4 className="raw-detail-title">Event Details</h4>
                    </div>
                    <button type="button" className="btn-close-raw-detail" title="Close">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <line x1="18" y1="6" x2="6" y2="18" />
                        <line x1="6" y1="6" x2="18" y2="18" />
                      </svg>
                    </button>
                  </div>

                  <div className="raw-kv-list">
                    <div className="raw-kv-row">
                      <span className="raw-kv-key">Event Type</span>
                      <span className="badge-event-type">process_create</span>
                    </div>
                    <div className="raw-kv-row">
                      <span className="raw-kv-key">Timestamp</span>
                      <span className="raw-kv-val">Oct 11, 2026, 14:22:10.123</span>
                    </div>
                    <div className="raw-kv-row">
                      <span className="raw-kv-key">Source</span>
                      <span className="raw-kv-val">sysmon</span>
                    </div>
                    <div className="raw-kv-row">
                      <span className="raw-kv-key">Event ID</span>
                      <span className="raw-kv-val">1</span>
                    </div>
                    <div className="raw-kv-row">
                      <span className="raw-kv-key">Process</span>
                      <span className="raw-kv-val">sample_malware.exe (PID 4320)</span>
                    </div>
                    <div className="raw-kv-row">
                      <span className="raw-kv-key">User</span>
                      <span className="raw-kv-val">WDAGUtilityAccount</span>
                    </div>
                    <div className="raw-kv-row align-start">
                      <span className="raw-kv-key">Command Line</span>
                      <div className="raw-cmd-box">
                        <span>"C:\Users\WDAGUtilityAccount\Desktop\sample_malware.exe"</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 2. Raw Event Data (JSON) Card */}
                <div className="dashboard-card raw-json-card">
                  <div className="raw-json-header">
                    <div className="raw-detail-title-group">
                      <span className="raw-header-icon">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                          <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                          <polyline points="14 2 14 8 20 8" />
                        </svg>
                      </span>
                      <h4 className="raw-detail-title">Raw Event Data (JSON)</h4>
                    </div>
                    <button type="button" className="btn-copy-raw-json" title="Copy JSON">
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                      </svg>
                    </button>
                  </div>

                  {/* JSON Code Viewer with Syntax Coloring */}
                  <div className="raw-json-viewer-container">
                    <pre className="raw-json-pre">
                      <code>
                        {sample.rawJson || `{
  "event_id": 1,
  "timestamp": "2026-10-11T14:22:10.123Z",
  "event_type": "process_create",
  "source": "sysmon",
  "process": {
    "pid": 4320,
    "name": "${sample.fileName}",
    "path": "C:\\\\ThreatBox\\\\sample\\\\${sample.fileName}",
    "command_line": "C:\\\\ThreatBox\\\\sample\\\\${sample.fileName}",
    "parent_pid": 3216,
    "parent_name": "explorer.exe",
    "user": "WDAGUtilityAccount"
  },
  "hashes": {
    "sha256": "${sample.sha256}"
  }
}`}
                      </code>
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Placeholder for other tabs (e.g. Registry) */}
          {activeTab !== 'Overview' && activeTab !== 'Behavior' && activeTab !== 'Processes' && activeTab !== 'File System' && activeTab !== 'Network' && activeTab !== 'DNS' && activeTab !== 'Modules' && activeTab !== 'MITRE ATT&CK' && activeTab !== 'IOCs' && activeTab !== 'Raw Events' && (
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
