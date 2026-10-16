import React, { useState, useRef } from 'react'
import './upload.css'
import Sidebar from '../layout/Sidebar'

const Upload = ({
  onNavigateHome,
  onSelectSample,
  onNavigateDashboard,
  onNavigateHistory
}) => {
  const [activeNavTab, setActiveNavTab] = useState('new-analysis')
  const [isDragging, setIsDragging] = useState(false)
  const [selectedFile, setSelectedFile] = useState(null)
  const [searchQuery, setSearchQuery] = useState('')
  const fileInputRef = useRef(null)

  // Toggle options state
  const [options, setOptions] = useState({
    networkMonitoring: true,
    registryMonitoring: true,
    fileSystemTracking: true,
    processMonitoring: true,
    generateReport: true,
    mapMitre: true,
    saveSample: false
  })

  const toggleOption = (key) => {
    setOptions((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  // Exact data from screenshot
  const recentAnalyses = [
    {
      id: 1,
      fileName: 'sample_malware.exe',
      fileType: 'PE32+ (EXE)',
      submitted: 'Oct 11, 2026, 14:22',
      status: 'Malicious',
      statusClass: 'status-badge-malicious',
      score: 92,
      scoreClass: 'score-malicious'
    },
    {
      id: 2,
      fileName: 'invoice.pdf.exe',
      fileType: 'PE32 (EXE)',
      submitted: 'Oct 10, 2026, 09:18',
      status: 'Suspicious',
      statusClass: 'status-badge-suspicious',
      score: 67,
      scoreClass: 'score-suspicious'
    },
    {
      id: 3,
      fileName: 'setup.exe',
      fileType: 'PE32 (EXE)',
      submitted: 'Oct 09, 2026, 22:41',
      status: 'Clean',
      statusClass: 'status-badge-clean',
      score: 8,
      scoreClass: 'score-clean'
    },
    {
      id: 4,
      fileName: 'unknown.bin',
      fileType: 'Binary',
      submitted: 'Oct 08, 2026, 16:07',
      status: 'Completed',
      statusClass: 'status-badge-completed',
      score: '-',
      scoreClass: 'score-none'
    }
  ]

  const handleDragOver = (e) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const handleDragLeave = () => {
    setIsDragging(false)
  }

  const handleDrop = (e) => {
    e.preventDefault()
    setIsDragging(false)
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setSelectedFile(e.dataTransfer.files[0])
    }
  }

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setSelectedFile(e.target.files[0])
    }
  }

  const handleBrowseClick = () => {
    fileInputRef.current?.click()
  }

  return (
    <div className="app-dashboard-layout">
      {/* ---------------- 1. Separate Sidebar Component ---------------- */}
      <Sidebar
        activeTab={activeNavTab}
        onNavigate={(tab) => {
          setActiveNavTab(tab)
          if ((tab === 'analyses' || tab === 'dashboard') && onNavigateDashboard) {
            onNavigateDashboard()
          } else if ((tab === 'analysis-history' || tab === 'history') && onNavigateHistory) {
            onNavigateHistory()
          }
        }}
        onNavigateHome={onNavigateHome}
      />

      {/* ---------------- 2. Main Dashboard Area ---------------- */}
      <div className="dashboard-main-area">
        {/* Top Header Bar: Search input + User Avatar */}
        <header className="dashboard-topbar">
          <div className="topbar-right-controls">
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

        {/* Content Body */}
        <div className="upload-content-body">
          {/* Header Title & Subtitle */}
          <div className="upload-view-header">
            <span className="upload-view-eyebrow">New Analysis</span>
            <h1 className="upload-view-title">Analyze a File</h1>
            <p className="upload-view-desc">
              Upload a suspicious file to run it inside a secure Windows Sandbox environment. ThreatBox will collect telemetry, analyze its behavior, and map it to MITRE ATT&amp;CK techniques.
            </p>
          </div>

          {/* Main Workspace Card: Drop Area (Left) + Analysis Options (Right) */}
          <div className="upload-workspace-grid">
            {/* Left: Drop Zone */}
            <div
              className={`upload-dropzone-box ${isDragging ? 'dragging' : ''}`}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              onClick={handleBrowseClick}
            >
              <input
                type="file"
                ref={fileInputRef}
                className="hidden-file-input"
                onChange={handleFileChange}
              />

              <div className="drop-icon-wrapper">
                <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                  <polyline points="14 2 14 8 20 8" />
                  <polyline points="9 15 12 12 15 15" />
                  <line x1="12" y1="12" x2="12" y2="20" />
                </svg>
              </div>

              <h2 className="drop-primary-heading">Drop your file here</h2>
              <p className="drop-secondary-subtext">or click to browse</p>

              <div className="drop-formats-mono">
                EXE, DLL, SCR, ZIP, RAR, 7Z, ISO<br />
                (MAX 500 MB)
              </div>

              {selectedFile ? (
                <div className="selected-file-indicator">
                  <span>Selected: {selectedFile.name}</span>
                </div>
              ) : null}

              <div className="drop-choose-pill" onClick={handleBrowseClick}>
                <span className="choose-pill-text">Choose File</span>
                <span className="choose-pill-sep"></span>
                <span className="choose-pill-icon">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z" />
                  </svg>
                </span>
              </div>
            </div>

            {/* Right: Analysis Options Column */}
            <div className="upload-options-column">
              <div>
                <h3 className="options-group-title">Analysis Options</h3>

                {/* Environment Card */}
                <div className="environment-box">
                  <div className="env-info-left">
                    <span className="env-title">Environment</span>
                    <span className="env-subtitle">
                      Runs in a clean Windows Sandbox with network and process monitoring enabled.
                    </span>
                  </div>

                  <div className="env-badge-right">
                    <div className="windows-logo-icon">
                      <svg width="22" height="22" viewBox="0 0 88 88" fill="currentColor">
                        <path d="M0 12.402l35.689-4.86v35.031H0V12.402zm0 37.375h35.689v35.056L0 79.972V49.777zm40.548-35.702L87.994 0v42.573H40.548V14.075zm47.446 35.702L40.548 49.777v28.513l47.446 6.643V49.777z"/>
                      </svg>
                    </div>
                    <div className="env-badge-text">
                      <span className="env-badge-name">Windows Sandbox</span>
                      <span className="env-badge-sub">Isolated Execution</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Toggles List */}
              <div className="toggle-rows-list">
                {/* Network Monitoring */}
                <div className="toggle-row-item">
                  <div className="toggle-item-left">
                    <span className="toggle-item-icon">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />
                      </svg>
                    </span>
                    <div className="toggle-item-text">
                      <span className="toggle-item-name">Network Monitoring</span>
                      <span className="toggle-item-desc">Capture DNS, HTTP(S) and outbound connections</span>
                    </div>
                  </div>
                  <label className="switch-label">
                    <input
                      type="checkbox"
                      checked={options.networkMonitoring}
                      onChange={() => toggleOption('networkMonitoring')}
                    />
                    <span className="switch-slider"></span>
                  </label>
                </div>

                {/* Registry Monitoring */}
                <div className="toggle-row-item">
                  <div className="toggle-item-left">
                    <span className="toggle-item-icon">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="3" y="3" width="7" height="7" />
                        <rect x="14" y="3" width="7" height="7" />
                        <rect x="14" y="14" width="7" height="7" />
                        <rect x="3" y="14" width="7" height="7" />
                      </svg>
                    </span>
                    <div className="toggle-item-text">
                      <span className="toggle-item-name">Registry Monitoring</span>
                      <span className="toggle-item-desc">Track registry changes and persistence</span>
                    </div>
                  </div>
                  <label className="switch-label">
                    <input
                      type="checkbox"
                      checked={options.registryMonitoring}
                      onChange={() => toggleOption('registryMonitoring')}
                    />
                    <span className="switch-slider"></span>
                  </label>
                </div>

                {/* File System Tracking */}
                <div className="toggle-row-item">
                  <div className="toggle-item-left">
                    <span className="toggle-item-icon">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M4 20h16a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.93a2 2 0 0 1-1.66-.9l-.82-1.2A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13c0 1.1.9 2 2 2Z" />
                      </svg>
                    </span>
                    <div className="toggle-item-text">
                      <span className="toggle-item-name">File System Tracking</span>
                      <span className="toggle-item-desc">Monitor file creation, modification and drops</span>
                    </div>
                  </div>
                  <label className="switch-label">
                    <input
                      type="checkbox"
                      checked={options.fileSystemTracking}
                      onChange={() => toggleOption('fileSystemTracking')}
                    />
                    <span className="switch-slider"></span>
                  </label>
                </div>

                {/* Process Monitoring */}
                <div className="toggle-row-item">
                  <div className="toggle-item-left">
                    <span className="toggle-item-icon">
                      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                        <polyline points="7 10 12 15 17 10" />
                        <line x1="12" y1="15" x2="12" y2="3" />
                        <rect x="4" y="19" width="16" height="2" rx="1" />
                      </svg>
                    </span>
                    <div className="toggle-item-text">
                      <span className="toggle-item-name">Process Monitoring</span>
                      <span className="toggle-item-desc">Capture spawned processes and command lines</span>
                    </div>
                  </div>
                  <label className="switch-label">
                    <input
                      type="checkbox"
                      checked={options.processMonitoring}
                      onChange={() => toggleOption('processMonitoring')}
                    />
                    <span className="switch-slider"></span>
                  </label>
                </div>
              </div>

              {/* Additional Options Checkboxes */}
              <div className="additional-options-group">
                <h4 className="options-group-title" style={{ margin: 0 }}>Additional Options</h4>

                <label className="custom-checkbox-row">
                  <input
                    type="checkbox"
                    checked={options.generateReport}
                    onChange={() => toggleOption('generateReport')}
                  />
                  <span>Generate detailed report</span>
                </label>

                <label className="custom-checkbox-row">
                  <input
                    type="checkbox"
                    checked={options.mapMitre}
                    onChange={() => toggleOption('mapMitre')}
                  />
                  <span>Map to MITRE ATT&amp;CK techniques</span>
                </label>

                <label className="custom-checkbox-row">
                  <input
                    type="checkbox"
                    checked={options.saveSample}
                    onChange={() => toggleOption('saveSample')}
                  />
                  <span>Save sample for future reference</span>
                </label>
              </div>
            </div>
          </div>

          {/* Bottom Table: Recent Analyses */}
          <section className="dashboard-recent-section">
            <div className="recent-analyses-header">
              <h3 className="recent-title-text">Recent Analyses</h3>
              <button
                type="button"
                className="recent-link-viewall"
                onClick={onNavigateHistory}
              >
                <span>View all</span>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="5" y1="12" x2="19" y2="12" />
                  <polyline points="12 5 19 12 12 19" />
                </svg>
              </button>
            </div>

            <div className="table-card-wrapper">
              <table className="analyses-table">
                <thead>
                  <tr>
                    <th>File Name</th>
                    <th>File Type</th>
                    <th>Submitted</th>
                    <th>Status</th>
                    <th>Threat Score</th>
                    <th className="th-action">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAnalyses.map((item) => (
                    <tr key={item.id}>
                      {/* File Name */}
                      <td>
                        <div className="td-file-cell">
                          <span className="table-file-icon">
                            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                              <polyline points="14 2 14 8 20 8" />
                              <line x1="16" y1="13" x2="8" y2="13" />
                              <line x1="16" y1="17" x2="8" y2="17" />
                              <line x1="10" y1="9" x2="8" y2="9" />
                            </svg>
                          </span>
                          <span>{item.fileName}</span>
                        </div>
                      </td>

                      {/* File Type */}
                      <td>{item.fileType}</td>

                      {/* Submitted */}
                      <td>{item.submitted}</td>

                      {/* Status */}
                      <td>
                        <span className={`table-status-pill ${item.statusClass}`}>
                          {item.status}
                        </span>
                      </td>

                      {/* Threat Score */}
                      <td>
                        <span className={item.scoreClass}>{item.score}</span>
                      </td>

                      {/* Actions */}
                      <td className="td-action-cell">
                        <button
                          type="button"
                          className="btn-table-view-report"
                          onClick={() => onSelectSample && onSelectSample(item)}
                        >
                          <span>View Report</span>
                          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                            <line x1="5" y1="12" x2="19" y2="12" />
                            <polyline points="12 5 19 12 12 19" />
                          </svg>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </div>
    </div>
  )
}

export default Upload
