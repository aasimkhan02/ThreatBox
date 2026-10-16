import React, { useState } from 'react'
import './history.css'
import Sidebar from '../layout/Sidebar'

const History = ({
  onNavigateHome,
  onNavigateUpload,
  onNavigateDashboard,
  onSelectSample
}) => {
  const [activeFilter, setActiveFilter] = useState('All')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedIds, setSelectedIds] = useState([])
  const [currentPageNum, setCurrentPageNum] = useState(1)

  // Full dataset matching screenshot exactly
  const allAnalyses = [
    {
      id: 1,
      fileName: 'sample_malware.exe',
      hash: '37a8e5c6b0d3e9f72ca9d6e17...',
      score: 92,
      scoreType: 'malicious',
      status: 'Malicious',
      statusClass: 'badge-status-malicious',
      fileType: 'PE32+ (EXE)',
      fileSize: '412 KB',
      submittedDate: 'Oct 11, 2026 · 14:22',
      duration: '2m 34s'
    },
    {
      id: 2,
      fileName: 'invoice.pdf.exe',
      hash: 'a92c8d3e1f4b7c6d9e0a2b1c...',
      score: 67,
      scoreType: 'suspicious',
      status: 'Suspicious',
      statusClass: 'badge-status-suspicious',
      fileType: 'PE32 (EXE)',
      fileSize: '1.8 MB',
      submittedDate: 'Oct 10, 2026 · 09:18',
      duration: '1m 12s'
    },
    {
      id: 3,
      fileName: 'setup.exe',
      hash: 'b1f3e5d9c7a8e2d4f6b9c0a1...',
      score: 8,
      scoreType: 'clean',
      status: 'Clean',
      statusClass: 'badge-status-clean',
      fileType: 'PE32 (EXE)',
      fileSize: '2.1 MB',
      submittedDate: 'Oct 09, 2026 · 22:41',
      duration: '1m 05s'
    },
    {
      id: 4,
      fileName: 'unknown.bin',
      hash: 'e4d9a7c1b8f3e6d0a9c2b5f7...',
      score: '-',
      scoreType: 'failed',
      status: 'Failed',
      statusClass: 'badge-status-failed',
      fileType: 'Binary',
      fileSize: '3.4 MB',
      submittedDate: 'Oct 08, 2026 · 16:07',
      duration: '-'
    },
    {
      id: 5,
      fileName: 'payload.dll',
      hash: 'c6b2d9f4a1e8c3d7b0f5a9e2...',
      score: 88,
      scoreType: 'malicious',
      status: 'Malicious',
      statusClass: 'badge-status-malicious',
      fileType: 'DLL',
      fileSize: '120 KB',
      submittedDate: 'Oct 07, 2026 · 11:33',
      duration: '2m 11s'
    },
    {
      id: 6,
      fileName: 'config.dat',
      hash: 'f9e2c1a7d4b8c6e0f3a9d5b1...',
      score: 54,
      scoreType: 'suspicious',
      status: 'Suspicious',
      statusClass: 'badge-status-suspicious',
      fileType: 'DAT',
      fileSize: '4 KB',
      submittedDate: 'Oct 06, 2026 · 18:20',
      duration: '1m 09s'
    },
    {
      id: 7,
      fileName: 'document.docm',
      hash: 'd2f7a9c3e1b8d4f6c0a5e9d2...',
      score: 61,
      scoreType: 'suspicious',
      status: 'Suspicious',
      statusClass: 'badge-status-suspicious',
      fileType: 'DOCM',
      fileSize: '310 KB',
      submittedDate: 'Oct 05, 2026 · 13:14',
      duration: '1m 47s'
    },
    {
      id: 8,
      fileName: 'tool.ps1',
      hash: 'a7e1c9d2f5b8a3e6d4c0f9b1...',
      score: 12,
      scoreType: 'clean',
      status: 'Clean',
      statusClass: 'badge-status-clean',
      fileType: 'PowerShell',
      fileSize: '9 KB',
      submittedDate: 'Oct 04, 2026 · 10:03',
      duration: '56s'
    },
    {
      id: 9,
      fileName: 'archive.zip',
      hash: 'c9d3e1a6b7f2c8d5e0a4f9b1...',
      score: 49,
      scoreType: 'suspicious',
      status: 'Suspicious',
      statusClass: 'badge-status-suspicious',
      fileType: 'ZIP',
      fileSize: '2.6 MB',
      submittedDate: 'Oct 03, 2026 · 21:10',
      duration: '1m 23s'
    },
    {
      id: 10,
      fileName: 'driver.sys',
      hash: 'e8a4c1d9b7f3e6a0c5d2b9f7...',
      score: 76,
      scoreType: 'malicious',
      status: 'Malicious',
      statusClass: 'badge-status-malicious',
      fileType: 'SYS',
      fileSize: '640 KB',
      submittedDate: 'Oct 02, 2026 · 17:55',
      duration: '1m 58s'
    }
  ]

  const filters = ['All', 'Malicious', 'Suspicious', 'Clean', 'Completed', 'Failed']

  const handleSelectAll = (e) => {
    if (e.target.checked) {
      setSelectedIds(allAnalyses.map((item) => item.id))
    } else {
      setSelectedIds([])
    }
  }

  const handleToggleSelect = (id) => {
    if (selectedIds.includes(id)) {
      setSelectedIds(selectedIds.filter((item) => item !== id))
    } else {
      setSelectedIds([...selectedIds, id])
    }
  }

  const handleRowClick = (item) => {
    if (onSelectSample) {
      onSelectSample(item)
    } else if (onNavigateDashboard) {
      onNavigateDashboard()
    }
  }

  // Helper to render circular ring progress indicator for threat score
  const renderScoreRing = (score, type) => {
    if (type === 'failed') {
      return (
        <svg width="20" height="20" viewBox="0 0 24 24">
          <circle cx="12" cy="12" r="9" fill="none" stroke="#D1D5DB" strokeWidth="2.5" />
          <line x1="8" y1="12" x2="16" y2="12" stroke="#9CA3AF" strokeWidth="2" strokeLinecap="round" />
        </svg>
      )
    }

    let strokeColor = '#10B981' // clean
    if (type === 'malicious') strokeColor = '#EF4444'
    if (type === 'suspicious') strokeColor = '#F59E0B'

    const radius = 9
    const circumference = 2 * Math.PI * radius
    const progressOffset = circumference - (score / 100) * circumference

    return (
      <svg width="20" height="20" viewBox="0 0 24 24" style={{ transform: 'rotate(-90deg)' }}>
        {/* Background track */}
        <circle cx="12" cy="12" r={radius} fill="none" stroke="#EAEAEA" strokeWidth="2.5" />
        {/* Colored progress arc */}
        <circle
          cx="12"
          cy="12"
          r={radius}
          fill="none"
          stroke={strokeColor}
          strokeWidth="2.5"
          strokeDasharray={circumference}
          strokeDashoffset={progressOffset}
          strokeLinecap="round"
        />
      </svg>
    )
  }

  // Filter items based on activeFilter and searchQuery
  const filteredAnalyses = allAnalyses.filter((item) => {
    const matchesFilter =
      activeFilter === 'All' ||
      item.status.toLowerCase() === activeFilter.toLowerCase()
    const matchesSearch =
      searchQuery === '' ||
      item.fileName.toLowerCase().includes(searchQuery.toLowerCase()) ||
      item.hash.toLowerCase().includes(searchQuery.toLowerCase())
    return matchesFilter && matchesSearch
  })

  return (
    <div className="history-layout">
      {/* ---------------- Sidebar with Analysis History active ---------------- */}
      <Sidebar
        activeTab="analysis-history"
        onNavigate={(tab) => {
          if (tab === 'dashboard') onNavigateDashboard && onNavigateDashboard()
          else if (tab === 'new-analysis') onNavigateUpload && onNavigateUpload()
        }}
        onNavigateHome={onNavigateHome}
      />

      {/* ---------------- Main Content Area ---------------- */}
      <div className="history-main-area">
        {/* Top Header Bar */}
        <header className="history-topbar">
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
              />
            </div>

            <div className="user-avatar-circle" title="User Profile">
              <span>M</span>
            </div>
          </div>
        </header>

        {/* Content Body */}
        <main className="history-content-body">
          {/* Header Title & Subtitle */}
          <div className="history-view-header">
            <span className="history-eyebrow">History</span>
            <h1 className="history-title">Analysis History</h1>
            <p className="history-desc">
              Browse and manage all previously analyzed files. View results, download reports, or rerun analyses.
            </p>
          </div>

          {/* Filter Pills + Right Toolbar (Date filter & Search) */}
          <div className="history-controls-bar">
            {/* Filter Pills */}
            <div className="filter-pills-group">
              {filters.map((filter) => (
                <button
                  key={filter}
                  type="button"
                  className={`filter-pill-btn ${activeFilter === filter ? 'active' : ''}`}
                  onClick={() => setActiveFilter(filter)}
                >
                  {filter}
                </button>
              ))}
            </div>

            {/* Right Tools */}
            <div className="history-right-tools">
              {/* Date Filter Dropdown */}
              <div className="date-filter-dropdown">
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
                  <line x1="16" y1="2" x2="16" y2="6" />
                  <line x1="8" y1="2" x2="8" y2="6" />
                  <line x1="3" y1="10" x2="21" y2="10" />
                </svg>
                <span>Last 30 days</span>
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="6 9 12 15 18 9" />
                </svg>
              </div>

              {/* Table search input */}
              <div className="table-search-input-wrapper">
                <span className="table-search-icon">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="11" cy="11" r="8" />
                    <line x1="21" y1="21" x2="16.65" y2="16.65" />
                  </svg>
                </span>
                <input
                  type="text"
                  placeholder="Search by filename, hash..."
                  className="table-search-input"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>
            </div>
          </div>

          {/* Data Table Card */}
          <div className="history-table-card">
            <table className="history-table">
              <thead>
                <tr>
                  <th className="th-checkbox">
                    <input
                      type="checkbox"
                      className="custom-table-checkbox"
                      onChange={handleSelectAll}
                      checked={selectedIds.length === allAnalyses.length}
                    />
                  </th>
                  <th>File Name</th>
                  <th>Threat Score</th>
                  <th>Status</th>
                  <th>File Type</th>
                  <th>File Size</th>
                  <th>Submitted</th>
                  <th className="th-actions">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredAnalyses.map((item) => (
                  <tr key={item.id}>
                    {/* Checkbox */}
                    <td className="td-checkbox">
                      <input
                        type="checkbox"
                        className="custom-table-checkbox"
                        checked={selectedIds.includes(item.id)}
                        onChange={() => handleToggleSelect(item.id)}
                      />
                    </td>

                    {/* File Name & Hash */}
                    <td>
                      <div className="td-filename-group">
                        <span className="table-file-doc-icon">
                          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                          </svg>
                        </span>
                        <div className="table-file-text-col">
                          <span
                            className="file-name-strong"
                            onClick={() => handleRowClick(item)}
                          >
                            {item.fileName}
                          </span>
                          <span className="file-hash-sub">{item.hash}</span>
                        </div>
                      </div>
                    </td>

                    {/* Threat Score with Circular Ring Indicator */}
                    <td>
                      <div className="score-cell-flex">
                        <span className="mini-score-ring">
                          {renderScoreRing(item.score, item.scoreType)}
                        </span>
                        <span className="score-num-bold">{item.score}</span>
                      </div>
                    </td>

                    {/* Status Pill */}
                    <td>
                      <span className={`status-pill-badge ${item.statusClass}`}>
                        {item.status}
                      </span>
                    </td>

                    {/* File Type */}
                    <td>{item.fileType}</td>

                    {/* File Size */}
                    <td>{item.fileSize}</td>

                    {/* Submitted Date & Duration */}
                    <td>
                      <div className="td-submitted-col">
                        <span className="sub-date-text">{item.submittedDate}</span>
                        <span className="sub-duration-sub">{item.duration}</span>
                      </div>
                    </td>

                    {/* Actions: View Report, Download, Rerun, More */}
                    <td className="td-actions">
                      <div className="row-actions-group">
                        {/* View Report */}
                        <button
                          type="button"
                          className="action-icon-btn"
                          title="View Report"
                          onClick={() => handleRowClick(item)}
                        >
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                            <polyline points="14 2 14 8 20 8" />
                            <line x1="16" y1="13" x2="8" y2="13" />
                            <line x1="16" y1="17" x2="8" y2="17" />
                            <polyline points="10 9 9 9 8 9" />
                          </svg>
                        </button>

                        {/* Download Report */}
                        <button
                          type="button"
                          className="action-icon-btn"
                          title="Download Report"
                        >
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                            <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                            <polyline points="7 10 12 15 17 10" />
                            <line x1="12" y1="15" x2="12" y2="3" />
                          </svg>
                        </button>

                        {/* Rerun Analysis */}
                        <button
                          type="button"
                          className="action-icon-btn"
                          title="Rerun Analysis"
                        >
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                            <polygon points="5 3 19 12 5 21 5 3" />
                          </svg>
                        </button>

                        {/* More options menu */}
                        <button
                          type="button"
                          className="action-icon-btn"
                          title="More Options"
                        >
                          <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                            <circle cx="12" cy="12" r="1.5" />
                            <circle cx="12" cy="5" r="1.5" />
                            <circle cx="12" cy="19" r="1.5" />
                          </svg>
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination Footer */}
          <div className="history-pagination-footer">
            <span className="pagination-counter">Showing 1 to 10 of 42 analyses</span>

            <div className="pagination-controls">
              <button
                type="button"
                className="page-num-btn"
                title="Previous Page"
                onClick={() => setCurrentPageNum((p) => Math.max(1, p - 1))}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="15 18 9 12 15 6" />
                </svg>
              </button>

              <button
                type="button"
                className={`page-num-btn ${currentPageNum === 1 ? 'active' : ''}`}
                onClick={() => setCurrentPageNum(1)}
              >
                1
              </button>
              <button
                type="button"
                className={`page-num-btn ${currentPageNum === 2 ? 'active' : ''}`}
                onClick={() => setCurrentPageNum(2)}
              >
                2
              </button>
              <button
                type="button"
                className={`page-num-btn ${currentPageNum === 3 ? 'active' : ''}`}
                onClick={() => setCurrentPageNum(3)}
              >
                3
              </button>
              <button
                type="button"
                className={`page-num-btn ${currentPageNum === 4 ? 'active' : ''}`}
                onClick={() => setCurrentPageNum(4)}
              >
                4
              </button>
              <button
                type="button"
                className={`page-num-btn ${currentPageNum === 5 ? 'active' : ''}`}
                onClick={() => setCurrentPageNum(5)}
              >
                5
              </button>

              <button
                type="button"
                className="page-num-btn"
                title="Next Page"
                onClick={() => setCurrentPageNum((p) => Math.min(5, p + 1))}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="9 18 15 12 9 6" />
                </svg>
              </button>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}

export default History
