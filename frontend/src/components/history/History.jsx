import React, { useState, useEffect, useRef } from 'react'
import './history.css'
import Sidebar from '../layout/Sidebar'
import { getJobs, getJobDetails } from '../../api/client'
import { formatBytes } from '../../utils/formatAnalysis'

const History = ({
  onNavigateHome,
  onNavigateUpload,
  onNavigateDashboard,
  onSelectSample,
  onNavigateTab
}) => {
  const [rawJobs, setRawJobs] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState(null)

  const [activeFilter, setActiveFilter] = useState('All')
  const [dateFilter, setDateFilter] = useState('All Time')
  const [isDateDropdownOpen, setIsDateDropdownOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedIds, setSelectedIds] = useState([])
  const [currentPageNum, setCurrentPageNum] = useState(1)

  const dateDropdownRef = useRef(null)
  const pageSize = 10
  const dateOptions = ['All Time', 'Today', 'Last 7 days', 'Last 30 days']
  const filters = ['All', 'Malicious', 'Suspicious', 'Clean', 'Completed', 'Failed']

  // Close date dropdown on outside click
  useEffect(() => {
    const handleOutsideClick = (e) => {
      if (dateDropdownRef.current && !dateDropdownRef.current.contains(e.target)) {
        setIsDateDropdownOpen(false)
      }
    }
    document.addEventListener('mousedown', handleOutsideClick)
    return () => document.removeEventListener('mousedown', handleOutsideClick)
  }, [])

  // Fetch all jobs from backend
  const fetchAnalyses = async (isManual = false) => {
    if (isManual) {
      setRefreshing(true)
    } else {
      setLoading(true)
    }
    setError(null)

    try {
      const data = await getJobs()
      setRawJobs(Array.isArray(data) ? data : [])
    } catch (err) {
      console.error('Failed to load analysis history:', err)
      setError(err.message || 'Failed to connect to backend server')
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchAnalyses()
  }, [])

  // Helper to derive human-readable file type from filename
  const getFileType = (filename) => {
    if (!filename) return 'Binary File'
    const lower = filename.toLowerCase()
    if (lower.endsWith('.dll')) return 'Dynamic Link Library (DLL)'
    if (lower.endsWith('.exe')) return 'PE32+ (EXE)'
    if (lower.endsWith('.sys')) return 'System Driver (SYS)'
    if (lower.endsWith('.ps1')) return 'PowerShell Script'
    if (lower.endsWith('.bat') || lower.endsWith('.cmd')) return 'Batch Script'
    if (lower.endsWith('.zip')) return 'ZIP Archive'
    if (lower.endsWith('.docm') || lower.endsWith('.docx')) return 'Word Document'
    if (lower.endsWith('.pdf')) return 'PDF Document'
    return 'Binary File'
  }

  // Helper to format date cleanly
  const formatSubmittedDate = (dateStr) => {
    if (!dateStr) return 'Not available'
    const date = new Date(dateStr)
    if (isNaN(date.getTime())) return 'Not available'
    return (
      date.toLocaleDateString('en-US', {
        month: 'short',
        day: '2-digit',
        year: 'numeric'
      }) +
      ' · ' +
      date.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
      })
    )
  }

  // Helper to calculate execution duration
  const formatDuration = (startedAt, completedAt) => {
    if (!startedAt || !completedAt) return '-'
    const start = new Date(startedAt).getTime()
    const end = new Date(completedAt).getTime()
    if (isNaN(start) || isNaN(end) || end < start) return '-'
    const diffSecs = Math.round((end - start) / 1000)
    if (diffSecs < 60) return `${diffSecs}s`
    const mins = Math.floor(diffSecs / 60)
    const remSecs = diffSecs % 60
    return `${mins}m ${remSecs}s`
  }

  // Transform raw backend jobs into UI presentation structures
  const allAnalyses = rawJobs.map((job) => {
    const statusLower = (job.status || '').toLowerCase()
    const score = job.score

    let status = 'Clean'
    let statusClass = 'badge-status-clean'
    let scoreDisplay = score != null ? score : '-'
    let scoreType = 'clean'

    if (statusLower === 'failed') {
      status = 'Failed'
      statusClass = 'badge-status-failed'
      scoreDisplay = '-'
      scoreType = 'failed'
    } else if (statusLower === 'running') {
      status = 'Running'
      statusClass = 'badge-status-running'
      scoreDisplay = '-'
      scoreType = 'pending'
    } else if (statusLower === 'pending') {
      status = 'Pending'
      statusClass = 'badge-status-pending'
      scoreDisplay = '-'
      scoreType = 'pending'
    } else if (score != null) {
      if (score >= 80) {
        status = 'Malicious'
        statusClass = 'badge-status-malicious'
        scoreType = 'malicious'
      } else if (score >= 40) {
        status = 'Suspicious'
        statusClass = 'badge-status-suspicious'
        scoreType = 'suspicious'
      } else {
        status = 'Clean'
        statusClass = 'badge-status-clean'
        scoreType = 'clean'
      }
    } else if (statusLower === 'completed') {
      status = 'Completed'
      statusClass = 'badge-status-completed'
      scoreDisplay = 0
      scoreType = 'clean'
    }

    return {
      id: job.id,
      fileName: job.filename || 'Unknown sample',
      hash: job.sha256 || 'Not available',
      score: scoreDisplay,
      scoreType: scoreType,
      status: status,
      statusClass: statusClass,
      fileType: getFileType(job.filename),
      fileSize: job.file_size ? formatBytes(job.file_size) : 'Not available',
      submittedDate: formatSubmittedDate(job.created_at),
      duration: formatDuration(job.started_at, job.completed_at),
      rawCreatedAt: job.created_at,
      rawJob: job
    }
  })

  // Filter items based on activeFilter, dateFilter, and searchQuery
  const filteredAnalyses = allAnalyses.filter((item) => {
    // 1. Status Filter
    let matchesStatus = false
    if (activeFilter === 'All') {
      matchesStatus = true
    } else if (activeFilter === 'Completed') {
      matchesStatus =
        item.status === 'Completed' ||
        item.status === 'Malicious' ||
        item.status === 'Suspicious' ||
        item.status === 'Clean'
    } else {
      matchesStatus = item.status.toLowerCase() === activeFilter.toLowerCase()
    }

    // 2. Date Filter
    let matchesDate = true
    if (dateFilter !== 'All Time' && item.rawCreatedAt) {
      const createdTime = new Date(item.rawCreatedAt).getTime()
      const now = Date.now()
      if (dateFilter === 'Today') {
        matchesDate = now - createdTime <= 24 * 60 * 60 * 1000
      } else if (dateFilter === 'Last 7 days') {
        matchesDate = now - createdTime <= 7 * 24 * 60 * 60 * 1000
      } else if (dateFilter === 'Last 30 days') {
        matchesDate = now - createdTime <= 30 * 24 * 60 * 60 * 1000
      }
    }

    // 3. Search Query
    const q = searchQuery.trim().toLowerCase()
    const matchesSearch =
      q === '' ||
      item.fileName.toLowerCase().includes(q) ||
      item.hash.toLowerCase().includes(q) ||
      item.status.toLowerCase().includes(q) ||
      item.fileType.toLowerCase().includes(q)

    return matchesStatus && matchesDate && matchesSearch
  })

  // Pagination calculation
  const totalPages = Math.max(1, Math.ceil(filteredAnalyses.length / pageSize))
  const safeCurrentPage = Math.min(currentPageNum, totalPages)
  const startIndex = (safeCurrentPage - 1) * pageSize
  const paginatedAnalyses = filteredAnalyses.slice(startIndex, startIndex + pageSize)

  const handleSelectAll = (e) => {
    if (e.target.checked) {
      setSelectedIds(filteredAnalyses.map((item) => item.id))
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
      onSelectSample({
        id: item.id,
        fileName: item.fileName,
        status: item.status,
        score: item.score !== '-' ? item.score : 0,
        rawJob: item.rawJob
      })
    } else if (onNavigateDashboard) {
      onNavigateDashboard()
    }
  }

  const handleDownloadRowReport = async (e, item) => {
    e.stopPropagation()
    try {
      const details = await getJobDetails(item.id)
      const reportData = JSON.stringify(details.analysis_result || details, null, 2)
      const blob = new Blob([reportData], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `threatbox-report-${item.fileName}.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Failed to download report for sample:', err)
      alert('Failed to download report. The analysis result may still be pending or unavailable.')
    }
  }

  const handleRerun = (e) => {
    e.stopPropagation()
    if (onNavigateUpload) {
      onNavigateUpload()
    }
  }

  // Render circular ring progress indicator for threat score
  const renderScoreRing = (score, type) => {
    if (type === 'failed' || type === 'pending' || score === '-') {
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
    const numericScore = typeof score === 'number' ? score : 0
    const progressOffset = circumference - (numericScore / 100) * circumference

    return (
      <svg width="20" height="20" viewBox="0 0 24 24" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx="12" cy="12" r={radius} fill="none" stroke="#EAEAEA" strokeWidth="2.5" />
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

  return (
    <div className="history-layout">
      {/* ---------------- Sidebar with Analysis History active ---------------- */}
      <Sidebar
        activeTab="analysis-history"
        onNavigate={(tab) => {
          if (tab === 'dashboard' || tab === 'analyses') onNavigateDashboard && onNavigateDashboard()
          else if (tab === 'new-analysis' || tab === 'upload') onNavigateUpload && onNavigateUpload()
          else if (onNavigateTab) onNavigateTab(tab)
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
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value)
                  setCurrentPageNum(1)
                }}
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

          {/* Error Banner */}
          {error && (
            <div className="history-error-banner">
              <span>Failed to fetch history: {error}</span>
              <button
                type="button"
                className="btn-history-retry"
                onClick={() => fetchAnalyses(true)}
              >
                Retry
              </button>
            </div>
          )}

          {/* Filter Pills + Right Toolbar (Date filter, Search, Refresh) */}
          <div className="history-controls-bar">
            {/* Filter Pills */}
            <div className="filter-pills-group">
              {filters.map((filter) => (
                <button
                  key={filter}
                  type="button"
                  className={`filter-pill-btn ${activeFilter === filter ? 'active' : ''}`}
                  onClick={() => {
                    setActiveFilter(filter)
                    setCurrentPageNum(1)
                  }}
                >
                  {filter}
                </button>
              ))}
            </div>

            {/* Right Tools */}
            <div className="history-right-tools">
              {/* Refresh Button */}
              <button
                type="button"
                className={`btn-history-refresh ${refreshing ? 'spinning' : ''}`}
                title="Refresh history"
                onClick={() => fetchAnalyses(true)}
                disabled={refreshing || loading}
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
                </svg>
                <span>Refresh</span>
              </button>

              {/* Date Filter Dropdown */}
              <div className="date-filter-wrapper" ref={dateDropdownRef}>
                <div
                  className="date-filter-dropdown"
                  onClick={() => setIsDateDropdownOpen(!isDateDropdownOpen)}
                >
                  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="4" width="18" height="18" rx="2" ry="2" />
                    <line x1="16" y1="2" x2="16" y2="6" />
                    <line x1="8" y1="2" x2="8" y2="6" />
                    <line x1="3" y1="10" x2="21" y2="10" />
                  </svg>
                  <span>{dateFilter}</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="6 9 12 15 18 9" />
                  </svg>
                </div>

                {isDateDropdownOpen && (
                  <div className="date-dropdown-menu">
                    {dateOptions.map((opt) => (
                      <div
                        key={opt}
                        className={`date-dropdown-item ${dateFilter === opt ? 'selected' : ''}`}
                        onClick={() => {
                          setDateFilter(opt)
                          setIsDateDropdownOpen(false)
                          setCurrentPageNum(1)
                        }}
                      >
                        {opt}
                      </div>
                    ))}
                  </div>
                )}
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
                  onChange={(e) => {
                    setSearchQuery(e.target.value)
                    setCurrentPageNum(1)
                  }}
                />
              </div>
            </div>
          </div>

          {/* Data Table Card */}
          <div className="history-table-card">
            {loading ? (
              <div className="history-loading-container">
                <div className="history-spinner"></div>
                <span>Loading analysis history...</span>
              </div>
            ) : filteredAnalyses.length === 0 ? (
              <div className="history-empty-container">
                <div className="history-empty-icon">
                  <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                    <line x1="16" y1="13" x2="8" y2="13" />
                    <line x1="16" y1="17" x2="8" y2="17" />
                    <polyline points="10 9 9 9 8 9" />
                  </svg>
                </div>
                <h3 className="history-empty-title">
                  {allAnalyses.length === 0
                    ? 'No analyses found'
                    : 'No analyses match your criteria'}
                </h3>
                <p className="history-empty-desc">
                  {allAnalyses.length === 0
                    ? 'Upload an executable sample in the sandbox to generate telemetry, process hierarchies, and MITRE ATT&CK mapping.'
                    : 'Try clearing your search query or selecting a different status filter.'}
                </p>
                {allAnalyses.length === 0 ? (
                  <button
                    type="button"
                    className="btn-history-primary"
                    onClick={onNavigateUpload}
                  >
                    Start New Analysis
                  </button>
                ) : (
                  <button
                    type="button"
                    className="btn-history-primary"
                    onClick={() => {
                      setActiveFilter('All')
                      setDateFilter('All Time')
                      setSearchQuery('')
                    }}
                  >
                    Clear Filters
                  </button>
                )}
              </div>
            ) : (
              <table className="history-table">
                <thead>
                  <tr>
                    <th className="th-checkbox">
                      <input
                        type="checkbox"
                        className="custom-table-checkbox"
                        onChange={handleSelectAll}
                        checked={
                          filteredAnalyses.length > 0 &&
                          selectedIds.length === filteredAnalyses.length
                        }
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
                  {paginatedAnalyses.map((item) => (
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
                              title={item.fileName}
                            >
                              {item.fileName}
                            </span>
                            <span className="file-hash-sub" title={item.hash}>
                              {item.hash}
                            </span>
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
                            onClick={(e) => handleDownloadRowReport(e, item)}
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
                            onClick={handleRerun}
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
                            onClick={() => handleRowClick(item)}
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
            )}
          </div>

          {/* Pagination Footer */}
          {!loading && filteredAnalyses.length > 0 && (
            <div className="history-pagination-footer">
              <span className="pagination-counter">
                Showing {startIndex + 1} to{' '}
                {Math.min(startIndex + pageSize, filteredAnalyses.length)} of{' '}
                {filteredAnalyses.length} analyses
              </span>

              <div className="pagination-controls">
                <button
                  type="button"
                  className="page-num-btn"
                  title="Previous Page"
                  disabled={safeCurrentPage === 1}
                  onClick={() => setCurrentPageNum((p) => Math.max(1, p - 1))}
                  style={{ opacity: safeCurrentPage === 1 ? 0.4 : 1, cursor: safeCurrentPage === 1 ? 'not-allowed' : 'pointer' }}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="15 18 9 12 15 6" />
                  </svg>
                </button>

                {Array.from({ length: totalPages }, (_, i) => i + 1).map((num) => (
                  <button
                    key={num}
                    type="button"
                    className={`page-num-btn ${safeCurrentPage === num ? 'active' : ''}`}
                    onClick={() => setCurrentPageNum(num)}
                  >
                    {num}
                  </button>
                ))}

                <button
                  type="button"
                  className="page-num-btn"
                  title="Next Page"
                  disabled={safeCurrentPage === totalPages}
                  onClick={() => setCurrentPageNum((p) => Math.min(totalPages, p + 1))}
                  style={{ opacity: safeCurrentPage === totalPages ? 0.4 : 1, cursor: safeCurrentPage === totalPages ? 'not-allowed' : 'pointer' }}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="9 18 15 12 9 6" />
                  </svg>
                </button>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  )
}

export default History
