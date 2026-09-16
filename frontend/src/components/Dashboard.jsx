import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { File, Clock, CheckCircle, AlertCircle, Loader } from 'lucide-react'

export default function Dashboard() {
  const [jobs, setJobs] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/jobs')
      .then(res => res.json())
      .then(data => {
        setJobs(data || [])
        setLoading(false)
      })
      .catch(err => {
        console.error(err)
        setLoading(false)
      })
  }, [])

  const getStatusBadge = (status) => {
    switch (status) {
      case 'completed':
        return <span className="badge badge-success"><CheckCircle size={12} style={{marginRight: 4, verticalAlign: 'middle'}}/> COMPLETED</span>
      case 'failed':
        return <span className="badge badge-danger"><AlertCircle size={12} style={{marginRight: 4, verticalAlign: 'middle'}}/> FAILED</span>
      case 'pending':
        return <span className="badge badge-warning"><Clock size={12} style={{marginRight: 4, verticalAlign: 'middle'}}/> QUEUED</span>
      case 'running':
        return <span className="badge badge-info"><Loader size={12} className="animate-spin" style={{marginRight: 4, verticalAlign: 'middle'}}/> RUNNING</span>
      default:
        return <span className="badge">{status}</span>
    }
  }

  const getSeverity = (score) => {
    if (score === null || score === undefined) return '-'
    if (score >= 75) return <span style={{color: 'var(--danger-color)', fontWeight: 600}}>Critical</span>
    if (score >= 50) return <span style={{color: 'var(--warning-color)', fontWeight: 600}}>High</span>
    if (score >= 25) return <span style={{color: '#eab308', fontWeight: 600}}>Medium</span>
    return <span style={{color: 'var(--success-color)', fontWeight: 600}}>Low</span>
  }

  return (
    <div className="fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Overview of recent malware analysis jobs.</p>
        </div>
        <Link to="/upload" className="btn btn-primary">
          Submit Sample
        </Link>
      </div>

      <div className="grid grid-cols-2" style={{ marginBottom: '2.5rem', gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <div className="stat-card">
          <div className="stat-label">Total Analyzed</div>
          <div className="stat-value">{jobs.length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Completed</div>
          <div className="stat-value">{jobs.filter(j => j.status === 'completed').length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Running</div>
          <div className="stat-value" style={{color: 'var(--info-color)'}}>{jobs.filter(j => j.status === 'running').length}</div>
        </div>
        <div className="stat-card">
          <div className="stat-label">Failed</div>
          <div className="stat-value" style={{color: 'var(--danger-color)'}}>{jobs.filter(j => j.status === 'failed').length}</div>
        </div>
      </div>

      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ padding: '1.5rem 1.5rem 0 1.5rem' }}>
            <h2 style={{ marginBottom: '1.5rem', fontSize: '1.25rem' }}>Recent Analyses</h2>
        </div>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '2rem' }}><Loader className="animate-spin" size={32} color="var(--primary-color)" /></div>
        ) : jobs.length === 0 ? (
          <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '2rem' }}>No jobs found. Upload a sample to begin.</div>
        ) : (
          <div className="table-container" style={{ border: 'none', borderRadius: '0', marginBottom: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Job ID</th>
                  <th>File Name</th>
                  <th>Status</th>
                  <th>Threat Score</th>
                  <th>Severity</th>
                  <th>Submission Time</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {jobs.slice(0, 10).map(job => (
                  <tr key={job.id}>
                    <td style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{job.id.split('-')[0]}</td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontWeight: 500 }}>
                        <File size={16} color="var(--primary-color)" />
                        {job.filename}
                      </div>
                    </td>
                    <td>{getStatusBadge(job.status)}</td>
                    <td style={{ fontWeight: 600 }}>
                      {job.score !== undefined && job.score !== null ? `${job.score}/100` : '-'}
                    </td>
                    <td>{getSeverity(job.score)}</td>
                    <td>{new Date(job.created_at).toLocaleString()}</td>
                    <td>
                      <Link to={`/job/${job.id}`} className="btn" style={{ background: 'var(--bg-color)', padding: '0.4rem 0.8rem', fontSize: '0.85rem' }}>
                        Open Analysis
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
