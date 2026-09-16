import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { File, Loader, CheckCircle, AlertCircle, Clock } from 'lucide-react'

export default function Samples() {
  const [samples, setSamples] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/jobs')
      .then(res => res.json())
      .then(data => {
        setSamples(data || [])
        setLoading(false)
      })
      .catch(err => {
        console.error(err)
        setLoading(false)
      })
  }, [])

  const getSeverity = (score) => {
    if (score === null || score === undefined) return '-'
    if (score >= 75) return <span style={{color: 'var(--danger-color)', fontWeight: 600}}>Critical</span>
    if (score >= 50) return <span style={{color: 'var(--warning-color)', fontWeight: 600}}>High</span>
    if (score >= 25) return <span style={{color: '#eab308', fontWeight: 600}}>Medium</span>
    return <span style={{color: 'var(--success-color)', fontWeight: 600}}>Low</span>
  }

  return (
    <div className="fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Samples</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Manage submitted files and their latest analysis status.</p>
        </div>
        <Link to="/upload" className="btn btn-primary">
          Submit Sample
        </Link>
      </div>

      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '4rem' }}><Loader className="animate-spin" size={32} color="var(--primary-color)" /></div>
        ) : samples.length === 0 ? (
          <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '4rem' }}>No samples submitted yet.</div>
        ) : (
          <div className="table-container" style={{ border: 'none', borderRadius: '0', marginBottom: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>File Name</th>
                  <th>Upload Date</th>
                  <th>Latest Status</th>
                  <th>Threat Score</th>
                  <th>Severity</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {samples.map(sample => (
                  <tr key={sample.id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', fontWeight: 500 }}>
                        <File size={16} color="var(--primary-color)" />
                        {sample.filename}
                      </div>
                    </td>
                    <td>{new Date(sample.created_at).toLocaleString()}</td>
                    <td>
                      <span className={`badge ${sample.status === 'completed' ? 'badge-success' : sample.status === 'failed' ? 'badge-danger' : sample.status === 'running' ? 'badge-info' : 'badge-warning'}`}>
                        {sample.status.toUpperCase()}
                      </span>
                    </td>
                    <td style={{ fontWeight: 600 }}>
                      {sample.score !== undefined && sample.score !== null ? `${sample.score}/100` : '-'}
                    </td>
                    <td>{getSeverity(sample.score)}</td>
                    <td>
                      <Link to={`/job/${sample.id}`} className="btn" style={{ background: 'var(--bg-color)', padding: '0.4rem 0.8rem', fontSize: '0.85rem' }}>
                        View Analysis
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
