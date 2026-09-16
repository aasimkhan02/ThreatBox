import React, { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { Server, Loader, CheckCircle, AlertCircle, Clock } from 'lucide-react'

export default function Jobs() {
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

  return (
    <div className="fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1 className="page-title">Analysis Jobs</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Monitor the execution state of backend analysis jobs.</p>
        </div>
      </div>

      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        {loading ? (
          <div style={{ textAlign: 'center', padding: '4rem' }}><Loader className="animate-spin" size={32} color="var(--primary-color)" /></div>
        ) : jobs.length === 0 ? (
          <div style={{ textAlign: 'center', color: 'var(--text-secondary)', padding: '4rem' }}>No jobs running.</div>
        ) : (
          <div className="table-container" style={{ border: 'none', borderRadius: '0', marginBottom: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>Job ID</th>
                  <th>Sample Filename</th>
                  <th>Status</th>
                  <th>Created Time</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {jobs.map(job => (
                  <tr key={job.id}>
                    <td style={{ fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{job.id}</td>
                    <td style={{ fontWeight: 500 }}>{job.filename}</td>
                    <td>
                      <span className={`badge ${job.status === 'completed' ? 'badge-success' : job.status === 'failed' ? 'badge-danger' : job.status === 'running' ? 'badge-info' : 'badge-warning'}`}>
                        {job.status.toUpperCase()}
                      </span>
                    </td>
                    <td>{new Date(job.created_at).toLocaleString()}</td>
                    <td>
                      <Link to={`/job/${job.id}`} className="btn" style={{ background: 'var(--bg-color)', padding: '0.4rem 0.8rem', fontSize: '0.85rem' }}>
                        View Details
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
