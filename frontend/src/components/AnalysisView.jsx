import React, { useEffect, useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { ArrowLeft, ShieldAlert, FileText, Network, Server, Cpu, Database, Hash, Eye, Code, Terminal, Activity } from 'lucide-react'

export default function AnalysisView() {
  const { id } = useParams()
  const [job, setJob] = useState(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState('overview')

  useEffect(() => {
    fetch(`/api/jobs/${id}`)
      .then(res => res.json())
      .then(data => {
        setJob(data)
        setLoading(false)
      })
      .catch(err => {
        console.error(err)
        setLoading(false)
      })
  }, [id])

  if (loading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '50vh' }}>
        <Activity className="animate-spin" size={48} color="var(--primary-color)" />
      </div>
    )
  }

  if (!job) {
    return <div className="glass-panel" style={{ textAlign: 'center', padding: '4rem' }}>Analysis job not found.</div>
  }

  const { analysis_result } = job

  const score = analysis_result?.threat_score?.score
  const severity = analysis_result?.threat_score?.severity || 'Unknown'
  const reasons = analysis_result?.threat_score?.reasons || []
  
  let scoreClass = 'score-low'
  if (score > 40) scoreClass = 'score-medium'
  if (score >= 75) scoreClass = 'score-high'
  if (score === undefined || score === null) scoreClass = 'score-low'

  const hasAnalysis = analysis_result !== null && analysis_result !== undefined

  // Compute file metrics
  const files = analysis_result?.files || []
  const createdFiles = files.filter(f => f.type === 'created')
  const modifiedFiles = files.filter(f => f.type === 'modified')
  const deletedFiles = files.filter(f => f.type === 'deleted')
  const renamedFiles = files.filter(f => f.type === 'renamed')

  const patterns = []
  if (createdFiles.length >= 25) patterns.push("Mass file creation detected")
  if (modifiedFiles.length >= 25) patterns.push("Mass file modification detected")
  if (deletedFiles.length >= 25) patterns.push("Mass file deletion detected")

  // Compute IOCs
  const uniqueIPs = [...new Set((analysis_result?.network || []).map(n => n.dest_ip))].filter(Boolean)
  const uniqueDomains = [...new Set((analysis_result?.dns || []).map(d => d.domain))].filter(Boolean)
  const uniqueFiles = [...new Set(files.filter(f => f.type === 'created' || f.type === 'modified').map(f => f.path))].filter(Boolean)
  const uniqueHashes = [...new Set((analysis_result?.images || []).map(i => i.checksum))].filter(h => h && h !== 0)

  return (
    <div className="fade-in">
      <Link to="/" className="btn" style={{ background: 'white', marginBottom: '1.5rem', border: '1px solid var(--border-color)' }}>
        <ArrowLeft size={16} /> Back to Dashboard
      </Link>
      
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 className="page-title">{job.filename}</h1>
          <p style={{ color: 'var(--text-secondary)' }}>Job ID: {job.id}</p>
        </div>
        <div className={`badge ${job.status === 'completed' ? 'badge-success' : job.status === 'running' ? 'badge-info' : job.status === 'failed' ? 'badge-danger' : 'badge-warning'}`} style={{ fontSize: '1rem', padding: '0.5rem 1rem' }}>
          {job.status.toUpperCase()}
        </div>
      </div>

      {job.status === 'failed' && (
        <div className="stat-card" style={{ marginBottom: '2.5rem', borderLeft: '4px solid var(--danger-color)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--danger-color)' }}>
            <ShieldAlert size={20} />
            <h3 style={{ fontWeight: 600 }}>Analysis Failed</h3>
          </div>
          <p style={{ color: 'var(--text-secondary)' }}>The analysis job encountered an error and could not complete successfully.</p>
        </div>
      )}

      {job.status === 'running' && (
        <div className="stat-card" style={{ marginBottom: '2.5rem', borderLeft: '4px solid var(--info-color)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem', color: 'var(--info-color)' }}>
            <Activity className="animate-spin" size={20} />
            <h3 style={{ fontWeight: 600 }}>Analysis in Progress</h3>
          </div>
          <p style={{ color: 'var(--text-secondary)' }}>The sandbox is currently analyzing the sample. Please check back later.</p>
        </div>
      )}

      {hasAnalysis && job.status === 'completed' && (
        <>
          <div className="glass-panel" style={{ padding: 0, overflow: 'hidden', marginBottom: '2rem' }}>
            <div className="tabs" style={{ margin: 0, borderBottom: '1px solid var(--border-color)', background: 'rgba(255,255,255,0.5)' }}>
              <div className={`tab ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>
                <Eye size={16} style={{display: 'inline', marginRight: 8, verticalAlign: 'middle'}} /> Overview
              </div>
              <div className={`tab ${activeTab === 'mitre' ? 'active' : ''}`} onClick={() => setActiveTab('mitre')}>
                <ShieldAlert size={16} style={{display: 'inline', marginRight: 8, verticalAlign: 'middle'}} /> MITRE ATT&CK
              </div>
              <div className={`tab ${activeTab === 'files' ? 'active' : ''}`} onClick={() => setActiveTab('files')}>
                <FileText size={16} style={{display: 'inline', marginRight: 8, verticalAlign: 'middle'}} /> File Behavior
              </div>
              <div className={`tab ${activeTab === 'network' ? 'active' : ''}`} onClick={() => setActiveTab('network')}>
                <Network size={16} style={{display: 'inline', marginRight: 8, verticalAlign: 'middle'}} /> Network
              </div>
              <div className={`tab ${activeTab === 'processes' ? 'active' : ''}`} onClick={() => setActiveTab('processes')}>
                <Cpu size={16} style={{display: 'inline', marginRight: 8, verticalAlign: 'middle'}} /> Processes
              </div>
              <div className={`tab ${activeTab === 'images' ? 'active' : ''}`} onClick={() => setActiveTab('images')}>
                <Database size={16} style={{display: 'inline', marginRight: 8, verticalAlign: 'middle'}} /> DLLs / Images
              </div>
              <div className={`tab ${activeTab === 'iocs' ? 'active' : ''}`} onClick={() => setActiveTab('iocs')}>
                <Hash size={16} style={{display: 'inline', marginRight: 8, verticalAlign: 'middle'}} /> IOCs
              </div>
              <div className={`tab ${activeTab === 'raw' ? 'active' : ''}`} onClick={() => setActiveTab('raw')}>
                <Terminal size={16} style={{display: 'inline', marginRight: 8, verticalAlign: 'middle'}} /> Raw Telemetry
              </div>
            </div>

            <div style={{ padding: '2rem' }}>
              
              {/* TAB: OVERVIEW */}
              {activeTab === 'overview' && (
                <div>
                  <div className="grid grid-cols-3" style={{ marginBottom: '2rem' }}>
                    <div className="stat-card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gridRow: 'span 2' }}>
                      <h3 style={{ marginBottom: '1.5rem', color: 'var(--text-secondary)', fontWeight: 600 }}>Threat Score</h3>
                      <div className={`score-circle ${scoreClass}`}>
                        {score ?? '-'}
                      </div>
                      <p style={{ marginTop: '1rem', fontWeight: 600, fontSize: '1.25rem', color: score >= 75 ? 'var(--danger-color)' : score >= 50 ? 'var(--warning-color)' : 'var(--success-color)' }}>
                        {severity}
                      </p>
                    </div>

                    <div className="stat-card" style={{ gridColumn: 'span 2' }}>
                      <h3 className="detail-header">Score Reasons</h3>
                      {reasons.length > 0 ? (
                        <ul style={{ paddingLeft: '1.5rem', color: 'var(--danger-color)', fontWeight: 500 }}>
                          {reasons.map((r, i) => <li key={i} style={{marginBottom: 8}}>{r}</li>)}
                        </ul>
                      ) : (
                        <p style={{ color: 'var(--text-secondary)' }}>No malicious behavior scored.</p>
                      )}
                    </div>

                    <div className="stat-card" style={{ gridColumn: 'span 2' }}>
                      <h3 className="detail-header">Analysis Highlights</h3>
                      <div className="grid grid-cols-2">
                        <div>
                          <div className="stat-label">Total File Activity</div>
                          <div className="stat-value">{files.length}</div>
                        </div>
                        <div>
                          <div className="stat-label">Network Connections</div>
                          <div className="stat-value">{analysis_result.network?.length || 0}</div>
                        </div>
                        <div>
                          <div className="stat-label">DNS Queries</div>
                          <div className="stat-value">{analysis_result.dns?.length || 0}</div>
                        </div>
                        <div>
                          <div className="stat-label">Modules Loaded</div>
                          <div className="stat-value">{analysis_result.images?.length || 0}</div>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="detail-section">
                    <h3 className="detail-header">MITRE Techniques Detected</h3>
                    {analysis_result.techniques && analysis_result.techniques.length > 0 ? (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                        {analysis_result.techniques.map((tech, i) => (
                          <span key={i} className="badge" style={{ background: 'var(--bg-color)', border: '1px solid var(--border-color)', color: 'var(--text-primary)', padding: '0.5rem 1rem', fontSize: '0.85rem' }} title={tech.name}>
                            <strong>{tech.technique_id}</strong> - {tech.name}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <p style={{ color: 'var(--text-secondary)' }}>No MITRE techniques detected during analysis.</p>
                    )}
                  </div>
                </div>
              )}

              {/* TAB: MITRE */}
              {activeTab === 'mitre' && (
                <div>
                  <h3 className="detail-header">MITRE ATT&CK Matrix Match</h3>
                  {analysis_result.techniques && analysis_result.techniques.length > 0 ? (
                    <div className="grid grid-cols-2">
                      {analysis_result.techniques.map((tech, i) => (
                        <div key={i} className="stat-card" style={{ borderLeft: '4px solid var(--primary-color)' }}>
                          <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 600, marginBottom: '0.5rem', textTransform: 'uppercase' }}>
                            {tech.tactic}
                          </div>
                          <div style={{ fontSize: '1.25rem', fontWeight: 700, marginBottom: '0.5rem', color: 'var(--text-primary)' }}>
                            {tech.technique_id} : {tech.name}
                          </div>
                          {tech.evidence && (
                            <p style={{ color: 'var(--text-secondary)', fontSize: '0.95rem' }}>
                              Evidence: {tech.evidence}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p style={{ color: 'var(--text-secondary)' }}>No MITRE techniques detected.</p>
                  )}
                </div>
              )}

              {/* TAB: FILES */}
              {activeTab === 'files' && (
                <div>
                  <h3 className="detail-header">File Behavior Summary</h3>
                  
                  <div className="grid grid-cols-2" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: '2rem' }}>
                    <div className="stat-card">
                      <div className="stat-label">Files Created</div>
                      <div className="stat-value">{createdFiles.length}</div>
                    </div>
                    <div className="stat-card">
                      <div className="stat-label">Files Modified</div>
                      <div className="stat-value">{modifiedFiles.length}</div>
                    </div>
                    <div className="stat-card">
                      <div className="stat-label">Files Deleted</div>
                      <div className="stat-value">{deletedFiles.length}</div>
                    </div>
                    <div className="stat-card">
                      <div className="stat-label">Files Renamed</div>
                      <div className="stat-value">{renamedFiles.length}</div>
                    </div>
                  </div>

                  {patterns.length > 0 && (
                    <div className="stat-card" style={{ marginBottom: '2rem', borderLeft: '4px solid var(--warning-color)' }}>
                      <h4 style={{ fontWeight: 600, color: 'var(--warning-color)', marginBottom: '0.5rem' }}>Detected Patterns</h4>
                      <ul style={{ paddingLeft: '1.5rem', color: 'var(--text-primary)' }}>
                        {patterns.map((p, i) => <li key={i}>{p}</li>)}
                      </ul>
                    </div>
                  )}

                  <h3 className="detail-header">Notable File Activity</h3>
                  {files.length > 0 ? (
                    <div className="table-container">
                      <table>
                        <thead>
                          <tr>
                            <th>Action</th>
                            <th>File Path</th>
                            <th>Process Image</th>
                            <th>PID</th>
                          </tr>
                        </thead>
                        <tbody>
                          {files.map((file, i) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600, color: file.type === 'created' ? 'var(--success-color)' : file.type === 'deleted' ? 'var(--danger-color)' : file.type === 'modified' ? 'var(--warning-color)' : 'var(--text-primary)' }}>
                                {file.type.toUpperCase()}
                              </td>
                              <td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{file.path}</td>
                              <td>{file.process}</td>
                              <td>{file.pid}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p style={{ color: 'var(--text-secondary)' }}>No file activity recorded.</p>
                  )}
                </div>
              )}

              {/* TAB: NETWORK */}
              {activeTab === 'network' && (
                <div>
                  <h3 className="detail-header">Network Connections</h3>
                  {analysis_result.network && analysis_result.network.length > 0 ? (
                    <div className="table-container" style={{ marginBottom: '2.5rem' }}>
                      <table>
                        <thead>
                          <tr>
                            <th>Protocol</th>
                            <th>Destination IP</th>
                            <th>Port</th>
                            <th>Process Image</th>
                            <th>PID</th>
                          </tr>
                        </thead>
                        <tbody>
                          {analysis_result.network.map((net, i) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600 }}>{net.protocol}</td>
                              <td style={{ fontFamily: 'monospace' }}>{net.dest_ip}</td>
                              <td>{net.dest_port}</td>
                              <td>{net.process}</td>
                              <td>{net.pid}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p style={{ color: 'var(--text-secondary)', marginBottom: '2.5rem' }}>No network connections recorded.</p>
                  )}

                  <h3 className="detail-header">DNS Queries</h3>
                  {analysis_result.dns && analysis_result.dns.length > 0 ? (
                    <div className="table-container">
                      <table>
                        <thead>
                          <tr>
                            <th>Query Domain</th>
                            <th>Resolved IPs</th>
                            <th>Process Image</th>
                          </tr>
                        </thead>
                        <tbody>
                          {analysis_result.dns.map((dns, i) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600 }}>{dns.domain}</td>
                              <td style={{ fontFamily: 'monospace' }}>{dns.results ? dns.results.join(', ') : '-'}</td>
                              <td>{dns.process} (PID: {dns.pid})</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p style={{ color: 'var(--text-secondary)' }}>No DNS queries recorded.</p>
                  )}
                </div>
              )}

              {/* TAB: PROCESSES */}
              {activeTab === 'processes' && (
                <div>
                  <h3 className="detail-header">Process Tree</h3>
                  {analysis_result.processes && analysis_result.processes.length > 0 ? (
                    <div className="table-container">
                      <table>
                        <thead>
                          <tr>
                            <th>PID</th>
                            <th>Process Name</th>
                            <th>Command Line</th>
                          </tr>
                        </thead>
                        <tbody>
                          {analysis_result.processes.map((proc, i) => (
                            <tr key={i}>
                              <td style={{ fontWeight: 600 }}>{proc.pid}</td>
                              <td style={{ color: 'var(--primary-color)', fontWeight: 500 }}>{proc.name}</td>
                              <td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{proc.command || '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p style={{ color: 'var(--text-secondary)' }}>No relevant processes recorded.</p>
                  )}
                </div>
              )}

              {/* TAB: IMAGES */}
              {activeTab === 'images' && (
                <div>
                  <h3 className="detail-header">Loaded Modules (DLLs / Executables)</h3>
                  {analysis_result.images && analysis_result.images.length > 0 ? (
                    <div className="table-container">
                      <table>
                        <thead>
                          <tr>
                            <th>Module Path</th>
                            <th>Checksum (Hex)</th>
                            <th>Process Image</th>
                            <th>PID</th>
                          </tr>
                        </thead>
                        <tbody>
                          {analysis_result.images.map((img, i) => (
                            <tr key={i}>
                              <td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{img.path}</td>
                              <td style={{ fontFamily: 'monospace' }}>{img.checksum ? img.checksum.toString(16) : '-'}</td>
                              <td>{img.process}</td>
                              <td>{img.pid}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : (
                    <p style={{ color: 'var(--text-secondary)' }}>No significant module loading recorded.</p>
                  )}
                </div>
              )}

              {/* TAB: IOCS */}
              {activeTab === 'iocs' && (
                <div>
                  <h3 className="detail-header">Extracted Indicators of Compromise</h3>
                  <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                    Unique artifacts observed during the analysis lifecycle.
                  </p>
                  
                  <div className="grid grid-cols-2">
                    <div className="stat-card">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                        <Network size={20} color="var(--primary-color)" />
                        <h4 style={{ fontWeight: 600 }}>IP Addresses</h4>
                      </div>
                      {uniqueIPs.length > 0 ? (
                        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '0.5rem', fontFamily: 'monospace', color: '#10b981', maxHeight: '200px', overflowY: 'auto' }}>
                          {uniqueIPs.map((ip, i) => <div key={i}>{ip}</div>)}
                        </div>
                      ) : <p style={{ color: 'var(--text-secondary)' }}>No IPs extracted.</p>}
                    </div>

                    <div className="stat-card">
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                        <Server size={20} color="var(--primary-color)" />
                        <h4 style={{ fontWeight: 600 }}>Domains</h4>
                      </div>
                      {uniqueDomains.length > 0 ? (
                        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '0.5rem', fontFamily: 'monospace', color: '#10b981', maxHeight: '200px', overflowY: 'auto' }}>
                          {uniqueDomains.map((d, i) => <div key={i}>{d}</div>)}
                        </div>
                      ) : <p style={{ color: 'var(--text-secondary)' }}>No domains extracted.</p>}
                    </div>

                    <div className="stat-card" style={{ gridColumn: 'span 2' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                        <FileText size={20} color="var(--primary-color)" />
                        <h4 style={{ fontWeight: 600 }}>Dropped / Modified Files</h4>
                      </div>
                      {uniqueFiles.length > 0 ? (
                        <div style={{ background: '#1e293b', padding: '1rem', borderRadius: '0.5rem', fontFamily: 'monospace', color: '#10b981', maxHeight: '300px', overflowY: 'auto' }}>
                          {uniqueFiles.map((f, i) => <div key={i}>{f}</div>)}
                        </div>
                      ) : <p style={{ color: 'var(--text-secondary)' }}>No dropped files extracted.</p>}
                    </div>
                  </div>
                </div>
              )}

              {/* TAB: RAW TELEMETRY */}
              {activeTab === 'raw' && (
                <div>
                  <h3 className="detail-header">Raw Analysis Telemetry</h3>
                  <p style={{ color: 'var(--text-secondary)', marginBottom: '1.5rem' }}>
                    This view exposes the underlying JSON data structures generated by the analysis engine.
                  </p>
                  <div style={{ background: '#0f172a', padding: '1.5rem', borderRadius: '0.75rem', fontFamily: 'monospace', color: '#38bdf8', height: '600px', overflowY: 'auto', fontSize: '0.85rem', whiteSpace: 'pre-wrap' }}>
                    {JSON.stringify(analysis_result, null, 2)}
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
