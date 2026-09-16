import React, { useCallback, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { UploadCloud, CheckCircle, AlertCircle } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

export default function Upload() {
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState(null)
  const navigate = useNavigate()

  const onDrop = useCallback(acceptedFiles => {
    if (acceptedFiles.length === 0) return
    const file = acceptedFiles[0]
    
    setUploading(true)
    setError(null)

    const formData = new FormData()
    formData.append('file', file)

    fetch('/api/samples', {
      method: 'POST',
      body: formData
    })
      .then(async res => {
        if (!res.ok) {
          let msg = 'Upload failed'
          try {
            const errData = await res.text()
            if (errData) msg = errData
          } catch(e) {}
          throw new Error(msg)
        }
        return res.json()
      })
      .then(data => {
        navigate(`/job/${data.job_id}`)
      })
      .catch(err => {
        console.error(err)
        setError(err.message)
        setUploading(false)
      })
  }, [navigate])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ onDrop, multiple: false })

  return (
    <div className="fade-in">
      <div className="page-header">
        <h1 className="page-title">Submit Sample</h1>
        <p style={{ color: 'var(--text-secondary)' }}>Upload a suspicious file for deep analysis.</p>
      </div>

      <div className="glass-panel" style={{ maxWidth: '600px', margin: '0 auto' }}>
        <div {...getRootProps()} className={`upload-zone ${isDragActive ? 'active' : ''}`}>
          <input {...getInputProps()} />
          <UploadCloud size={64} color={isDragActive ? 'var(--primary-hover)' : 'var(--primary-color)'} style={{ marginBottom: '1.5rem', transition: 'all 0.2s' }} />
          {
            uploading ? (
              <h3 style={{ fontSize: '1.25rem', fontWeight: 600 }}>Uploading & Initializing Sandbox...</h3>
            ) : isDragActive ? (
              <h3 style={{ fontSize: '1.25rem', fontWeight: 600, color: 'var(--primary-color)' }}>Drop the file here...</h3>
            ) : (
              <>
                <h3 style={{ fontSize: '1.25rem', fontWeight: 600, marginBottom: '0.5rem' }}>Drag & Drop file to scan</h3>
                <p style={{ color: 'var(--text-secondary)' }}>or click to browse from your computer</p>
                <div style={{ marginTop: '2rem' }}>
                  <button className="btn btn-primary">Select File</button>
                </div>
              </>
            )
          }
        </div>

        {error && (
          <div style={{ marginTop: '1.5rem', padding: '1rem', background: 'rgba(239, 68, 68, 0.1)', color: 'var(--danger-color)', borderRadius: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertCircle size={20} />
            {error}
          </div>
        )}
      </div>
    </div>
  )
}
