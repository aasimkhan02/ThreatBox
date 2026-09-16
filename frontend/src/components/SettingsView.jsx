import React from 'react'
import { Settings } from 'lucide-react'

export default function SettingsView() {
  return (
    <div className="fade-in">
      <div className="page-header">
        <h1 className="page-title">Settings</h1>
        <p style={{ color: 'var(--text-secondary)' }}>Configure ThreatBox engine and dashboard preferences.</p>
      </div>

      <div className="glass-panel" style={{ textAlign: 'center', padding: '6rem 2rem' }}>
        <Settings size={48} color="var(--text-secondary)" style={{ margin: '0 auto 1.5rem auto', opacity: 0.5 }} />
        <h2 style={{ marginBottom: '0.5rem', color: 'var(--text-primary)' }}>Configuration Area</h2>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '500px', margin: '0 auto' }}>
          YARA rules, MITRE ATT&CK database updates, and scoring thresholds will be configurable here in a future update.
        </p>
      </div>
    </div>
  )
}
