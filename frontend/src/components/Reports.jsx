import React from 'react'
import { PieChart } from 'lucide-react'

export default function Reports() {
  return (
    <div className="fade-in">
      <div className="page-header">
        <h1 className="page-title">Reports</h1>
        <p style={{ color: 'var(--text-secondary)' }}>Aggregated threat intelligence reports.</p>
      </div>

      <div className="glass-panel" style={{ textAlign: 'center', padding: '6rem 2rem' }}>
        <PieChart size={48} color="var(--text-secondary)" style={{ margin: '0 auto 1.5rem auto', opacity: 0.5 }} />
        <h2 style={{ marginBottom: '0.5rem', color: 'var(--text-primary)' }}>Reporting Engine Coming Soon</h2>
        <p style={{ color: 'var(--text-secondary)', maxWidth: '500px', margin: '0 auto' }}>
          This section will provide aggregated metrics, trend analysis, and printable PDF reports across all analyzed samples.
        </p>
      </div>
    </div>
  )
}
