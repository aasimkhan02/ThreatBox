import React from 'react'
import { BrowserRouter as Router, Routes, Route, NavLink } from 'react-router-dom'
import { LayoutDashboard, FileText, Server, Settings, PieChart, Shield, UploadCloud } from 'lucide-react'
import Dashboard from './components/Dashboard'
import Samples from './components/Samples'
import Jobs from './components/Jobs'
import AnalysisView from './components/AnalysisView'
import Reports from './components/Reports'
import SettingsView from './components/SettingsView'
import Upload from './components/Upload'

function App() {
  return (
    <Router>
      <div className="app-container">
        {/* Sidebar */}
        <aside className="sidebar">
          <div className="sidebar-brand">
            <Shield size={32} color="var(--primary-color)" />
            <span>ThreatBox</span>
          </div>
          
          <nav>
            <NavLink to="/" className={({isActive}) => `nav-link ${isActive ? 'active' : ''}`}>
              <LayoutDashboard size={20} />
              Dashboard
            </NavLink>
            <NavLink to="/upload" className={({isActive}) => `nav-link ${isActive ? 'active' : ''}`}>
              <UploadCloud size={20} />
              Submit Sample
            </NavLink>
            <NavLink to="/samples" className={({isActive}) => `nav-link ${isActive ? 'active' : ''}`}>
              <FileText size={20} />
              Samples
            </NavLink>
            <NavLink to="/jobs" className={({isActive}) => `nav-link ${isActive ? 'active' : ''}`}>
              <Server size={20} />
              Analysis Jobs
            </NavLink>
            <NavLink to="/reports" className={({isActive}) => `nav-link ${isActive ? 'active' : ''}`}>
              <PieChart size={20} />
              Reports
            </NavLink>
            <div style={{ marginTop: 'auto' }}>
              <NavLink to="/settings" className={({isActive}) => `nav-link ${isActive ? 'active' : ''}`}>
                <Settings size={20} />
                Settings
              </NavLink>
            </div>
          </nav>
        </aside>

        {/* Main Content */}
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/upload" element={<Upload />} />
            <Route path="/samples" element={<Samples />} />
            <Route path="/jobs" element={<Jobs />} />
            <Route path="/job/:id" element={<AnalysisView />} />
            <Route path="/reports" element={<Reports />} />
            <Route path="/settings" element={<SettingsView />} />
          </Routes>
        </main>
      </div>
    </Router>
  )
}

export default App
