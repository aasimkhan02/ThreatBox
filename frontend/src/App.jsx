import React, { useState } from 'react'
import './App.css'
import Home from './pages/home/home'
import Upload from './components/upload/Upload'
import Dashboard from './components/dashboard/Dashboard'
import History from './components/history/History'

function App() {
  // 'home' | 'upload' | 'dashboard' | 'history'
  const [currentPage, setCurrentPage] = useState('home')
  const [selectedSample, setSelectedSample] = useState(null)

  const handleOpenSampleReport = (sample) => {
    setSelectedSample(sample)
    setCurrentPage('dashboard')
  }

  const handleSidebarNavigate = (tab) => {
    if (tab === 'new-analysis') setCurrentPage('upload')
    else if (tab === 'dashboard' || tab === 'analyses') setCurrentPage('dashboard')
    else if (tab === 'history' || tab === 'analysis-history') setCurrentPage('history')
  }

  return (
    <div className="container">
      {currentPage === 'home' && (
        <Home onOpenReport={() => setCurrentPage('upload')} />
      )}
      {currentPage === 'upload' && (
        <Upload
          onNavigateHome={() => setCurrentPage('home')}
          onSelectSample={handleOpenSampleReport}
          onNavigateDashboard={() => setCurrentPage('dashboard')}
          onNavigateHistory={() => setCurrentPage('history')}
        />
      )}
      {currentPage === 'dashboard' && (
        <Dashboard
          sampleData={selectedSample}
          onNavigateHome={() => setCurrentPage('home')}
          onNavigateUpload={() => setCurrentPage('upload')}
          onNavigateTab={handleSidebarNavigate}
        />
      )}
      {currentPage === 'history' && (
        <History
          onNavigateHome={() => setCurrentPage('home')}
          onNavigateUpload={() => setCurrentPage('upload')}
          onNavigateDashboard={() => setCurrentPage('dashboard')}
          onSelectSample={handleOpenSampleReport}
        />
      )}
    </div>
  )
}

export default App
