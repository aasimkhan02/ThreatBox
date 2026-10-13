import React, { useState } from 'react'
import './App.css'
import Home from './pages/home/home'
import AnalysisReport from './pages/report/AnalysisReport'
import AnalyzePage from './pages/analyze/AnalyzePage'

function App() {
  // 'analyze' (Upload section), 'result' (Analysis Report / Dashboard), or 'home'
  const [currentPage, setCurrentPage] = useState('analyze')

  return (
    <div className="container">
      {currentPage === 'home' && (
        <Home onOpenReport={() => setCurrentPage('result')} />
      )}
      {currentPage === 'analyze' && (
        <AnalyzePage
          onNavigateHome={() => setCurrentPage('home')}
          onOpenResult={() => setCurrentPage('result')}
        />
      )}
      {currentPage === 'result' && (
        <AnalysisReport
          onNavigateHome={() => setCurrentPage('home')}
          onNavigateAnalyze={() => setCurrentPage('analyze')}
        />
      )}
    </div>
  )
}

export default App


