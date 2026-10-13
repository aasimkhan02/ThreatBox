import React from 'react'
import './home.css'
import bgImage from '../../assets/background.png'

const Home = () => {
  return (
    <div>
      <div className="hero">
        <img src={bgImage} alt="Hero Background" className="hero-bg-img" />
        <div className="hero-content">
          <h1>ThreatBox</h1>
          <p>Automated Malware Sandbox & Analysis Pipeline</p>
        </div>
      </div>
    </div>
  )
}

export default Home