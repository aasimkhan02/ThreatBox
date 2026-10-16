import React from 'react'
import './home.css'
import Navbar from '../../components/layout/Navbar'
import bgImage from '../../assets/background.png'

import dashboardImg from '../../assets/dashboard.png'

const Home = ({ onOpenReport }) => {
  return (
    <div className="home-container">
      <Navbar onGetStarted={onOpenReport} />

      {/* ---------------- 1. Hero Section ---------------- */}
      <section className="hero">
        {/* Clean Background Image at 100% full opacity, behind everything */}
        <img src={bgImage} alt="ThreatBox Architecture" className="hero-bg-img" />

        {/* Tactical Annotation: Top Left - Isolated Execution */}
        <div className="tactical-marker marker-isolated">
          <div className="marker-pip"></div>
          <div className="marker-label">
            <span>ISOLATED</span>
            <span>EXECUTION</span>
          </div>
        </div>

        {/* Tactical Annotation: Top Right - Behavioral Insights */}
        <div className="tactical-marker marker-behavioral">
          <div className="marker-label">
            <span>BEHAVIORAL</span>
            <span>INSIGHTS</span>
          </div>
          <div className="marker-line"></div>
        </div>

        {/* Tactical Annotation: Mid Right - MITRE ATT&CK Mapping */}
        <div className="tactical-marker marker-mitre">
          <div className="marker-label">
            <span>MITRE ATT&amp;CK</span>
            <span>MAPPING</span>
          </div>
          <div className="marker-line-corner"></div>
        </div>

        {/* Tactical Annotation: Lower Left Specs Overlay */}
        <div className="tactical-pipeline-specs">
          <div className="spec-item"><span className="dash">—</span> FILE EXECUTION</div>
          <div className="spec-item"><span className="dash">—</span> PROCESS MONITORING</div>
          <div className="spec-item"><span className="dash">—</span> NETWORK ACTIVITY</div>
          <div className="spec-item"><span className="dash">—</span> BEHAVIORAL ANALYSIS</div>
          <div className="spec-item"><span className="dash">—</span> ATT&amp;CK MAPPING</div>
        </div>

        {/* Center Main Content */}
        <div className="hero-content">
          <div className="hero-eyebrow">
            <span>ANALYZE</span>
            <span className="dot">·</span>
            <span>UNDERSTAND</span>
            <span className="dot">·</span>
            <span>STAY AHEAD</span>
          </div>

          <h1 className="hero-title">
            Unpack malware.<br />
            See the <span className="title-muted">bigger picture.</span>
          </h1>

          <p className="hero-description">
            ThreatBox analyzes suspicious files in an isolated Windows Sandbox,
            extracts detailed telemetry, and maps behavior to MITRE ATT&amp;CK techniques.
          </p>

          <div className="hero-cta-group">
            <button
              type="button"
              className="hero-btn-primary"
              onClick={onOpenReport}
            >
              <span>Get Started</span>
              <svg
                width="15"
                height="15"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <line x1="5" y1="12" x2="19" y2="12" />
                <polyline points="12 5 19 12 12 19" />
              </svg>
            </button>

            <a
              href="https://github.com"
              target="_blank"
              rel="noreferrer"
              className="hero-btn-secondary"
            >
              <span>View on GitHub</span>
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="currentColor"
              >
                <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" />
              </svg>
            </a>
          </div>
        </div>
      </section>

      {/* ---------------- 2. Feature Highlights Ribbon ---------------- */}
      <section className="features-ribbon-section" id="features">
        <div className="features-ribbon-container">
          {/* Card 1: Windows Sandbox */}
          <div className="ribbon-card">
            <div className="ribbon-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z" />
                <path d="m3.3 7 8.7 5 8.7-5" />
                <path d="M12 22V12" />
              </svg>
            </div>
            <div className="ribbon-text">
              <h3 className="ribbon-title">Windows Sandbox isolation</h3>
              <p className="ribbon-subtitle">Run untrusted files safely</p>
            </div>
          </div>

          {/* Card 2: Behavioral telemetry */}
          <div className="ribbon-card">
            <div className="ribbon-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
                <line x1="10" y1="9" x2="8" y2="9" />
              </svg>
            </div>
            <div className="ribbon-text">
              <h3 className="ribbon-title">Behavioral telemetry</h3>
              <p className="ribbon-subtitle">Extract detailed runtime data</p>
            </div>
          </div>

          {/* Card 3: MITRE ATT&CK mapping */}
          <div className="ribbon-card">
            <div className="ribbon-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10" />
                <line x1="22" y1="12" x2="18" y2="12" />
                <line x1="6" y1="12" x2="2" y2="12" />
                <line x1="12" y1="6" x2="12" y2="2" />
                <line x1="12" y1="22" x2="12" y2="18" />
              </svg>
            </div>
            <div className="ribbon-text">
              <h3 className="ribbon-title">MITRE ATT&amp;CK mapping</h3>
              <p className="ribbon-subtitle">Identify attacker techniques</p>
            </div>
          </div>

          {/* Card 4: Explainable threat scoring */}
          <div className="ribbon-card">
            <div className="ribbon-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                <line x1="18" y1="20" x2="18" y2="10" />
                <line x1="12" y1="20" x2="12" y2="4" />
                <line x1="6" y1="20" x2="6" y2="14" />
              </svg>
            </div>
            <div className="ribbon-text">
              <h3 className="ribbon-title">Explainable threat scoring</h3>
              <p className="ribbon-subtitle">Understand risk with context</p>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- 3. How It Works Section ---------------- */}
      <section className="how-it-works-section" id="how-it-works">
        <div className="how-it-works-container">
          {/* Header row: Split Title on left, Paragraph on right */}
          <div className="how-header-row">
            <div className="how-title-col">
              <span className="how-eyebrow">HOW IT WORKS</span>
              <h2 className="how-heading">From file to evidence.</h2>
            </div>
            <div className="how-desc-col">
              <p className="how-description">
                ThreatBox executes your sample in an isolated Windows Sandbox
                environment, collects comprehensive telemetry, and maps observed
                behavior to real attacker techniques.
              </p>
            </div>
          </div>

          {/* 4 Steps Columns */}
          <div className="how-steps-grid">
            {/* Step 01 */}
            <div className="how-step-card">
              <div className="step-top-row">
                <span className="step-num">01</span>
                <div className="step-icon">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                    <polyline points="17 8 12 3 7 8" />
                    <line x1="12" y1="3" x2="12" y2="15" />
                  </svg>
                </div>
              </div>
              <h4 className="step-title">Submit sample</h4>
              <p className="step-desc">
                Upload a suspicious file (EXE, DLL, script, or archive) to analyze in a secure environment.
              </p>
            </div>

            {/* Step 02 */}
            <div className="how-step-card">
              <div className="step-top-row">
                <span className="step-num">02</span>
                <div className="step-icon">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z" />
                    <path d="m3.3 7 8.7 5 8.7-5" />
                    <path d="M12 22V12" />
                  </svg>
                </div>
              </div>
              <h4 className="step-title">Execute in isolation</h4>
              <p className="step-desc">
                The file runs inside a clean Windows Sandbox with full monitoring enabled.
              </p>
            </div>

            {/* Step 03 */}
            <div className="how-step-card">
              <div className="step-top-row">
                <span className="step-num">03</span>
                <div className="step-icon">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                    <line x1="16" y1="13" x2="8" y2="13" />
                    <line x1="16" y1="17" x2="8" y2="17" />
                    <polyline points="10 9 9 9 8 9" />
                  </svg>
                </div>
              </div>
              <h4 className="step-title">Observe behavior</h4>
              <p className="step-desc">
                ThreatBox captures process, file, registry, network and DNS activity in real time.
              </p>
            </div>

            {/* Step 04 */}
            <div className="how-step-card">
              <div className="step-top-row">
                <span className="step-num">04</span>
                <div className="step-icon">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="3" width="7" height="7" />
                    <rect x="14" y="3" width="7" height="7" />
                    <rect x="14" y="14" width="7" height="7" />
                    <rect x="3" y="14" width="7" height="7" />
                  </svg>
                </div>
              </div>
              <h4 className="step-title">Review findings</h4>
              <p className="step-desc">
                Get a detailed report with behavior analysis, ATT&amp;CK mapping and risk assessment.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- 4. Product Preview Section ---------------- */}
      <section className="product-preview-section">
        <div className="product-preview-container">
          {/* Left Text Column */}
          <div className="preview-text-col">
            <span className="preview-eyebrow">PRODUCT PREVIEW</span>
            <h2 className="preview-heading">
              See what the file<br />
              actually does.
            </h2>
            <p className="preview-description">
              A clear, structured view of the file's behavior with process tree, event timeline and MITRE ATT&amp;CK mappings.
            </p>
            <div className="preview-btn-wrap">
              <button
                type="button"
                className="preview-cta-btn"
                onClick={onOpenReport}
              >
                <span>View sample report</span>
                <svg
                  width="15"
                  height="15"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <line x1="5" y1="12" x2="19" y2="12" />
                  <polyline points="12 5 19 12 12 19" />
                </svg>
              </button>
            </div>
          </div>

          {/* Right Window Screen Frame Column */}
          <div className="preview-screen-col">
            <div className="preview-window-frame">
              {/* Window Titlebar with 3 macOS traffic light dots */}
              <div className="window-frame-titlebar">
                <div className="window-dots">
                  <span className="window-dot dot-close"></span>
                  <span className="window-dot dot-minimize"></span>
                  <span className="window-dot dot-expand"></span>
                </div>
              </div>

              {/* Window Screen Image Viewport */}
              <div className="window-frame-screen">
                <img
                  src={dashboardImg}
                  alt="ThreatBox Dashboard Preview"
                  className="window-preview-image"
                />
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- 5. Split Value Proposition Section ---------------- */}
      <section className="home-split-values-section">
        <div className="split-values-container">
          {/* Left Column: Detailed Telemetry */}
          <div className="split-val-col">
            <span className="split-val-eyebrow">DETAILED TELEMETRY</span>
            <h3 className="split-val-title">Behavior, not guesswork.</h3>
            <p className="split-val-desc">
              Capture and analyze real runtime behavior to understand what the file actually does inside the system.
            </p>

            <div className="split-val-icons-grid five-items">
              <div className="val-icon-item">
                <div className="val-svg-wrap">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z" />
                    <path d="m3.3 7 8.7 5 8.7-5" />
                    <path d="M12 22V12" />
                  </svg>
                </div>
                <span className="val-item-name">Process</span>
                <span className="val-item-sub">Creation, injection, termination</span>
              </div>

              <div className="val-icon-item">
                <div className="val-svg-wrap">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                    <polyline points="14 2 14 8 20 8" />
                  </svg>
                </div>
                <span className="val-item-name">File</span>
                <span className="val-item-sub">Read, write, drop, modify</span>
              </div>

              <div className="val-icon-item">
                <div className="val-svg-wrap">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="2" y1="12" x2="22" y2="12" />
                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                  </svg>
                </div>
                <span className="val-item-name">Network</span>
                <span className="val-item-sub">Connections, HTTP/S, domains</span>
              </div>

              <div className="val-icon-item">
                <div className="val-svg-wrap">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    <circle cx="12" cy="11" r="3" />
                  </svg>
                </div>
                <span className="val-item-name">DNS</span>
                <span className="val-item-sub">Queries and resolved IPs</span>
              </div>

              <div className="val-icon-item">
                <div className="val-svg-wrap">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="3" width="7" height="7" />
                    <rect x="14" y="3" width="7" height="7" />
                    <rect x="14" y="14" width="7" height="7" />
                    <rect x="3" y="14" width="7" height="7" />
                  </svg>
                </div>
                <span className="val-item-name">Registry</span>
                <span className="val-item-sub">Key changes, persistence</span>
              </div>
            </div>
          </div>

          {/* Right Column: ATT&CK Context */}
          <div className="split-val-col right-col">
            <span className="split-val-eyebrow">ATT&amp;CK CONTEXT</span>
            <h3 className="split-val-title">Every finding has context.</h3>
            <p className="split-val-desc">
              Observed behavior is mapped to MITRE ATT&amp;CK techniques with clear evidence, so you can understand the attacker's intent.
            </p>

            <div className="split-val-icons-grid three-items">
              <div className="val-icon-item">
                <div className="val-svg-wrap">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <circle cx="12" cy="12" r="10" />
                    <line x1="22" y1="12" x2="18" y2="12" />
                    <line x1="6" y1="12" x2="2" y2="12" />
                    <line x1="12" y1="6" x2="12" y2="2" />
                    <line x1="12" y1="22" x2="12" y2="18" />
                  </svg>
                </div>
                <span className="val-item-name">Technique mapping</span>
                <span className="val-item-sub">Link behavior to real ATT&amp;CK techniques</span>
              </div>

              <div className="val-icon-item">
                <div className="val-svg-wrap">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    <path d="M9 12h6" />
                  </svg>
                </div>
                <span className="val-item-name">Evidence details</span>
                <span className="val-item-sub">See exactly what triggered the detection</span>
              </div>

              <div className="val-icon-item">
                <div className="val-svg-wrap">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    <path d="m9 12 2 2 4-4" />
                  </svg>
                </div>
                <span className="val-item-name">Clear context</span>
                <span className="val-item-sub">Understand the why behind the behavior</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- 6. Dark Get Started CTA Banner ---------------- */}
      <section className="home-dark-cta-banner">
        <div className="dark-cta-container">
          <div className="dark-cta-left">
            <span className="dark-cta-eyebrow">GET STARTED</span>
            <h2 className="dark-cta-headline">
              Ready to examine<br />
              a suspicious file?
            </h2>
          </div>

          <div className="dark-cta-right">
            <p className="dark-cta-desc">
              Analyze unknown files, uncover hidden behavior, and get clear, actionable insights with ThreatBox.
            </p>
            <button
              type="button"
              className="dark-cta-btn-white"
              onClick={onOpenReport}
            >
              <span>Analyze a file</span>
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <line x1="5" y1="12" x2="19" y2="12" />
                <polyline points="12 5 19 12 12 19" />
              </svg>
            </button>
          </div>
        </div>
      </section>

      {/* ---------------- 7. Home Footer ---------------- */}
      <footer className="home-footer">
        <div className="home-footer-container">
          {/* Left Brand */}
          <div className="footer-brand">
            <div className="hero-box-icon">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z" />
                <path d="m3.3 7 8.7 5 8.7-5" />
                <path d="M12 22V12" />
              </svg>
            </div>
            <span className="footer-brand-name">THREATBOX</span>
          </div>

          {/* Center Links */}
          <div className="footer-nav-links">
            <a href="#features" className="footer-link">Features</a>
            <a href="#how-it-works" className="footer-link">How It Works</a>
            <a href="https://github.com" target="_blank" rel="noreferrer" className="footer-link">GitHub</a>
            <a href="#docs" className="footer-link">Documentation</a>
          </div>

          {/* Right Tagline */}
          <div className="footer-tagline">
            <span className="tagline-divider">|</span>
            <span>Open Source · Built for a Safer Internet</span>
          </div>
        </div>
      </footer>
    </div>
  )
}

export default Home