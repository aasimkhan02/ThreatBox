import React from 'react';
import './Navbar.css';

const Navbar = ({ onGetStarted }) => {
  return (
    <nav className="tactical-navbar">
      <div className="navbar-inner">
        {/* Left: Box logo + Brand */}
        <div className="hero-brand">
          <div className="hero-box-icon">
            <svg
              width="24"
              height="24"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              {/* Isometric / 3D Box Logo */}
              <path d="M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16Z" />
              <path d="m3.3 7 8.7 5 8.7-5" />
              <path d="M12 22V12" />
            </svg>
          </div>
          <span className="hero-brand-name">Threatbox</span>
        </div>

        {/* Center: Navigation Links */}
        <ul className="navbar-links">
          <li>
            <a href="#features" className="navbar-link">Features</a>
          </li>
          <li>
            <a href="#how-it-works" className="navbar-link">How it works</a>
          </li>
          <li>
            <a href="#usecases" className="navbar-link">Usecases</a>
          </li>
          <li>
            <a href="#docs" className="navbar-link">Docs</a>
          </li>
        </ul>

        {/* Right: Get started button with upward arrow */}
        <div className="navbar-action">
          <button
            type="button"
            className="btn-get-started"
            onClick={onGetStarted}
          >
            <span>Get Started</span>
            <span className="btn-arrow-icon">
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
                <line x1="7" y1="17" x2="17" y2="7" />
                <polyline points="7 7 17 7 17 17" />
              </svg>
            </span>
          </button>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
