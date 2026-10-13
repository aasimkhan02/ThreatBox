import React from 'react';
import './layout/Navbar.css';

const Navbar = () => {
  return (
    <nav className="tactical-navbar">
      <div className="navbar-inner">
        <div className="hero-brand">
          <div className="hero-reticle">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
              <path d="M7 4H4v3" stroke="#FF1744" strokeWidth="2.5" strokeLinecap="square" />
              <path d="M17 4h3v3" stroke="#FF1744" strokeWidth="2.5" strokeLinecap="square" />
              <path d="M7 20H4v-3" stroke="#FF1744" strokeWidth="2.5" strokeLinecap="square" />
              <path d="M17 20h3v-3" stroke="#FF1744" strokeWidth="2.5" strokeLinecap="square" />
            </svg>
          </div>
          <span className="hero-brand-name">THREATBOX</span>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
