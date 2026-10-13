import React from 'react';

const Footer = () => {
  return (
    <footer className="tactical-footer">
      <div className="footer-container">
        <div className="footer-grid">
          {/* Brand Info */}
          <div className="footer-brand">
            <div className="footer-logo">
              <span className="logo-glitch">THREATBOX</span>
            </div>
            <p className="footer-desc">
              Automated dynamic malware detonation platform and telemetry sandbox 
              for enterprise SecOps, kernel reverse engineers, and incident responders.
            </p>
            <div className="footer-tags">
              <span className="tech-tag">SOC2_TYPE_II</span>
              <span className="tech-tag">AIR_GAPPED</span>
              <span className="tech-tag">HARDWARE_VMX</span>
            </div>
          </div>

          {/* Column 1 */}
          <div className="footer-col">
            <h4 className="footer-heading">DETONATION ENGINES</h4>
            <ul className="footer-links">
              <li><a href="#hypervisor">Hypervisor Sandbox</a></li>
              <li><a href="#baremetal">Bare Metal Detonator</a></li>
              <li><a href="#memory">Memory Dump Inspection</a></li>
              <li><a href="#mitre">Automated MITRE Heatmap</a></li>
              <li><a href="#pcap">Network PCAP Deep Inspection</a></li>
            </ul>
          </div>

          {/* Column 2 */}
          <div className="footer-col">
            <h4 className="footer-heading">THREAT INTELLIGENCE</h4>
            <ul className="footer-links">
              <li><a href="#mitre">MITRE ATT&CK Matrix</a></li>
              <li><a href="#yara">YARA Signature Engine</a></li>
              <li><a href="#ioc">IOC Threat Feeds</a></li>
              <li><a href="#virustotal">Hybrid Virus Feeds</a></li>
              <li><a href="#rules">Sigma Rule Repository</a></li>
            </ul>
          </div>

          {/* Column 3 */}
          <div className="footer-col">
            <h4 className="footer-heading">DEVELOPER & SOC</h4>
            <ul className="footer-links">
              <li><a href="#api">REST Telemetry API</a></li>
              <li><a href="#sdk">Python SDK Client</a></li>
              <li><a href="#soar">SOAR Webhook Integrations</a></li>
              <li><a href="#cli">CLI Automation Tool</a></li>
              <li><a href="#github">Open Ruleset GitHub</a></li>
            </ul>
          </div>
        </div>

        {/* Bottom Status Bar */}
        <div className="footer-bottom">
          <div className="footer-status-pills">
            <span className="status-pill"><span className="pulse-dot active"></span> SYSTEM STATUS: ALL CLUSTERS OPERATIONAL</span>
            <span className="status-pill">ENGINE VERSION: v3.4.1-PROD</span>
            <span className="status-pill">PROTOCOL: AIR-GAPPED VM</span>
          </div>

          <div className="footer-legal">
            <span>© 2026 ThreatBox Inc. All Systems Armed & Operational.</span>
            <div className="legal-links">
              <a href="#privacy">Privacy Policy</a>
              <a href="#terms">Terms of Service</a>
              <a href="#security">Security Whitepaper</a>
            </div>
          </div>
        </div>
      </div>
    </footer>
  );
};

export default Footer;
