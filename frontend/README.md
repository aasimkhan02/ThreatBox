# 🖥️ ThreatBox Frontend

Tactical, cybersecurity-focused Single Page Application (SPA) dashboard for **ThreatBox**, built with **React 18** and **Vite 6**.

---

## ⚡ Highlights

- **Tactical Dark HUD Aesthetic**: Styled with cybersecurity operations center visual hierarchy.
- **Detonation Chamber**: Interactive drag-and-drop sample submission with live detonation progress feedback.
- **10 Dedicated Intelligence Tabs**:
  - **Overview**: Executive summary, animated threat score gauge, and AI analysis report.
  - **Behavior**: Execution timeline and suspicious indicator counters.
  - **Processes**: Interactive hierarchical parent-child process tree with PID/PPID and CLI arguments.
  - **File System**: Granular file creates, writes, renames, and deletions.
  - **Network**: Outbound socket connections, destination ports, protocols, and data transferred.
  - **DNS**: Intercepted `Microsoft-Windows-DNS-Client` queries, query types, and resolved IP addresses.
  - **Modules**: Executable images and loaded DLLs categorized by system vs. writable user space.
  - **MITRE ATT&CK**: Matrix mapping techniques with tactic badges and telemetry evidence citations.
  - **IOCs**: Indicators of Compromise (SHA-256, MD5, Imphash, C2 IPs, domains, modified files, persistence registry keys) with JSON/CSV export.
  - **Raw Events**: High-volume kernel ETW JSONL telemetry stream with search filtering.
- **Built-in Demo Engine**: Seamlessly demo realistic threat scenarios (Ransomware, InfoStealer, Dropper, Benign) without needing a live Windows Sandbox backend or dangerous binaries.

---

## 🚀 Quickstart

### Prerequisites
- Node.js 18+
- npm or yarn

### Installation
```bash
npm install
```

### Development Server
```bash
npm run dev
```
Runs at `http://localhost:5173`. Proxies `/api` and `/ws` to the ThreatBox Go backend at `http://localhost:8080`.

### Production Build
```bash
npm run build
```
Generates production-optimized static assets in `dist/`.

---

## 📂 Project Structure

```
frontend/src/
├── api/             # Centralized API client (fetch wrappers for /api/samples, /api/jobs)
├── assets/          # High-resolution screenshots, tactical diagrams, and icons
├── components/
│   ├── dashboard/   # 10-tab analysis dashboard, circular score gauge, process tree
│   ├── history/     # Historical analyses table with search and severity filters
│   ├── layout/      # Navbar and tactical HUD Sidebar
│   └── upload/      # Drag & drop detonation dropzone and live loading overlay
├── demo/            # Synthetic threat fixtures (Ransomware, Stealer, Dropper, Benign)
├── pages/
│   └── home/        # Hero landing page with tactical annotations and CTA
└── utils/           # Data transformation and telemetry formatting helpers
```
