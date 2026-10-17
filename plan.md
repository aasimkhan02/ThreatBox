# ThreatBox: Full-Stack Integration & Production Website Plan (`plan.md`)

This plan bridges the **ThreatBox** Go backend (`:8080`) with the **React + Vite** frontend (`:5173`), turning the static mock UI into a fully working, real-time malware analysis platform and website.

---

## 1. System Architecture & Current State Audit

```
┌────────────────────────────────────────────────────────┐
│               Frontend (React + Vite)                  │
│  - Home Page (Hero, Tactical Features, Sandbox Demo)   │
│  - Upload Chamber (Drag & Drop, Options, Recents Table)│
│  - Analysis Dashboard (Overview, Process Tree, MITRE)  │
│  - Analysis History (Filters, Search, Job Status)      │
└───────────────────────────┬────────────────────────────┘
                            │ (REST HTTP / WebSocket)
                            ▼
┌────────────────────────────────────────────────────────┐
│             Backend API Gateway (Go :8080)             │
│  - POST /api/samples       (Upload, Hash, Dedup, Queue)│
│  - GET  /api/jobs          (List all jobs & scores)    │
│  - GET  /api/jobs/{id}     (Job status + result_data)  │
│  - PATCH /api/jobs/{id}    (State management)          │
│  - WS   /ws/analysis/{id}  (Live ETW stream broadcast) │
└───────────────────────────┬────────────────────────────┘
                            │
               ┌────────────┴────────────┐
               ▼                         ▼
      PostgreSQL Database       Worker & Sandbox Engine
   (samples, jobs, results)     (ETW, Windows Sandbox, MITRE)
```

### Current Status & Disconnects Identified:
1. **Frontend Disconnect**: The frontend has complete UI mockups (`Upload.jsx`, `Dashboard.jsx`, `History.jsx`), but all tables, metrics, and cards are hardcoded or static. No real HTTP calls (`fetch`/`axios`) or WebSocket connections are currently active.
2. **CORS / Vite Proxy Missing**: Backend runs on `http://localhost:8080` and frontend on `http://localhost:5173`. Without CORS headers or a Vite reverse proxy (`/api`), browser requests will fail due to Same-Origin Policy.
3. **Missing Backend Capabilities**:
   - No CORS middleware on Go HTTP mux.
   - Analysis results data format (`result_data` JSON) needs clear mapping to the dashboard telemetry tabs (Processes, Network, Filesystem, Registry, DNS, MITRE ATT&CK).
   - Incomplete route handling for static file serving when building a unified production binary/container.
   - Need WebSocket endpoint exposure in `main.go` for the existing `internal/analysis/stream` package.

---

## 2. Step-by-Step Implementation Roadmap

### Phase 1: Network & API Plumbing (Backend & Frontend Bridge)
*Goal: Ensure seamless, secure communication between client and server without CORS headaches.*

1. **Vite Development Proxy**:
   - Update `frontend/vite.config.js` to proxy `/api` and `/ws` to `http://localhost:8080`.
   - Allows frontend to call `/api/samples` directly without hardcoding port numbers or environment-specific URLs.
2. **Go Backend CORS & Preflight Middleware**:
   - Wrap the Go `http.ServeMux` with a CORS middleware supporting `OPTIONS`, `GET`, `POST`, `PATCH`, and custom headers (`Content-Type`).
3. **Standardized API Client in Frontend**:
   - Create `frontend/src/api/client.js` with centralized helper functions:
     - `uploadSample(file, options)` -> `POST /api/samples`
     - `getJobs()` -> `GET /api/jobs`
     - `getJobDetails(jobId)` -> `GET /api/jobs/{id}`
     - `subscribeJobStream(jobId, onEvent)` -> `WebSocket /ws/analysis/{id}`

---

### Phase 2: Live Upload & Detonation Chamber
*Goal: Make the upload dropzone actually submit executables, queue jobs, and show detonation progression.*

1. **Real File Ingestion**:
   - In `Upload.jsx`, wire the dropzone & file picker to `POST /api/samples` via `FormData`.
   - Handle response (`job_id`, `status`, `is_duplicate`).
2. **Pre-detonation Feedback**:
   - Add real upload progress bar and SHA-256 calculation state.
   - If the backend returns an existing job (deduplicated sample), present a banner: *"Sample previously analyzed on [Date]. Loading cached report..."* with an option to view or re-run.
3. **Live Detonation & Loading State**:
   - When a job is `pending` or `running`, show an interactive Detonation Progress Overlay:
     - Phase 1: Ingesting binary & computing hashes.
     - Phase 2: Booting Windows Sandbox isolation environment.
     - Phase 3: Executing sample & capturing ETW kernel events.
     - Phase 4: Scoring threat level & MITRE ATT&CK correlation.
   - Poll `GET /api/jobs/{id}` (or listen via WebSocket) until status reaches `completed` or `failed`.
   - Automatically redirect the user to the Analysis Dashboard upon completion.

---

### Phase 3: Real Analysis Dashboard Binding
*Goal: Replace static mock data in `Dashboard.jsx` with real payload data from `GET /api/jobs/{id}`.*

1. **Dashboard Data Transformer**:
   - Create a parser (`frontend/src/utils/formatAnalysis.js`) to parse `JobDetailsResponse`:
     - **Header / Meta**: `original_filename`, `sha256`, `file_size`, `status`, `created_at`, analysis duration.
     - **Threat Score Gauge**: Bind to `result_data.threat_score.score` (0-100) and severity rating.
     - **Behavior Summary**: Extract counts for processes spawned, network endpoints, registry keys touched, and files modified.
     - **Process Tree Tab**: Map `result_data.processes` to parent-child process tree hierarchy.
     - **MITRE ATT&CK Tab**: Map `result_data.mitre_techniques` (technique ID, tactic, evidence description).
     - **Network Tab**: Map `result_data.network_activity` (IP, port, protocol, data transferred).
     - **File Activity Tab**: Filterable list of file operations (`CREATE`, `WRITE`, `DELETE`).
     - **Registry Tab**: Registry key tampering and persistence paths.
     - **DNS & Modules Tabs**: DNS queries and loaded DLLs.
     - **IOC Exporter**: Provide quick buttons to export extracted IOCs (IPs, hashes, domains) as JSON/CSV.
2. **Graceful Fallbacks**:
   - While an analysis is running or if certain telemetry arrays are empty, display clean empty states or skeleton loaders instead of blank or broken screens.

---

### Phase 4: History & Intelligence Feed (`History.jsx` & `Upload.jsx`)
*Goal: Connect the historical analyses table to real database records.*

1. **Real Job History Loading**:
   - Fetch recent analyses from `GET /api/jobs` on mount.
   - Replace the static `allAnalyses` array in `History.jsx` and `recentAnalyses` in `Upload.jsx`.
2. **Filtering, Searching & Pagination**:
   - Client-side or server-side filtering by verdict (`Malicious`, `Suspicious`, `Clean`, `Failed`).
   - Search bar filtering by filename or SHA-256 hash.
   - Clicking any row navigates directly to `Dashboard.jsx` with that job's ID.

---

### Phase 5: Live Event Streaming (WebSocket)
*Goal: Display real-time execution logs as the malware runs inside the sandbox.*

1. **Backend Route**:
   - Register the existing `stream.Server` handler in `main.go` on `/ws/analysis/{id}`.
2. **Frontend HUD**:
   - In `Dashboard.jsx` or during execution in `Upload.jsx`, stream live kernel events into the **Raw Events** console window in real-time.

---

### Phase 6: Unified Production Deployment & Polish
*Goal: Single command to run the whole website seamlessly.*

1. **SPA Static File Serving**:
   - Build frontend assets (`npm run build` in `frontend/dist`).
   - Add a fallback file server handler in Go `main.go` to serve `frontend/dist` on `/` when not in API mode.
2. **Development Scripts**:
   - Create a clean `start-dev.bat` / `npm run dev` script that starts both backend (`go run .`) and frontend (`npm run dev`) simultaneously.

---

## 3. Immediate Action Items (Task Checklist)

- [x] **Config**: Configure Vite proxy in `frontend/vite.config.js`.
- [x] **Backend**: Add CORS headers & register WebSocket route in `main.go`.
- [x] **Frontend API**: Build `frontend/src/api/client.js` with fetch wrappers.
- [x] **Upload Page**: Hook file upload input & submit button to `client.uploadSample()`.
- [x] **Job Polling / HUD**: Implement status polling and loading indicator during sandbox run.
- [x] **Dashboard**: Map dynamic `result_data` JSON to the 10 analysis tabs.
- [ ] **History Table**: Fetch and render real records from `GET /api/jobs`.
- [ ] **Verification**: Test end-to-end flow with sample file upload, processing, and dashboard presentation.
