# 🛡️ ThreatBox

<div align="center">

### Automated Dynamic Malware Analysis Platform & Hypervisor Detonation Chamber

[![Go Version](https://img.shields.io/badge/Go-1.25+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-6.0-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)](https://www.postgresql.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-FF6B6B?style=for-the-badge&logo=target&logoColor=white)](https://attack.mitre.org)
[![Windows Sandbox](https://img.shields.io/badge/Platform-Windows%20Sandbox%20%2F%20ETW-0078D6?style=for-the-badge&logo=windows&logoColor=white)](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

<p align="center">
  <b>Safely detonate untrusted binaries &bull; Trace deep kernel-level telemetry via ETW &bull; Map behaviors to MITRE ATT&CK &bull; Generate hardened AI threat intelligence reports</b>
</p>

[Key Features](#-key-features) •
[Architecture](#-system-architecture) •
[Interactive Demo Mode](#-try-it-instantly-demo-mode) •
[Telemetry & Detection](#-telemetry--detection-capabilities) •
[AI Hardening](#-adversarially-hardened-ai-reporting) •
[Getting Started](#-getting-started) •
[API Reference](#-rest-api-reference)

---

</div>

<div align="center">
  <img src="frontend/src/assets/dashboard.png" alt="ThreatBox Security Operations Dashboard" width="950" style="border-radius: 8px; box-shadow: 0 8px 24px rgba(0,0,0,0.5);" />
</div>

---

## 📌 Executive Summary

**ThreatBox** is an enterprise-grade, local-first dynamic malware analysis platform and detonation chamber. Designed for reverse engineers, SOC analysts, and incident responders, ThreatBox bridges low-level Windows kernel instrumentation with modern threat intelligence.

Traditional malware sandboxes are either cloud-dependent—risking sensitive data leakage and incurring hefty subscription fees—or rely on fragile userland API hooking easily circumvented by evasion techniques. ThreatBox takes a radically different approach:

1. **Hypervisor Isolation**: Executes untrusted binaries inside disposable, ephemeral **Windows Sandbox (WSB)** micro-virtual machines, ensuring the host machine remains completely untouched.
2. **Kernel-Level Instrumentation**: Bypasses userland anti-hooking tricks by listening directly to **Event Tracing for Windows (ETW)** kernel trace sessions (processes, threads, file I/O, TCP/UDP sockets, registry modifications, image loads, and DNS client requests).
3. **Advanced Temporal Process Attribution**: Solves the notorious Windows PID recycling dilemma through full process and thread lifecycle modeling, accurately linking malicious actions across complex parent-child-grandchild execution trees.
4. **Deterministic ATT&CK Correlation**: Automatically translates raw kernel events into structured **MITRE ATT&CK®** techniques, calculating a transparent 0–100 threat score based on empirical evidence.
5. **Adversarially Hardened Local AI**: Synthesizes structured security evidence into executive summaries via local LLMs (Ollama / Qwen 2.5), shielded with strict prompt-injection defenses and anti-hallucination validation guards.
6. **Tactical SOC Interface**: A high-contrast, military-grade dark theme HUD built with React and Vite, featuring 10 dedicated analysis tabs and a built-in **zero-setup Demo Mode** for instant recruiter and evaluator inspection.

---

## ⚡ Key Features

<table>
  <tr>
    <td width="50%">
      <h3>🔬 Disposable Hypervisor Detonation</h3>
      <ul>
        <li>Dynamically generates isolated <code>.wsb</code> profiles with read-only host shares.</li>
        <li>Automated guest agent orchestrates sample launch, telemetry collection, and graceful shutdown.</li>
        <li>Strict execution watchdogs and timeouts guarantee zero host contamination or hanging VM tasks.</li>
      </ul>
    </td>
    <td width="50%">
      <h3>📡 Kernel ETW Telemetry Collector</h3>
      <ul>
        <li>High-throughput Go collector written over native Windows NT Kernel trace sessions.</li>
        <li>Intercepts Process, Thread, File, TCP/UDP Network, Registry, Image Load, and DNS events.</li>
        <li>High-speed JSONL streaming pipeline equipped with lost-event monitoring and buffer flushing.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🌳 Anti-Evasion Process Attribution</h3>
      <ul>
        <li>Overcomes Windows PID reuse by maintaining temporal process and thread lifetimes.</li>
        <li>Distinguishes pre-existing rundown processes from dynamically spawned malware trees.</li>
        <li>Accurately correlates short-lived droppers, shell spawners, and hollowed targets.</li>
      </ul>
    </td>
    <td width="50%">
      <h3>🎯 MITRE ATT&CK® Matrix Mapping</h3>
      <ul>
        <li>Correlates behaviors with Enterprise ATT&CK techniques (T1059, T1547, T1218, T1574, T1071).</li>
        <li>Detects Living-off-the-Land Binaries (LOLBins: <code>mshta</code>, <code>rundll32</code>, <code>regsvr32</code>, <code>installutil</code>).</li>
        <li>Identifies DLL side-loading through write-then-load temporal analysis across user-writable paths.</li>
      </ul>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h3>🛡️ Prompt-Injection-Hardened AI</h3>
      <ul>
        <li>Local, privacy-preserving LLM reporting powered by Ollama (Qwen 2.5 / customizable).</li>
        <li>Telemetry inputs treated strictly as untrusted data strings, immune to malicious instruction overrides.</li>
        <li>Regex guardrails enforce strict grounding: no hallucinated PIDs, false techniques, or score shifts.</li>
      </ul>
    </td>
    <td width="50%">
      <h3>📊 Tactical 10-Tab SOC Dashboard</h3>
      <ul>
        <li>Overview with animated Threat Score gauge and dynamic severity verdict.</li>
        <li>Interactive parent-child process tree hierarchy with command-line arguments.</li>
        <li>Automated IOC extractor with one-click JSON/CSV exports for immediate SIEM/EDR blocklisting.</li>
      </ul>
    </td>
  </tr>
</table>

---

## 🚀 Try It Instantly (Demo Mode)

Evaluating ThreatBox doesn't require setting up a Windows Sandbox or handling dangerous live malware binaries!

ThreatBox ships with a comprehensive **Client-Side Simulation & Demo Engine** pre-loaded with four realistic, schema-accurate threat scenarios:

```
┌──────────────────────────┬─────────────────────────────┬──────────────────────────────────────────────────┐
│ Profile                  │ Threat Score                │ Key Behaviors Simulated                          │
├──────────────────────────┼─────────────────────────────┼──────────────────────────────────────────────────┤
│ 🏴‍☠️ Ransomware Attack     │ Critical (96/100)           │ VSS shadow deletion (vssadmin), mass encryption  │
│                          │                             │ (.locked), C2 killswitch, Run key persistence    │
├──────────────────────────┼─────────────────────────────┼──────────────────────────────────────────────────┤
│ 🕵️ InfoStealer / Trojan   │ High (82/100)               │ Chrome/Edge DPAPI credential scraping, memory    │
│                          │                             │ injection (T1055), base64 exfiltration over HTTP │
├──────────────────────────┼─────────────────────────────┼──────────────────────────────────────────────────┤
│ 💉 Staged Dropper        │ Medium (48/100)             │ Encoded PowerShell cradle, LOLBin proxy execution│
│                          │                             │ via regsvr32, temp directory DLL drop            │
├──────────────────────────┼─────────────────────────────┼──────────────────────────────────────────────────┤
│ 🟢 Clean Benign Tool     │ Clean (0/100)               │ Harmless file utilities and standard runtime DLLs│
│                          │                             │ demonstrating zero false-positive scoring        │
└──────────────────────────┴─────────────────────────────┴──────────────────────────────────────────────────┘
```

> **To test immediately:**
> 1. Launch the frontend: `cd frontend && npm install && npm run dev`
> 2. Open `http://localhost:5173` and click **"Get Started"** or explore any demo sample directly in the dashboard!

---

## 🏗️ System Architecture

ThreatBox is built on a modular, decoupled architecture where each layer isolates untrusted code and maintains strict security boundaries:

```mermaid
flowchart TD
    subgraph UI ["Client Layer (Browser)"]
        FE["React 18 + Vite HUD\n(10 Telemetry Tabs, Realtime Detonation HUD)"]
    end

    subgraph Host ["Host System (Go Backend & Orchestrator)"]
        API["Go HTTP REST API (:8080)\n(CORS, Mutex Job Controller, Hash Dedup)"]
        PG[("PostgreSQL 16\nSamples, Jobs, JSONB Analysis Results")]
        Worker["Job Worker Daemon\n(SKIP LOCKED Queue, Heartbeat Leases)"]
        Engine["Attribution & Scoring Engine\n(PID Lifetime Resolution, MITRE Rules)"]
        AI["Adversarially Hardened AI\n(Ollama / Qwen 2.5 with Anti-Hallucination Guards)"]
    end

    subgraph Sandbox ["Isolated Hypervisor (Windows Sandbox WSB)"]
        WSB["Disposable MicroVM Environment"]
        Agent["ThreatBox Guest Agent (sandbox-agent.exe)"]
        ETW["Kernel ETW Collector (etw-collector.exe)"]
        Malware["Untrusted Binary Detonation (sample.exe)"]
    end

    FE -->|"1. Upload Sample / Poll Status"| API
    API -->|"2. Deduplicate SHA-256 & Enqueue"| PG
    Worker -->|"3. Claim Job (FOR UPDATE SKIP LOCKED)"| PG
    Worker -->|"4. Provision .wsb & Mount Shared Workspace"| WSB
    WSB --> Agent
    Agent -->|"5. Start Kernel NT Session"| ETW
    Agent -->|"6. Detonate with Watchdog"| Malware
    ETW -.->|"7. Intercept Kernel Events (Proc/File/Net/DNS/Reg)"| Malware
    Agent -->|"8. Flush events.jsonl"| Worker
    Worker -->|"9. Reconstruct Tree & Attributions"| Engine
    Engine -->|"10. MITRE Mapping & Threat Scoring"| AI
    AI -->|"11. Save Unified Result Data (JSONB)"| PG
    API -->|"12. Stream Telemetry & Dashboard View"| FE

    style UI fill:#0d1117,stroke:#58a6ff,stroke-width:2px,color:#fff
    style Host fill:#161b22,stroke:#2ea043,stroke-width:2px,color:#fff
    style Sandbox fill:#1f1322,stroke:#f85149,stroke-width:2px,color:#fff
```

### Architectural Deep-Dive

#### 1. Transactional Queue & Self-Healing Worker
The Go backend implements a resilient concurrency model backed by PostgreSQL:
- **Lock-Free Concurrency**: Jobs are claimed via `WITH next_job AS (SELECT job_id FROM jobs WHERE status = 'pending' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE jobs ... RETURNING job_id`. This allows multiple workers to run concurrently without race conditions.
- **Heartbeat Leasing**: Active workers maintain an asynchronous ticker (`keepJobLeaseAlive`) updating the job's `updated_at` timestamp.
- **Orphan Recovery**: A background sweeper (`RecoverStaleJobs`) automatically identifies abandoned jobs caused by ungraceful crashes and resets them for re-execution.

#### 2. Temporal Process Attribution & PID Reuse Solver
Windows aggressively recycles Process IDs (PIDs). A simplistic mapping of `PID -> Process Name` will misattribute background OS activity to malware or confuse parent-child relationships. ThreatBox solves this:
- **Process & Thread Lifetime Intervals**: Captures `ProcessStart`, `ProcessStop`, `ThreadStart`, and `ThreadStop` events with microsecond timestamps and chronological sequence numbering.
- **Rundown Disambiguation**: Tracks pre-existing system processes captured during ETW rundown so they are never misclassified as newly spawned malware children.
- **Attribution Verification**: Telemetry events (file modifications, network connections, registry tampering) are attributed to the specific process instance whose `[Start, Stop]` interval encapsulates the event timestamp.

---

## 📸 Interface Tour

<div align="center">

| Executive Overview & Threat Score | Interactive Process Hierarchy Tree |
| :---: | :---: |
| <img src="frontend/src/assets/dashboard.png" width="450" /> | <img src="frontend/src/assets/processes.png" width="450" /> |
| *0–100 Severity gauge, summary cards & AI analysis* | *Deep parent-child lineage with command lines & PIDs* |

| MITRE ATT&CK Matrix Mapping | File System Operations Filter |
| :---: | :---: |
| <img src="frontend/src/assets/mitre.png" width="450" /> | <img src="frontend/src/assets/filesystem.png" width="450" /> |
| *Enterprise tactics, techniques & correlated evidence* | *Granular file create, modify, rename & delete operations* |

| Network & DNS Telemetry | Extracted IOCs & Instant Export |
| :---: | :---: |
| <img src="frontend/src/assets/network.png" width="450" /> | <img src="frontend/src/assets/ioc.png" width="450" /> |
| *Outbound connections, destination ports & DNS lookups* | *C2 IPs, hashes, domains & registry persistence keys* |

</div>

---

## 🎯 Telemetry & Detection Capabilities

ThreatBox correlates low-level kernel activities directly into the **MITRE ATT&CK®** framework using deterministic, multi-stage heuristics:

```
┌───────────────┬────────────────────────────┬─────────────────────────────────────────────────────────┐
│ Technique ID  │ ATT&CK Technique Name      │ Detection Heuristic & Telemetry Grounding               │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1059.001     │ PowerShell Execution       │ Spawning of powershell.exe / pwsh.exe by sample tree     │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1059.003     │ Windows Command Shell      │ Execution of cmd.exe with embedded commands             │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1059.006     │ Python Script Execution    │ Spawning of python.exe or pythonw.exe child processes   │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1547.001     │ Registry Run Keys          │ Modification or creation of values under                │
│               │ (Autostart Persistence)    │ \Microsoft\Windows\CurrentVersion\Run                   │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1218.004     │ InstallUtil Proxy Exec     │ Microsoft InstallUtil executing binaries in temp folders │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1218.005     │ Mshta Proxy Execution      │ Mshta executing inline script: or web-hosted resources  │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1218.007     │ Msiexec Proxy Execution    │ Msiexec executing remote or untrusted .msi packages     │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1218.010     │ Regsvr32 (Squiblydoo)      │ Regsvr32 invoking scrobj.dll or remote .sct scriptlets  │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1218.011     │ Rundll32 Proxy Execution   │ Rundll32 executing DLLs residing in writable user paths │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1574.002     │ DLL Side-Loading           │ Correlation: DLL write in writable path (\Temp, \Users) │
│               │ (High-Confidence Match)    │ followed by DLL load from distinct process image        │
├───────────────┼────────────────────────────┼─────────────────────────────────────────────────────────┤
│ T1071.004     │ DNS Exfiltration / DGA     │ DNS queries exhibiting anomalous label lengths (>40),   │
│               │                            │ high digit-to-letter ratios, or encoded entropy mixes   │
└───────────────┴────────────────────────────┴─────────────────────────────────────────────────────────┘
```

### Deterministic Threat Scoring Formula
Threat scores are not opaque black-box predictions. ThreatBox uses an explainable, rule-based point accumulation model:

$$\text{Threat Score} = \min\left(100, \sum_{i} \text{Points}(\text{Rule}_i)\right)$$

| Score Range | Severity Level | Typical Action |
|:---:|:---:|:---|
| **75 – 100** | **Critical** | Immediate incident response, host isolation, endpoint blocking |
| **50 – 74** | **High** | Strong evidence of malicious intent (persistence, LOLBins, DGA) |
| **25 – 49** | **Medium** | Suspicious indicators requiring analyst triage (script spawns) |
| **0 – 24** | **Clean / Low** | Standard utility behaviors, zero persistence, clean reputation |

---

## 🛡️ Adversarially Hardened AI Reporting

Many security tools blindly feed untrusted strings from malware (like embedded strings, window titles, or paths) into an LLM. ThreatBox defends against **Indirect Prompt Injection** and **AI Hallucinations** through a hardened pipeline (`ai_report.go`):

1. **Strict Context Isolation**: Prompt templates clearly instruct the model that all JSON evidence represents untrusted data artifacts, never natural language commands.
2. **Deterministic Evidence Bounding**: Evidence sets are summarized deterministically before prompt construction, preventing truncation from being misread as an absence of behavior.
3. **Regex Sanity & Verdict Enforcement**:
   - The LLM is **forbidden** from independently fabricating verdicts or overriding the deterministic threat score.
   - Guard filters verify that any mentioned PIDs, file indicators, or technique IDs exist in the verified ground-truth telemetry.
   - If the local model encounters an error or violates guardrails, the analysis pipeline gracefully falls back to deterministic telemetry without crashing.

---

## 💻 Tech Stack

| Domain | Technology | Purpose |
|:---|:---|:---|
| **Backend Language** | **Go (Golang 1.25+)** | High-performance API server, worker daemon, and analysis engine |
| **Database** | **PostgreSQL 16 + pgx/v5** | Relational metadata store, ACID job queue, JSONB telemetry documents |
| **Virtualization** | **Windows Sandbox (WSB)** | Hypervisor-isolated, lightweight, disposable execution environment |
| **Telemetry** | **Event Tracing for Windows (ETW)** | Kernel NT trace sessions (Process, File, TCP/UDP, Registry, DNS) |
| **Frontend Framework** | **React 18 + Vite 6** | Ultra-responsive Single Page Application (SPA) with tactical styling |
| **Local AI** | **Ollama (Qwen 2.5:1.5b / Customizable)** | Local, offline, privacy-safe threat report generation |
| **Validation** | **Accuracy Test Suite** | Benign ground-truth test fixtures measuring Recall and Precision |

---

## 🛠️ Getting Started

### Prerequisites
- **Host OS**: Windows 10/11 Pro, Enterprise, or Education (required for Windows Sandbox and ETW tracing)
- **Windows Features**: Enable **Windows Sandbox** via `OptionalFeatures.exe` or PowerShell:
  ```powershell
  Enable-WindowsOptionalFeature -FeatureName "Containers-DisposableClientVM" -All -Online
  ```
- **Go**: Version 1.25 or later ([Download Go](https://golang.org/dl/))
- **Node.js**: Version 18+ and npm ([Download Node.js](https://nodejs.org/))
- **PostgreSQL**: Version 15+ ([Download PostgreSQL](https://www.postgresql.org/download/))
- **Ollama** *(Optional for AI summaries)*: ([Download Ollama](https://ollama.ai/))

---

### Step 1: Clone Repository
```powershell
git clone https://github.com/aasimkhan02/ThreatBox.git
cd ThreatBox
```

### Step 2: Configure Environment Variables
Create a `.env` file in the project root:
```env
# Database Connection URL
DATABASE_URL=postgres://postgres:yourpassword@localhost:5432/threatbox?sslmode=disable

# Sandbox Runtime Directories
THREATBOX_RUNTIME_ROOT=C:\ThreatBox\runtime\jobs
THREATBOX_SANDBOX_TOOLS=C:\ThreatBoxSandbox
THREATBOX_SANDBOX_TIMEOUT_MIN=15

# AI Report Configuration (Optional)
THREATBOX_AI_ENABLED=true
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=qwen2.5:1.5b
```

### Step 3: Compile Sandbox In-Guest Tools
Build and deploy the kernel collector and guest agent binaries:
```powershell
.\scripts\build-sandbox-tools.ps1
```
*This compiles `etw-collector.exe` and `sandbox-agent.exe` and deploys them to `C:\ThreatBoxSandbox`.*

### Step 4: Run Database Migrations & Start Backend
```powershell
go run .
```
*ThreatBox automatically applies database migrations from `migrations/` and binds to `http://localhost:8080`.*

### Step 5: Start Frontend Dashboard
In a separate terminal:
```powershell
cd frontend
npm install
npm run dev
```
Open **`http://localhost:5173`** in your browser.

---

## 🔌 REST API Reference

The Go backend exposes a clean REST API:

```
┌────────┬──────────────────────┬────────────────────────────────────────────────────────┐
│ Method │ Endpoint             │ Description                                            │
├────────┼──────────────────────┼────────────────────────────────────────────────────────┤
│ POST   │ /api/samples         │ Multipart upload of binary sample. Hashes & enqueues.  │
├────────┼──────────────────────┼────────────────────────────────────────────────────────┤
│ GET    │ /api/jobs            │ Lists all analysis jobs with status & threat scores.   │
├────────┼──────────────────────┼────────────────────────────────────────────────────────┤
│ GET    │ /api/jobs/{id}       │ Returns job metadata, full telemetry, and AI report.   │
├────────┼──────────────────────┼────────────────────────────────────────────────────────┤
│ PATCH  │ /api/jobs/{id}       │ Updates job status or worker state flags.              │
└────────┴──────────────────────┴────────────────────────────────────────────────────────┘
```

### Sample Ingestion Request
```bash
curl -X POST http://localhost:8080/api/samples \
  -F "file=@malware_sample.exe"
```

### Response
```json
{
  "job_id": "4d59a842-8fb1-4322-83b6-2fa9418432a1",
  "sample_id": "89eb5bca-3260-4963-b8a7-e8ea47683ca5",
  "filename": "malware_sample.exe",
  "sha256": "9b71d224bd62f3785d96d46ad3ea3d733158c35b",
  "status": "pending"
}
```

---

## 🧪 Rigorous Accuracy & Verification Testing

ThreatBox includes dedicated benign ground-truth test fixtures (`tools/threatbox-accuracy-tests/`):
- **`file-ops`**: Performs known file creates, reads, renames, and deletions.
- **`process-tree`**: Spawns known multi-generational child processes with recorded PIDs.
- **`mitre-shells`**: Evaluates positive vs. negative shell execution to verify zero false-positives under benign conditions.

Every test binary outputs a verifiable `GROUND_TRUTH` JSON ledger, allowing continuous measurement of:
- **Recall**: Detected ground-truth actions / Expected observable actions.
- **Precision**: Validated reported actions / All reported actions.
- **Attribution Accuracy**: Correctly mapped parent-child nodes / Total evaluated events.

---

## 🔒 Security & Safe Handling Notice

ThreatBox is designed to analyze potentially destructive malware:
- Always run ThreatBox on dedicated analysis workstations or test machines.
- Never configure the sandbox tool share with write privileges to host directories.
- Keep the Windows host operating system fully updated with active endpoint protections.
- Use the included **Demo Mode** for presentations, portfolio walkthroughs, and UI demonstrations.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) — free for personal, academic, and commercial research use.

---

<div align="center">
  <sub>Engineered with precision for modern malware analysis &bull; Crafted by <a href="https://github.com/aasimkhan02">Aasim Khan</a></sub>
</div>

