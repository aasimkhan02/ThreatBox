# Maltrace

## Local Dynamic Malware Analysis Platform

Maltrace is a **self-hosted dynamic malware-analysis platform** designed as a portfolio and open-source project rather than a commercial cloud service.

The user runs Maltrace on their own computer. The application uses the user's local resources to safely execute an untrusted Linux executable inside an isolated sandbox, observe its runtime behavior, convert observations into structured security evidence, and present the results through an analyst-oriented interface.

The core idea is:

```text
Suspicious executable
        ↓
Local Maltrace application
        ↓
Isolated sandbox
        ↓
Execution
        ↓
Behavioral monitoring
        ↓
Structured events
        ↓
Security findings
        ↓
IOC / MITRE / threat scoring
        ↓
Human-readable report
```

The project is intentionally designed to run on modest hardware.

The initial implementation should support **one analysis at a time**, use local storage, and avoid requiring cloud infrastructure, Kubernetes, GPUs, or expensive services.

---

# 1. Project Goal

Maltrace is not primarily an "AI malware scanner."

It is a **local security-analysis system** whose main job is:

> Safely execute untrusted software, observe what it does, turn those observations into evidence, and help an analyst understand that evidence.

The LLM is an optional final reporting layer.

The important engineering underneath it is:

- Go backend engineering
- Linux internals
- process and system-call observation
- virtualization
- sandbox isolation
- event processing
- asynchronous jobs
- persistent storage
- security analysis
- real-time streaming

---

# 2. Why Maltrace Exists

A security analyst may receive an unknown executable:

```text
invoice.elf
```

They need to determine whether it behaves suspiciously.

Running an unknown executable directly on the analyst's main operating system is unsafe because software may:

- Create or terminate processes
- Create, modify, or delete files
- Modify system configuration
- Establish network connections
- Attempt persistence
- Access credentials or sensitive information
- Inject into other processes
- Execute additional programs

Maltrace provides a controlled environment where the executable can run while its behavior is observed.

---

# 3. Dynamic vs Static Analysis

## Static Analysis

Static analysis examines a sample without executing it.

Examples:

```text
File hash
Strings
ELF headers
Imports
Metadata
Disassembly
```

Static analysis can provide useful information, but it does not directly show what the program actually does at runtime.

## Dynamic Analysis

Dynamic analysis executes the sample inside a controlled environment and observes its behavior.

```text
Executable
    ↓
Sandbox
    ↓
Execution
    ↓
Runtime behavior
```

Maltrace is primarily a **dynamic analysis** platform.

Static analysis may be added later.

---

# 4. Initial Scope

The first version of Maltrace targets:

> **Linux ELF executable analysis using Firecracker microVMs.**

This keeps the project realistic for a personal laptop and avoids attempting to support every operating system at once.

Windows analysis should be treated as a future sandbox backend.

Windows-specific behavior such as:

- Registry modifications
- Windows services
- DLL loading
- Windows process injection

requires a Windows-capable execution environment and should not be faked by the Linux implementation.

---

# 5. Local-First Architecture

Unlike a cloud malware-analysis service, Maltrace is designed to run on the user's own computer.

```text
                 USER'S COMPUTER
┌─────────────────────────────────────────────┐
│                                             │
│              Maltrace Application           │
│                                             │
│   React UI                                  │
│      │                                      │
│      ▼                                      │
│   Go Engine / API                           │
│      │                                      │
│      ├── Local Storage                      │
│      ├── Database                           │
│      ├── Job Manager                        │
│      └── Sandbox Manager                    │
│                    │                        │
│                    ▼                        │
│             Firecracker MicroVM             │
│                    │                        │
│                    ▼                        │
│              Linux Guest                    │
│                    │                        │
│                    ▼                        │
│             Sample Executes                │
│                    │                        │
│                    ▼                        │
│             Event Collector                 │
│                    │                        │
│                    ▼                        │
│             Analysis Engine                 │
│                    │                        │
│          ┌─────────┼─────────┐              │
│          ▼         ▼         ▼              │
│        IOCs      MITRE     Score             │
│          │         │         │              │
│          └─────────┼─────────┘              │
│                    ▼                        │
│              Report Engine                  │
│                                             │
└─────────────────────────────────────────────┘
```

There is no requirement for:

- AWS
- Kubernetes
- cloud GPUs
- multiple servers
- distributed cloud infrastructure

The user supplies the CPU, RAM, disk, and virtualization support.

---

# 6. Resource-Constrained Design

The project is explicitly designed for a normal development laptop.

Initial limits should be configurable:

```text
Maximum upload size: 50 MB
Maximum analysis duration: 30 seconds
Maximum concurrent analyses: 1
Maximum VM memory: configurable
Maximum VM CPU: configurable
```

These are engineering defaults, not hard security guarantees.

The architecture should support future scaling, but the local implementation does not need to run multiple VMs simultaneously.

A strong design principle is:

> **Build scalable abstractions without paying for scalable infrastructure.**

For example, the code can use an analysis-job abstraction and worker interface even if the local deployment only has one worker.

---

# 7. Security Boundary

The computer running Maltrace is also the computer that must be protected from the sample.

Therefore:

```text
Host OS
   │
   ├── Maltrace
   │
   └── Isolated Sandbox
          │
          └── Untrusted Sample
```

The sample must never simply be executed directly by the host application.

For example, the application should never casually do:

```go
exec.Command("./uploaded-file")
```

on the host.

Execution belongs inside the sandbox.

---

# 8. Why Virtualization?

A container shares the host kernel:

```text
Host OS
   │
   └── Container
          │
          └── Sample
```

A virtual machine provides a stronger boundary:

```text
Host
   │
   └── Virtual Machine
          │
          └── Guest OS
                 │
                 └── Sample
```

For malware analysis, a VM-based isolation boundary is preferable because the sample does not directly share the host kernel.

---

# 9. Firecracker

Firecracker provides lightweight microVMs designed for workloads requiring VM-level isolation with low overhead.

Maltrace uses Firecracker as the initial sandbox backend.

The intended lifecycle is:

```text
Create MicroVM
      ↓
Configure environment
      ↓
Configure networking
      ↓
Start MicroVM
      ↓
Start monitoring
      ↓
Transfer sample
      ↓
Execute sample
      ↓
Collect events
      ↓
Stop MicroVM
      ↓
Destroy MicroVM
```

The VM should be disposable.

A completed analysis environment should not be treated as a permanent machine.

---

# 10. Local Application Model

The first version should behave like a local application.

Initially, it can simply run:

```text
Maltrace Go server
        ↓
localhost
        ↓
React dashboard
```

For example:

```text
http://localhost:8080
```

The browser is only the user interface.

The Go process performs the actual application work.

Later, Maltrace can be packaged as a desktop application.

Possible future approach:

```text
Go + React
      ↓
Desktop packaging
      ↓
Maltrace.exe
```

A framework such as Wails could be considered later.

Do not make desktop packaging a first milestone.

---

# 11. Core Architecture

```text
                    React Dashboard
                           │
                    HTTP / WebSocket
                           │
                           ▼
                    ┌─────────────┐
                    │   Go API    │
                    └──────┬──────┘
                           │
             ┌─────────────┼─────────────┐
             │             │             │
             ▼             ▼             ▼
        File Storage    Database     Job Manager
             │             │             │
             │             │             ▼
             │             │          Local Worker
             │             │             │
             │             │             ▼
             │             │       Firecracker VM
             │             │             │
             │             │             ▼
             │             │        Sample Runs
             │             │             │
             │             │             ▼
             │             │      Behavioral Monitor
             │             │             │
             │             └─────────────┤
             │                           ▼
             │                     Event Collector
             │                           │
             └───────────────────────────┤
                                         ▼
                                  Event Processor
                                         │
                              ┌──────────┼──────────┐
                              ▼          ▼          ▼
                            IOCs       MITRE      Score
                              │          │          │
                              └──────────┼──────────┘
                                         ▼
                                  Structured Findings
                                         │
                                         ▼
                                   Report Generation
                                         │
                                         ▼
                                   React Dashboard
```

The architecture separates:

1. Control
2. Execution
3. Observation
4. Analysis
5. Presentation

---

# 12. Module Roadmap

The project should be built as a sequence of increasingly capable modules.

Do not build everything at once.

---

## Module 1 — File Upload

### Goal

Allow a user to upload an executable.

Endpoint:

```text
POST /samples
```

Flow:

```text
HTTP Request
    ↓
Multipart Upload
    ↓
Validate Size
    ↓
Calculate SHA-256
    ↓
Save File
    ↓
Return Metadata
```

Example response:

```json
{
  "id": "sample_123",
  "filename": "suspicious.elf",
  "size": 182394,
  "sha256": "abc123...",
  "status": "uploaded"
}
```

### Learn

- Go `net/http`
- multipart forms
- request bodies
- `io.Reader`
- file I/O
- SHA-256
- HTTP status codes
- validation
- error handling

### Important

Do not execute uploaded files.

This module only:

```text
Receive
→ Hash
→ Store
→ Return metadata
```

---

# Module 2 — Sample Storage

Store uploaded samples locally.

Example:

```text
storage/
└── samples/
    └── <sha256>
```

The SHA-256 becomes the content identity.

Why?

Two files with the same hash represent the same binary with extremely high probability.

This enables future deduplication:

```text
Upload
  ↓
Calculate hash
  ↓
Already analyzed?
  ├── Yes → reuse existing result
  └── No  → create new analysis
```

### Learn

- Filesystem operations
- hashing
- metadata
- file naming
- safe paths

---

# Module 3 — PostgreSQL Metadata

Add PostgreSQL after the basic upload flow works.

Initial table:

```text
samples
----------------
id
filename
sha256
size
mime_type
created_at
status
```

The binary stays in local storage.

PostgreSQL stores metadata and state.

### Learn

- SQL
- schema design
- primary keys
- indexes
- transactions
- Go database access

---

# Module 4 — Analysis Jobs

Uploading and analyzing are separate operations.

```text
Upload
  ↓
Sample
  ↓
Analysis Job
```

Endpoint:

```text
POST /analyses
```

Possible states:

```text
queued
running
completed
failed
timeout
```

Example:

```json
{
  "job_id": "job_123",
  "status": "queued"
}
```

### Learn

- asynchronous processing
- state machines
- background work
- context cancellation
- timeouts

---

# Module 5 — Local Worker

Create a Go worker that receives an analysis job.

Initially it can simply simulate the sandbox lifecycle.

```text
Receive Job
    ↓
Load Sample
    ↓
Prepare Analysis
    ↓
Run
    ↓
Collect Result
    ↓
Mark Complete
```

Do not introduce NATS yet.

Use a simple in-process job channel.

This keeps development cheap and understandable.

### Learn

- goroutines
- channels
- worker pools
- graceful shutdown
- context
- concurrency limits

---

# Module 6 — Linux Fundamentals

Before building real monitoring, understand:

- User space vs kernel space
- Processes
- Threads
- PIDs
- Signals
- File descriptors
- Filesystems
- Permissions
- `/proc`
- System calls
- Network sockets
- namespaces
- cgroups

This is theory you need for understanding the sandbox.

---

# Module 7 — Basic Runtime Monitoring

Start with `strace`.

Pipeline:

```text
Sample
  ↓
strace
  ↓
System-call output
  ↓
Parser
  ↓
Normalized Events
```

For example:

```text
execve("/bin/sh")
```

becomes:

```json
{
  "type": "process",
  "action": "execute",
  "path": "/bin/sh"
}
```

### Learn

- system calls
- `strace`
- Linux process behavior
- parsing
- event normalization

Do not start with eBPF.

---

# Module 8 — Event Model

Define one common event structure.

```text
Event
├── ID
├── Timestamp
├── Type
├── Process
├── PID
├── Action
└── Metadata
```

Core categories:

```text
process
file
network
dns
syscall
```

Example:

```json
{
  "timestamp": "...",
  "type": "network",
  "action": "connect",
  "process": "sample",
  "pid": 1234,
  "metadata": {
    "ip": "192.0.2.10",
    "port": 443
  }
}
```

### Learn

- event-driven architecture
- schemas
- JSON
- normalization
- structured logging

---

# Module 9 — Firecracker Sandbox

Now introduce the real isolation layer.

Worker:

```text
Analysis Job
    ↓
Create MicroVM
    ↓
Configure VM
    ↓
Start VM
    ↓
Start monitoring
    ↓
Transfer sample
    ↓
Execute sample
    ↓
Collect events
    ↓
Stop VM
    ↓
Destroy VM
```

### Learn

- virtualization
- KVM
- Firecracker
- guest kernel
- root filesystem
- VM lifecycle
- virtual networking

This is one of the hardest modules.

---

# Module 10 — Event Collector

Connect the sandbox monitoring system to the Go backend.

```text
Sandbox
   ↓
Monitoring Agent
   ↓
Events
   ↓
Go Collector
   ↓
Event Store
```

The collector should be able to receive events without knowing exactly how they were produced.

That means later you can replace:

```text
strace
```

with:

```text
eBPF
```

without rewriting the analysis layer.

---

# Module 11 — IOC Extraction

Extract indicators from events.

Examples:

```text
IP addresses
Domains
URLs
File hashes
File paths
```

Future:

```text
Mutexes
Registry keys
```

Example:

```text
Network event
    ↓
evil.example
    ↓
IOC
```

Store IOCs separately from raw events.

---

# Module 12 — MITRE ATT&CK Mapping

Map observed behaviors to ATT&CK techniques.

Flow:

```text
Observed Behavior
       ↓
Detection Rule
       ↓
MITRE ATT&CK Technique
```

Use deterministic rules wherever possible.

Example:

```text
Observed process-injection behavior
        ↓
MITRE technique
```

Do not make the LLM responsible for the core classification.

### Learn

- ATT&CK terminology
- detection rules
- evidence
- explainability

---

# Module 13 — Threat Scoring

Create a simple explainable heuristic.

Example:

```text
Network activity       +5
Persistence            +20
Process injection      +30
Credential access      +30
```

Classification:

```text
0–20     Low
21–50    Medium
51–80    High
81+      Critical
```

The score is not a statistically validated malware probability.

Always display the contributing evidence.

---

# Module 14 — Real-Time Events

Stream analysis progress to the frontend.

```text
Worker
  ↓
Event
  ↓
WebSocket
  ↓
React
```

Example:

```text
[12:01:04] VM created
[12:01:05] Process started
[12:01:05] File created
[12:01:06] DNS request
[12:01:07] Network connection
[12:01:08] Analysis completed
```

### Learn

- WebSockets
- event streaming
- connection lifecycle
- concurrent clients

---

# Module 15 — Analyst Dashboard

Build the React interface.

Views:

```text
Overview
Timeline
Processes
Files
Network
DNS
IOCs
MITRE ATT&CK
Threat Report
```

The dashboard should show both:

```text
High-level summary
```

and:

```text
Underlying evidence
```

---

# Module 16 — AI Report Generation

Only after the deterministic pipeline works.

Input:

```json
{
  "events": [],
  "iocs": [],
  "mitre_findings": [],
  "threat_score": 72
}
```

LLM output:

```text
Executive Summary
Observed Behavior
Why It Is Suspicious
MITRE Techniques
Indicators of Compromise
Evidence
Recommended Investigation
```

The LLM explains evidence.

It does not replace:

- sandboxing
- event collection
- IOC extraction
- MITRE mapping
- threat scoring

---

# Module 17 — Advanced Monitoring

Replace or supplement `strace` with eBPF.

Progression:

```text
Linux processes
      ↓
System calls
      ↓
strace
      ↓
Event normalization
      ↓
eBPF
```

### Learn

- eBPF concepts
- kernel instrumentation
- probes
- event buffers
- kernel/user-space communication

This is an advanced module.

---

# Module 18 — Local Desktop Packaging

Only after the application works.

Potential architecture:

```text
Go
+
React
+
Local engine
+
Sandbox
```

Packaged as:

```text
Maltrace.exe
```

A framework such as Wails can be investigated later.

This is optional for the portfolio version.

---

# Module 19 — Optional Distributed Architecture

Do not build this just because the project documentation mentions distributed systems.

The local version can use:

```text
Go
 ↓
Local job channel
 ↓
One worker
```

If you want to demonstrate distributed architecture later:

```text
Go API
   ↓
NATS
   ↓
Worker 1
Worker 2
Worker 3
```

This is an extension.

NATS should not block the core project.

---

# Module 20 — Optional Future Features

After the core project is complete:

- eBPF monitoring
- Windows sandbox backend
- static analysis
- YARA
- packet capture
- memory analysis
- threat-intelligence enrichment
- analyst annotations
- sample deduplication
- historical comparison
- S3-compatible storage
- multi-worker execution
- Kubernetes scaling

None of these are required for the first portfolio release.

---

# 13. Recommended Learning Roadmap

Do not study the entire stack before coding.

Learn in dependency order.

## Stage 1 — Go Backend

Learn:

```text
net/http
HTTP methods
multipart uploads
JSON
io.Reader / io.Writer
file I/O
hashing
errors
context
goroutines
channels
```

Build:

```text
Module 1
Module 2
Module 3
```

---

## Stage 2 — Linux

Learn:

```text
Processes
Threads
PIDs
Signals
File descriptors
Filesystem
/proc
Permissions
System calls
Sockets
```

Then:

```text
strace
```

Build:

```text
Module 7
Module 8
```

---

## Stage 3 — Concurrency and Jobs

Learn:

```text
goroutines
channels
worker pools
job states
timeouts
cancellation
```

Build:

```text
Module 4
Module 5
```

---

## Stage 4 — Virtualization

Learn:

```text
VMs
hypervisors
KVM
virtual disks
Linux kernels
virtual networking
Firecracker
```

Build:

```text
Module 9
Module 10
```

---

## Stage 5 — Security Analysis

Learn:

```text
Dynamic analysis
IOCs
MITRE ATT&CK
detection rules
threat scoring
```

Build:

```text
Module 11
Module 12
Module 13
```

---

## Stage 6 — Real-Time Frontend

Learn:

```text
WebSockets
React state
event streams
timeline visualization
```

Build:

```text
Module 14
Module 15
```

---

## Stage 7 — AI

Learn:

```text
LLM APIs
structured prompts
JSON output
evidence-grounded generation
```

Build:

```text
Module 16
```

---

## Stage 8 — Advanced Systems

Only if the core project is working:

```text
eBPF
NATS
distributed workers
failure handling
```

Build:

```text
Module 17
Module 19
```

---

# 14. Technology Stack

| Layer | Technology | Why |
|---|---|---|
| Backend | **Go** | API, concurrency, systems programming |
| HTTP | **Go `net/http`** | Learn standard-library HTTP |
| Database | **PostgreSQL** | Persistent metadata/state |
| Local storage | **Filesystem** | Cheap executable storage |
| Jobs | **Go channels initially** | Simple local worker model |
| Queue | **NATS later** | Optional distributed workers |
| Sandbox | **Firecracker** | MicroVM isolation |
| OS | **Linux** | Sandbox + monitoring |
| Monitoring | **strace → eBPF** | Runtime observation |
| Real-time | **WebSockets** | Live analysis events |
| Frontend | **React + TypeScript** | Analyst dashboard |
| AI | **LLM API** | Report generation |
| Containers | **Docker** | Reproducible development |
| Security knowledge | **MITRE ATT&CK** | Behavioral classification |
| Desktop packaging | **Wails, optional** | Future local application |

---

# 15. What NOT to Build Initially

To keep the project finishable:

```text
❌ Cloud infrastructure
❌ Kubernetes
❌ Multiple VMs
❌ Multiple workers
❌ Windows malware support
❌ GPU-based ML
❌ Custom malware classifier
❌ Huge local LLM
❌ Authentication system
❌ Multi-tenancy
❌ Payment system
❌ SaaS architecture
❌ Mobile app
```

None of these make the portfolio project fundamentally better.

---

# 16. Portfolio Definition of Done

A strong first release is:

```text
✓ Local application
✓ Linux ELF sample upload
✓ SHA-256 identification
✓ Local sample storage
✓ Analysis jobs
✓ One local worker
✓ Firecracker isolation
✓ Runtime monitoring
✓ Structured events
✓ Event timeline
✓ IOC extraction
✓ MITRE mapping
✓ Explainable threat score
✓ React dashboard
✓ Optional LLM report
✓ Good README
✓ Architecture diagram
✓ Screenshots/demo
✓ Tests
✓ Docker development setup
```

That is already a serious project.

---

# 17. Resume Positioning

Project title:

> **Maltrace — Local Dynamic Malware Analysis Platform**

Possible resume description:

> Built a lightweight self-hosted malware-analysis platform in Go that executes untrusted Linux ELF binaries inside isolated Firecracker microVMs, collects runtime behavioral telemetry, normalizes events, extracts IOCs, maps behaviors to MITRE ATT&CK, and generates explainable threat reports.

Additional bullets can emphasize:

- concurrent analysis jobs
- real-time WebSocket event streaming
- resource-constrained local execution
- deterministic security findings
- evidence-backed LLM reporting

Do not call it an "AI malware detector."

---

# 18. Repository Structure

Start simple.

```text
maltrace/
│
├── cmd/
│   └── server/
│       └── main.go
│
├── internal/
│   ├── handlers/
│   ├── models/
│   ├── store/
│   ├── services/
│   └── workers/
│
├── storage/
│   └── samples/
│
├── migrations/
│
├── frontend/
│
├── tests/
│
├── README.md
├── go.mod
└── go.sum
```

Do not create every directory immediately.

Introduce each package when the project actually needs it.

---

# 19. First Milestone

Ignore almost everything above for now.

Your first target is:

```text
MALTRACE
│
├── Go HTTP server
│
├── POST /samples
│
├── Multipart file upload
│
├── File-size validation
│
├── SHA-256 calculation
│
├── Local sample storage
│
└── JSON response
```

Expected flow:

```text
Browser/Postman
      │
      │ POST /samples
      ▼
   Go server
      │
      ├── validate
      ├── hash
      └── save
      │
      ▼
  storage/samples/
      │
      ▼
   JSON response
```

**Do not start Firecracker, PostgreSQL, eBPF, NATS, or AI yet.**

Build this first. Once it works, the next module is database-backed sample metadata.

---

# 20. Mental Model

The project should always be understood as:

```text
Safely execute untrusted software
              ↓
Observe operating-system interactions
              ↓
Convert observations into structured events
              ↓
Analyze those events
              ↓
Extract security evidence
              ↓
Classify behavior
              ↓
Calculate an explainable threat score
              ↓
Present evidence to an analyst
              ↓
Optionally use AI to explain it
```

The LLM is the final layer.

The real project is the machinery underneath it.

That is what makes Maltrace a strong systems/security portfolio project.
