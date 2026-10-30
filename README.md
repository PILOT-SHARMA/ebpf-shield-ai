# 🛡️ eBPF-Shield AI: Kernel-Level Cloud-Native Runtime Threat & Container Escape Engine

> **B.Tech CS (AI/ML) III Year – V Semester (2025–26)**  
> **Department of Computer Science Engineering & Applications, GLA University, Mathura**  
> **Mentor:** Sanjana Shaw Mam  
> **Team:** Arpit Sharma (UR: 2415500099), Aryan Gupta (UR: 2415500102), Ananya Mishra (UR: 2415500068)  
> **GitHub Repository:** [https://github.com/PILOT-SHARMA/ebpf-shield-ai](https://github.com/PILOT-SHARMA/ebpf-shield-ai)

---

## 📌 1. Project Overview & 70% MVP Milestone

**eBPF-Shield AI** is an enterprise-grade cloud-native runtime security and container escape detection engine. It continuously monitors process executions, sensitive file modifications, and network sockets from container workloads.

### Current Milestone Status (70% MVP)
- **Containerized Microservices:** Full Docker Compose multi-service architecture running PostgreSQL 16, FastAPI Backend, Nginx Frontend, and an Autonomous Telemetry Collector.
- **Relational Persistence:** Migrated from single-node SQLite to high-performance PostgreSQL with persistent volumes and backward compatibility for local SQLite testing.
- **Autonomous Telemetry Ingestion:** Containerized background collector continuously streaming mixed normal container operations and real-world attack scenarios (container escapes, privilege escalations, reverse shells, cryptomining).
- **Dual-Layer Detection Engine:** Deterministic Heuristic Rules (R001–R007) combined with an Unsupervised Machine Learning Isolation Forest model (`isolation_forest_v1`).
- **Interactive Security Operations Console:** 8-section dark-mode dashboard (Overview, Runtime Monitoring, Threat Detection, Security Alerts, AI Analytics, Container Monitoring, Event Timeline, System Health) featuring live WebSocket streaming, dynamic SVG analytics, and human-in-the-loop remediation.

---

## 🏛️ 2. Architecture & Data Flow

```
                               ┌────────────────────────────────────────────────────────┐
                               │             eBPF-Shield AI Architecture               │
                               └────────────────────────────────────────────────────────┘

    [ Telemetry Source ]           [ Ingestion & Detection ]              [ Storage & Streaming ]
   ┌──────────────────────┐        ┌─────────────────────────────┐        ┌─────────────────────┐
   │ Autonomous Collector │        │       FastAPI Backend       │        │  PostgreSQL 16 DB   │
   │ (Replay Mode)        │───────>│  POST /api/v1/events/batch  │───────>│  • runtime_events   │
   │ • Process executions │ HTTP   │                             │ SQL    │  • alerts           │
   │ • File operations    │        │  ┌───────────────────────┐  │        │  • container_info   │
   │ • Socket connects    │        │  │ Layer 1: Rule Engine  │  │        │  • anomaly_preds    │
   └──────────────────────┘        │  │ (R001 - R007)         │  │        │  • audit_log        │
                                   │  └───────────┬───────────┘  │        └─────────────────────┘
                                   │              ▼              │                   │
                                   │  ┌───────────────────────┐  │                   │
                                   │  │ Layer 2: ML Engine    │  │                   ▼
                                   │  │ (Isolation Forest v1) │  │        ┌─────────────────────┐
                                   │  └───────────┬───────────┘  │        │ WebSocket Broadcast │
                                   │              ▼              │───────>│ /ws/v1/stream       │
                                   │  ┌───────────────────────┐  │ WS     │ Sub-second latency  │
                                   │  │ Layer 3: Hybrid Score │  │        └─────────────────────┘
                                   │  │ Threshold > 0.60 Alert│  │                   │
                                   │  └───────────────────────┘  │                   ▼
                                   └─────────────────────────────┘        ┌─────────────────────┐
                                                  ▲                       │   Nginx Frontend    │
                                                  │ HTTP Reverse Proxy    │   (Port 3000 / 80)  │
                                                  └───────────────────────│  8 Dashboard Views  │
                                                                          └─────────────────────┘
```

---

## 💻 3. Technology Stack

- **Containerization & Orchestration:** Docker Engine 29+, Docker Compose v2 (No Kubernetes/Helm used).
- **Database:** PostgreSQL 16 Alpine (with persistent Docker volume `pgdata`), SQLAlchemy 2.0 ORM, `psycopg` / `psycopg2-binary`.
- **Backend Framework:** Python 3.11, FastAPI, Uvicorn, Pydantic v2.
- **Machine Learning & AI:** Scikit-learn (Isolation Forest), NumPy, Joblib (8 behavioral features scored).
- **Reverse Proxy & Web Server:** Nginx 1.25 Alpine.
- **Frontend Console:** Vanilla HTML5, CSS3 (Dark cybersecurity console, glassmorphism, responsive grid), Vanilla JavaScript ES6+ (Zero external UI dependencies, inline SVG chart rendering).
- **Real-Time Communications:** WebSocket protocol (`/ws/v1/stream` with bidirectional heartbeat).

---

## 🚀 4. Quick Start with Docker Compose

### Prerequisites
- Docker Desktop or Docker Engine installed and running.
- Docker Compose v2 (`docker compose version`).

### Step 1: Clone and Configure Environment
```bash
git clone https://github.com/PILOT-SHARMA/ebpf-shield-ai.git
cd miniproject3rdyear

# Copy configuration template (already pre-configured for Docker Compose)
cp .env.example .env
```

### Step 2: Build & Start All Services
```bash
docker compose up --build -d
```

### Step 3: Verify Running Services
```bash
docker compose ps
```
Expected output:
```
NAME                    IMAGE                          STATUS
ebpf-shield-postgres    postgres:16-alpine             Up (healthy)
ebpf-shield-backend     miniproject3rdyear-backend     Up (healthy)
ebpf-shield-collector   miniproject3rdyear-collector   Up
ebpf-shield-frontend    miniproject3rdyear-frontend    Up (healthy)
```

### Step 4: Access the Dashboard & API
- **Web Dashboard:** [http://localhost:3000](http://localhost:3000) (via Nginx) or [http://localhost:8000](http://localhost:8000) (Direct Backend)
- **Interactive Swagger API Docs:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **API Health Endpoint:** [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

### Step 5: View Service Logs
```bash
# View real-time collector activity:
docker compose logs -f collector

# View backend event processing and ML scoring:
docker compose logs -f backend
```

### Step 6: Teardown
```bash
# Stop all services:
docker compose down

# Stop and wipe persistent volume data (clean restart):
docker compose down -v
```

---

## ⚙️ 5. Environment Configuration (`.env`)

| Variable | Default Value | Description |
|---|---|---|
| `POSTGRES_USER` | `ebpf_shield` | PostgreSQL database username |
| `POSTGRES_PASSWORD` | `ebpf_shield_dev_2024` | PostgreSQL database password |
| `POSTGRES_DB` | `ebpf_shield` | Primary database name |
| `DATABASE_URL` | `postgresql://ebpf_shield:...@postgres:5432/ebpf_shield` | Database connection URL |
| `COLLECTOR_MODE` | `replay` | `replay` (Simulated telemetry) or `ebpf` (Live kernel probe) |
| `COLLECTOR_INTERVAL`| `5` | Delay in seconds between telemetry batches |
| `BACKEND_URL` | `http://backend:8000` | Backend API URL for the collector |
| `BACKEND_HOST` | `0.0.0.0` | Bind address for FastAPI backend |
| `BACKEND_PORT` | `8000` | Port for FastAPI backend |
| `CORS_ORIGINS` | `*` | Allowed CORS origins for API requests |

---

## 📡 6. Complete API Endpoint Reference

### Health & Sensor Diagnostics
- `GET /api/v1/health` — Application health check (status, PostgreSQL connection, collector mode, uptime).
- `GET /api/v1/sensor/status` — Telemetry sensor status (mode: `DEMO_REPLAY_MODE`, total events collected, kernel probe availability).

### Telemetry & Container Workloads
- `POST /api/v1/events/batch` — Ingest telemetry batches from sensor or replay scripts.
- `GET /api/v1/events` — Query newest ingested runtime events with optional filters (`suspicious_only`, `event_type`, `container_id`).
- `GET /api/v1/containers` — Query monitored container workloads with namespace, pod, node, alert counts, and threat levels.

### Security Alerts & Incident Response
- `GET /api/v1/alerts` — Query generated security alerts with severity (`critical`, `high`, `medium`, `low`) and status filters.
- `GET /api/v1/alerts/{id}` — Retrieve deep forensic evidence for a specific alert.
- `POST /api/v1/alerts/{id}/acknowledge` — Acknowledge an alert with analyst username and audit notes.
- `PATCH /api/v1/alerts/{id}?status=...` — Transition alert lifecycle (`open`, `investigating`, `resolved`, `false_positive`).
- `POST /api/v1/responses` — Trigger simulated mitigation actions (`isolate_pod`, `terminate_container`, `quarantine`).
- `GET /api/v1/responses` — Query executed mitigation actions.

### Analytics, Rules & Audit
- `GET /api/v1/stats` — Executive KPI counters for dashboard topbar.
- `GET /api/v1/metrics/summary` — Comprehensive statistical distributions (events by type, alerts by severity, detection methods, top triggered rules, recent scores).
- `GET /api/v1/rules` — Active detection rules catalog (R001–R007).
- `GET /api/v1/predictions` — Query individual Isolation Forest anomaly predictions.
- `GET /api/v1/audit` — Immutable security audit trail.

### WebSocket Channels
- `WS /ws/v1/stream` — Bidirectional real-time stream broadcasting `new_event` and `new_alert` payloads with ping/pong heartbeats.
- `WS /ws/v1/alerts` — Dedicated alert notifications stream.

---

## 🖥️ 7. Dashboard Sections (All 8 Connected Views)

1. **Overview:** Executive summary displaying 5 KPI cards (Total Events, Suspicious Events, Open Alerts, Critical Threats, Containers), recent event & alert feeds, and live distribution charts.
2. **Runtime Monitoring:** Live telemetry feed streaming kernel operations (`process_exec`, `file_open`, `net_connect`) with live search and syscall filtering.
3. **Threat Detection:** System architecture deep-dive showing the 3-layer pipeline, mathematical scoring formulas, and active detection rules catalog (R001–R007) with MITRE ATT&CK technique mappings.
4. **Security Alerts:** Triage center displaying active incidents with glowing severity pills (Critical, High, Medium, Low), 1-click Acknowledge button, and Forensic Deep-Dive Modal with interactive mitigation triggers.
5. **AI Analytics:** Real-time data visualizations including:
   - Syscall volume by type.
   - Alert severity distribution.
   - Historical threat score trajectory (inline SVG sparkline).
   - Machine Learning anomaly score histogram (binned 0.0 to 1.0).
   - Top triggered rules leaderboard.
6. **Container Monitoring:** Monitored container cards displaying pod name, namespace, container image, worker node, event count, alert count, and threat rating.
7. **Event Timeline:** Chronological visual timeline correlating raw kernel events, triggered alerts, analyst acknowledgements, and response actions.
8. **System Health:** Live status cards for Backend, Database, Collector, ML Model, WebSocket, and Docker services, with live diagnostic JSON report and immutable Audit Log.

---

## 🧪 8. Testing Instructions

### Automated End-to-End Test Suite
Run the comprehensive test script covering all 11 validation phases:
```bash
python3 test_e2e.py
```
This suite verifies:
1. Static files & dashboard HTML serving (`GET /`).
2. Benign event ingestion (verifies zero false alerts on normal web traffic).
3. Attack event ingestion (verifies `nsenter` triggers Critical alert and R001 match).
4. Events and Alerts query APIs.
5. Alert forensic evidence and pod context linkage.
6. Simulated Kubernetes response actions and audit trail logging.
7. Dashboard KPI stats and audit APIs.
8. Health check API (`GET /api/v1/health`).
9. Sensor telemetry status API (`GET /api/v1/sensor/status`).
10. Container monitoring API (`GET /api/v1/containers`).
11. Metrics summary and alert acknowledgement (`POST /api/v1/alerts/{id}/acknowledge`).
12. WebSocket live streaming and heartbeat.

---

## ⚠️ 9. Academic Transparency & Known Limitations

In strict adherence to academic honesty and engineering integrity:

| Aspect | Current 70% MVP State | Explanation / Limitation |
|---|---|---|
| **Operating System** | macOS Host (Docker Desktop) | macOS does not run a native Linux kernel; eBPF (`kprobe`, `tracepoint`, `perf_event`) requires a real Linux kernel. |
| **Telemetry Sensor** | `DEMO_REPLAY_MODE` | The telemetry collector generates synthetic, realistic security events simulating containerized microservices and attacks. It does **not** hook into the macOS host kernel. |
| **Mitigation Actions** | Simulated (`[SIMULATED]`) | Mitigations (network policy isolation, container termination) log to the audit trail and update application state, but do not mutate the local Docker host. |
| **Database** | PostgreSQL 16 + SQLite fallback | PostgreSQL is primary in Docker Compose; SQLite is preserved for local CLI tests without Docker. |

---

## 🔮 10. Future Live eBPF Integration Roadmap

1. **Linux Kernel Probes:** Transition from synthetic replay to compiled eBPF C programs (`kprobe/sys_execve`, `tracepoint/syscalls/sys_enter_openat`, `sock:inet_sock_set_state`) using `libbpf` and CO-RE (Compile Once – Run Everywhere).
2. **Kubernetes CRI Integration:** Direct UNIX domain socket attachment to `containerd` (`/run/containerd/containerd.sock`) to extract cgroup IDs and match PIDs to Kubernetes Pod namespaces in real time.
3. **Deep Learning Autoencoder:** Train a PyTorch/ONNX reconstruction error autoencoder on 24-hour benign container baselines to detect zero-day evasion techniques.
4. **Kubernetes CRD Operator:** Implement a Kubernetes Operator that applies dynamic `NetworkPolicy` custom resources to isolate compromised pods in live clusters.
