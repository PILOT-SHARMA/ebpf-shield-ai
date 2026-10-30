# ContainerShield AI — Live Demonstration Guide

A step-by-step walkthrough for faculty project evaluations, technical interviews, and stakeholder demonstrations.

---

## 1. Prerequisites & Environment Verification

Before presenting, ensure Docker Desktop is running on your macOS machine:

```bash
cd /Users/arpit/Downloads/miniproject3rdyear
docker compose ps
```

All 4 services should display `healthy` or `Up`:
- `ebpf-shield-postgres` (healthy, port 5432)
- `ebpf-shield-backend` (healthy, port 8000)
- `ebpf-shield-frontend` (healthy, port 3000)
- `ebpf-shield-collector` (Up)

If the stack is not running, start it:
```bash
docker compose up -d
```

Open your browser to: **`http://localhost:3000`**

---

## 2. Demonstration Sequence

### Step 1: Platform Overview & System Identity (1 Minute)
1. **Show the Topbar & Sidebar Brand**:
   - Point out **ContainerShield AI** branding and the `DEMO REPLAY MODE` badge.
   - Note the **Connected** WebSocket status indicator with the green pulse.
2. **Review the KPI Cards**:
   - `Total Events`: Real-time counter of processed kernel events.
   - `Threats Detected`: Incidents flagged by rules or ML.
   - `Critical Escapes`: High-priority container escape attempts.
   - `Tracked Containers`: 6 containerized microservice workloads (`nginx`, `redis`, `payment-svc`, etc.).
   - `Response Actions`: Count of simulated mitigation interventions.

---

### Step 2: Live Telemetry & Streaming Feed (1 Minute)
1. Click **Runtime Monitoring** in the sidebar.
2. **Highlight Live Ingestion**:
   - Watch new rows stream in automatically without page refresh (powered by WebSockets over `/ws/v1/stream`).
   - Point out diverse event types: `process_exec`, `file_open`, `net_connect`.
   - Show workload attribution: each event tags `container_id`, `pod_name`, `namespace`, and `threat_score`.
3. **Filter Events**:
   - Use the type dropdown to filter by `process_exec` or `file_open`.
   - Enter `nginx` in the search box to view web-tier process trees.

---

### Step 3: Threat Detection Architecture (1 Minute)
1. Click **Threat Detection** in the sidebar.
2. **Explain the Dual-Layer Engine**:
   - **Layer 1: Heuristic Rules**: Deterministic container security checks (R001 through R007).
     - *R001*: Container escape tools (`nsenter`, `unshare`, `chroot`).
     - *R002*: Sensitive file reads (`/etc/shadow`, `/proc/self/ns/`).
     - *R003*: Reverse shell sockets (`bash -i >& /dev/tcp/`).
     - *R004*: In-container privilege escalation (`sudo`).
     - *R005*: Cryptocurrency mining (`xmrig`).
     - *R006*: Suspicious egress traffic (`:4444`).
     - *R007*: Reconnaissance activity (`whoami`).
   - **Layer 2: Isolation Forest**: Unsupervised model scoring process hierarchy and argument complexity.
   - **Hybrid Scoring**: Explain the formula $\min(1.0, 0.7 \times \text{Rule} + 0.3 \times \text{ML})$.

---

### Step 4: Security Alert Triage & Forensic Deep Dive (2 Minutes)
1. Click **Security Alerts** in the sidebar.
2. Filter the table to **Critical** alerts.
3. Select an alert with rule **`R001`** (`Container escape tool detected: nsenter`) and click **Investigate**:
   - **Modal Header**: Displays Alert ID, severity badge, and threat score ($0.95+$).
   - **Forensic Evidence Box**: Shows exact executable path (`/usr/bin/nsenter`), arguments (`--target 1 --mount --uts`), PID, and UID.
   - **Workload Attribution**: Identifies target pod (`compromised-pod`), container ID, and namespace.
   - **Recommended Action**: Explains why container isolation is suggested.
4. **Demonstrate Incident Triage**:
   - Click **Acknowledge Alert**. Note that the status transitions to `acknowledged`.
   - Click **Simulated Workload Isolation**.
   - Notice the green confirmation message:
     `[SIMULATED] Pod compromised-pod-test network policy applied — isolated from cluster network`.
   - Close the modal.

---

### Step 5: AI Analytics & Threat Distributions (1 Minute)
1. Click **AI Analytics** in the sidebar.
2. Review the visualized metrics:
   - **Threat Score Distribution**: Histogram grouping events into Safe ($<0.4$), Suspicious ($0.4-0.65$), and Malicious ($>0.65$).
   - **Syscall Event Volume**: Relative frequency of process, file, and socket activities.
   - **Engine Detection Breakdown**: Percentage of threats caught via Rules vs. ML vs. Hybrid.

---

### Step 6: Container Workload Inventory & Timeline (1 Minute)
1. Click **Container Monitoring**:
   - Inspect the 6 workloads. Point out that uncompromised containers (`cache-redis-0`) remain in **NORMAL** status, while attacked pods transition to **CRITICAL**.
2. Click **Event Timeline**:
   - Review the chronological sequence of events showing telemetry arrival, alert elevation, and response action execution.

---

### Step 7: System Diagnostics & Security Audit Trail Log (1 Minute)
1. Click **System Health**:
   - Show all service indicators: FastAPI Backend (Healthy), PostgreSQL 16 (Healthy), Telemetry Collector (Active / Replay), Nginx (Healthy).
2. **Inspect the Audit Trail**:
   - Point out the recent acknowledgment and simulated response records.
   - Show that actor name, timestamp, action type, and target alert ID are permanently recorded in PostgreSQL.

---

### Step 8: Database Persistence Proof (1 Minute)
To prove that all telemetry and triage data persists across system restarts:

1. Open your terminal and show the alert count:
   ```bash
   docker compose exec postgres psql -U ebpf_shield -d ebpf_shield -c "SELECT count(*) FROM alerts;"
   ```
2. Restart the database container:
   ```bash
   docker compose restart postgres
   ```
3. Query the table again after 3 seconds:
   ```bash
   docker compose exec postgres psql -U ebpf_shield -d ebpf_shield -c "SELECT count(*) FROM alerts;"
   ```
4. Confirm that the count has not reset to zero — proving that data is persisted in Docker named volume `pgdata`.

---

## 3. Anticipated Questions & Strong Answers

**Q: Why does the system run in Replay Telemetry Mode instead of using live eBPF probes?**
> *"Live eBPF kernel instrumentation requires a native Linux kernel with `libbpf` and `CAP_BPF` privileges. Development and testing on macOS (Darwin kernel) do not support Linux BPF syscalls directly. By engineering a high-fidelity Telemetry Collector in `DEMO_REPLAY_MODE`, we demonstrate the entire detection engine, ML inference pipeline, database persistence, and SOC dashboard reliably and reproducibly on any workstation."*

**Q: Is the container actually killed when I click 'Simulated Workload Isolation'?**
> *"No. The platform deliberately operates in `[SIMULATED]` mitigation mode to ensure safe demonstration without disrupting the user's Docker environment or killing running containers. The action triggers the full approval gate, response logging, and audit trail record exactly as a real SOC tool would."*

**Q: How does the Isolation Forest contribute if heuristic rules exist?**
> *"Heuristic rules are deterministic and capture known signatures (e.g. `nsenter`). The Isolation Forest evaluates an 8-dimensional feature vector (PID depth, path length, argument complexity, root flag) to identify anomalous behaviors that don't match any static rule (zero-day activity). It also boosts the confidence score of matched rules in our hybrid combiner."*
