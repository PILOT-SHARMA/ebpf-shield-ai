# ContainerShield AI — Quality Assurance Test Report

**Execution Date**: 2026-10-30
**Target Platform**: macOS (Apple Silicon), Docker Desktop, PostgreSQL 16 Alpine, FastAPI Backend, Nginx 1.25 Alpine
**Git Branch**: `main` (Synced with `origin/main`)
**Scope**: AI-Powered Container Security Demonstration MVP
**Overall Verdict**: **ALL EXECUTED TESTS PASSED (100% SUCCESS)**

---

## 1. Test Methodology & Distinction of Verification Layers

To ensure absolute transparency and prevent ambiguity between automated and manual checks, the test suite is partitioned into four distinct verification layers:

1. **Layer 1: Automated Integration & Unit Suite (`test_e2e.py`)**
   Executed directly via `python3 test_e2e.py` against the FastAPI application and SQLite/PostgreSQL engine. Contains **14 distinct test blocks** (13 numbered phases + 1 WebSocket check) comprising **55 individual automated assertions**.
2. **Layer 2: Direct HTTP & API Error Handling Tests**
   Executed via `curl` against the live backend container (`http://localhost:8000`) and Nginx reverse proxy (`http://localhost:3000`). Validates HTTP status codes (`200`, `404`, `422`), response headers, and Pydantic validation schema enforcement.
3. **Layer 3: PostgreSQL Volume Persistence Tests**
   Executed directly in the database container via `psql`. Compares exact record IDs and table row counts before and after safe PostgreSQL container restarts.
4. **Layer 4: Real Browser Subagent Verification**
   Executed via autonomous browser agent against `http://localhost:3000`. Navigates all 8 dashboard views, tests modal interactivity, inspects browser console logs for JavaScript errors, and saves 9 verified screenshots into `docs/screenshots/`.

---

## 2. Test Execution Summary

| Verification Layer | Test Blocks / Phases | Assertions / Verification Points | Passed | Failed |
|---|:---:|:---:|:---:|:---:|
| **1. Automated Suite (`test_e2e.py`)** | 14 | 55 | 55 | 0 |
| **2. Direct REST API & Error Tests** | 11 | 11 | 11 | 0 |
| **3. PostgreSQL Volume Persistence** | 3 | 5 | 5 | 0 |
| **4. Autonomous Telemetry Collector** | 2 | 4 | 4 | 0 |
| **5. Browser UI & Modal Interactivity** | 9 | 10 | 10 | 0 |
| **Total** | **39** | **85** | **85** | **0** |

---

## 3. Granular Layer-by-Layer Test Results

### Layer 1: Automated Integration Suite (`test_e2e.py`)

| Phase # | Test Phase Name | Components Tested | Key Assertions | Status |
|---|---|---|---|:---:|
| **Phase 1** | Static Assets & Dashboard Delivery | GET `/`, `/static/style.css`, `/static/app.js` | Status 200, HTML contains branding, CSS/JS load | ✅ PASS |
| **Phase 2** | Baseline Normal Ingestion | POST `/api/v1/events/batch` (Normal nginx event) | Status 200, events_received=1, alerts_created=0 | ✅ PASS |
| **Phase 3** | Attack Ingestion (Container Escape) | POST `/api/v1/events/batch` (nsenter payload) | Status 200, events_received=1, alerts_created=1 | ✅ PASS |
| **Phase 4** | Query APIs (`/events` & `/alerts`) | GET `/api/v1/events`, GET `/api/v1/alerts` | Events retrieved $\ge 10$, alert severity=`critical`, rule_id=`R001` | ✅ PASS |
| **Phase 5** | Forensic Evidence Detail | GET `/api/v1/alerts/{id}` | Target executable, process arguments, pod context linked | ✅ PASS |
| **Phase 6** | Simulated Mitigation Action | POST `/api/v1/responses`, PATCH `/alerts/{id}` | Result contains `[SIMULATED]`, alert status updated to `resolved` | ✅ PASS |
| **Phase 7** | Dashboard Stats & Audit Trail | GET `/api/v1/stats`, GET `/api/v1/audit` | Total counts consistent, audit log records mitigation action | ✅ PASS |
| **Phase 8** | System Health API | GET `/api/v1/health` | Status 200, `database: "connected"`, `collector_mode: "DEMO_REPLAY_MODE"` | ✅ PASS |
| **Phase 9** | Telemetry Collector Status | GET `/api/v1/sensor/status` | Status 200, mode reports replay, explains macOS BPF reason | ✅ PASS |
| **Phase 10** | Container Workloads Inventory | GET `/api/v1/containers` | Returns tracked workloads with image, pod name, and threat level | ✅ PASS |
| **Phase 11** | Metrics Summary & Alert Triage | GET `/api/v1/metrics/summary`, POST `/alerts/{id}/ack` | Severity breakdown returned, alert marked acknowledged with actor name | ✅ PASS |
| **Bonus** | WebSocket Streaming Heartbeat | WS `/ws/v1/stream` | Client sends `ping`, server responds `{"type": "pong"}` | ✅ PASS |
| **Phase 12** | Heuristic Detection Rules Engine | Individual evaluation of Rules R001–R007 | **R001** (Escape): `nsenter` flagged `critical`<br>**R002** (File): `/etc/shadow` flagged `high`<br>**R003** (Shell): `/dev/tcp` flagged `critical`<br>**R004** (Privilege): in-container `sudo` flagged `high`<br>**R005** (Mining): `xmrig` flagged `medium`<br>**R006** (Network): egress `:4444` flagged `high`<br>**R007** (Recon): `whoami` flagged `medium`<br>**Baseline**: Normal event matches 0 rules | ✅ PASS |
| **Phase 13** | Isolation Forest ML Scoring | 8-dim feature extraction & scoring | Feature shape is `(1, 8)`, normal score $= 0.5301$, attack score $= 0.5533$ (Attack $>$ Normal), hybrid combiner score $= 0.691$ | ✅ PASS |

---

### Layer 2: Direct REST API & Error Handling Tests

| # | Endpoint Tested | Method & Payload | Expected Result | Actual Observed Result | Status |
|---|---|---|---|---|:---:|
| L2-1 | `/api/v1/health` | GET | HTTP 200, database connected | `{"status":"healthy","database":"connected"}` | ✅ PASS |
| L2-2 | `/api/v1/sensor/status` | GET | HTTP 200, replay mode | `{"mode":"DEMO_REPLAY_MODE","status":"active"}` | ✅ PASS |
| L2-3 | `/api/v1/containers` | GET | HTTP 200, array of containers | Array of 6 simulated workloads returned | ✅ PASS |
| L2-4 | `/api/v1/stats` | GET | HTTP 200, real-time counters | `total_events > 3000`, `open_alerts > 200` | ✅ PASS |
| L2-5 | `/api/v1/rules` | GET | HTTP 200, 7 rule objects | Returns R001 through R007 definitions | ✅ PASS |
| L2-6 | `/api/v1/responses` | GET | HTTP 200, response action list | Lists simulated response records with actor and timestamp | ✅ PASS |
| L2-7 | `/api/v1/audit` | GET | HTTP 200, audit log list | Lists append-only compliance audit trail | ✅ PASS |
| L2-8 | `/api/v1/nonexistent` | GET | HTTP 404 Not Found | `{"detail":"Not Found"}` | ✅ PASS |
| L2-9 | `/api/v1/alerts/{invalid}/ack`| POST with bogus UUID | HTTP 404 Not Found | `{"detail":"Alert not found"}` | ✅ PASS |
| L2-10 | `/api/v1/events/batch` | POST with invalid JSON schema | HTTP 422 Unprocessable | Pydantic schema validation error | ✅ PASS |
| L2-11 | Nginx Reverse Proxy (`:3000`) | GET `/api/v1/health` via port 3000 | HTTP 200 Proxying correctly | Transparently proxies backend response | ✅ PASS |

---

### Layer 3: PostgreSQL Persistence Across Container Restart

To prove that telemetry, alert evidence, and audit logs survive service restarts, specific record IDs were captured and verified before and after restarting the database container:

```bash
docker compose restart postgres
```

| Verification Item | Pre-Restart Observed Value | Post-Restart Observed Value | Persistence Result |
|---|---|---|:---:|
| **Earliest Alert ID** | `78f039f5-9a0c-4a04-b897-9788f21ee087` | `78f039f5-9a0c-4a04-b897-9788f21ee087` | ✅ Exact Match (Intact) |
| **Earliest Event ID** | `1820ba4b-2fb8-417d-878a-5489e77a084f` | `1820ba4b-2fb8-417d-878a-5489e77a084f` | ✅ Exact Match (Intact) |
| **Total Alerts Row Count** | 335 records | 335+ records | ✅ Persisted (Incrementing) |
| **Total Runtime Events** | 3,628 records | 3,636+ records | ✅ Persisted (Incrementing) |
| **Named Volume Backing** | `pgdata` volume mounted | `pgdata` volume mounted | ✅ Zero Data Loss |

---

### Layer 4: Autonomous Telemetry Collector Verification

- **Operating Mode**: `DEMO_REPLAY_MODE` (configured via environment variables).
- **Batch Cadence**: Dispatches batches of 2–5 events every 5 seconds.
- **Attack Injection Frequency**: Every 4th cycle includes a synthetic container attack scenario.
- **Observed Reliability**: Ingested over 650 continuous cycles with zero network failures, zero database dropouts, and automatic retry readiness.

---

### Layer 5: Real Browser Subagent Verification (`http://localhost:3000`)

An autonomous browser agent navigated the application and verified interactive functionality:

| View Tested | Navigation Selector | Verification Criteria | Observed Result | Status |
|---|---|---|---|:---:|
| **1. Overview Dashboard** | `#nav-overview` | 6 KPI cards, event ticker, quick actions | Rendered live event counts, active streams | ✅ PASS |
| **2. Runtime Monitoring** | `#nav-monitoring` | Syscall table, PID, UID, threat scores | Event stream populated with search/filter working | ✅ PASS |
| **3. Threat Detection** | `#nav-detection` | Architecture hero, scoring formula, R001–R007 | Rendered all 7 rule cards and mathematical formulas | ✅ PASS |
| **4. Security Alerts** | `#nav-alerts` | Alert list, severity badges, Investigate button | Alerts displayed chronologically with filters | ✅ PASS |
| **4b. Alert Triage Modal** | Button click | Evidence modal opens, shows PID/args, closes | Modal displayed evidence, buttons labeled simulated, closed cleanly | ✅ PASS |
| **5. AI Analytics** | `#nav-analytics` | Anomaly distribution histogram, syscall volume | Score distribution buckets and volume charts active | ✅ PASS |
| **6. Container Monitoring** | `#nav-containers` | Workload cards, namespaces, threat status | 6 simulated workload cards displayed | ✅ PASS |
| **7. Event Timeline** | `#nav-timeline` | Chronological incident sequence | Correlated telemetry and alert stream visible | ✅ PASS |
| **8. System Health** | `#nav-health` | Service indicators (FastAPI, Postgres, Collector, Nginx) | All 4 services green; audit trail populated | ✅ PASS |
| **Browser Console** | Console Logs | Unhandled errors or promise rejections | **0 console errors observed** | ✅ PASS |

---

## 4. Verification of Documentation Screenshots

The following 9 genuine screenshots were captured directly from the live application and exist in `docs/screenshots/`:

| File Name | File Size | Description | Verified |
|---|:---:|---|:---:|
| `docs/screenshots/overview.png` | 506 KB | Executive overview dashboard and telemetry KPIs | ✅ Verified |
| `docs/screenshots/runtime_monitoring.png` | 559 KB | Real-time streaming kernel telemetry feed | ✅ Verified |
| `docs/screenshots/threat_detection.png` | 703 KB | Dual-layer architecture and heuristic rule cards (R001–R007) | ✅ Verified |
| `docs/screenshots/security_alerts.png` | 818 KB | Filterable security alert desk with severity indicators | ✅ Verified |
| `docs/screenshots/alert_modal.png` | 539 KB | Forensic evidence modal with simulated workload isolation trigger | ✅ Verified |
| `docs/screenshots/ai_analytics.png` | 351 KB | Anomaly score distribution histograms and syscall breakdown | ✅ Verified |
| `docs/screenshots/container_monitoring.png` | 488 KB | Simulated container workload inventory across demo groups | ✅ Verified |
| `docs/screenshots/event_timeline.png` | 428 KB | Chronological incident and alert correlation stream | ✅ Verified |
| `docs/screenshots/system_health.png` | 553 KB | Service health diagnostics and security audit trail log | ✅ Verified |

---

## 5. Disclosed Limitations & Scope Boundaries

1. **Linux Kernel Probes**: Live eBPF kernel probes require a native Linux kernel with `libbpf` and `CAP_BPF`. This project is intentionally developed and verified on macOS using high-fidelity **Replay Telemetry Mode** (`DEMO_REPLAY_MODE`).
2. **Mitigation Enforcement**: Kubernetes mutating webhooks and network policy changes are explicitly **`[SIMULATED]`** to guarantee non-destructive demonstration on development workstations.
3. **Audit Log Persistence**: The audit log is an append-only relational database table in PostgreSQL. It is durable across container restarts but is not cryptographically immutable.
