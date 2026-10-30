# ContainerShield AI — 2–3 Minute Demonstration Script & Career Profiles

---

## 1. Professional Demonstration Script (2–3 Minutes)

> **Speaker**: Arpit Sharma (Project Lead)  
> **Audience**: Faculty Evaluation Panel / Engineering Hiring Team  
> **Visual Backdrop**: Browser open to `http://localhost:3000` with active telemetry flowing.

### [0:00 – 0:35] Problem Statement & Core Identity
*"Good morning. Modern microservices run inside lightweight containers that share the underlying operating system kernel. If a containerized workload is compromised, traditional host firewalls often miss in-container process escalations and escape tools.

To solve this, we engineered **ContainerShield AI** — an AI-powered container runtime security monitoring and anomaly detection platform. It combines deterministic heuristic detection rules with unsupervised machine learning to inspect container telemetry in real time."*

### [0:35 – 1:15] System Architecture & Telemetry Ingestion
*(Switch to Dashboard Overview)*  
*"Here is our architecture: A containerized **Telemetry Collector** runs alongside our services in Docker, generating realistic container syscall events — process executions, file accesses, and network connections.

In this demonstration on macOS, the system operates in **Replay Telemetry Mode**, feeding structured telemetry batches directly to our asynchronous **FastAPI backend** every five seconds. The backend processes the events and streams them live to our SOC dashboard via **WebSockets**."*

### [1:15 – 1:55] Detection Engine: Rules + Machine Learning
*(Click on 'Threat Detection', then 'Security Alerts')*  
*"Our detection engine is two-tiered:
First, **Layer 1** applies deterministic rules — R001 through R007 — targeting known container attack vectors: `nsenter` escape tools, `/etc/shadow` credential reads, reverse shells, and unauthorized `sudo` executions.

Second, **Layer 2** leverages an **Isolation Forest** model evaluating an 8-dimensional runtime feature vector. The model analyzes process hierarchy, argument length, and root privilege flags to detect zero-day anomalies that lack static signatures.

Our hybrid engine calculates a weighted composite threat score, elevating severe attacks to real-time security alerts."*

### [1:55 – 2:30] Incident Triage, Mitigation & Persistence
*(Click 'Investigate' on a Critical Alert, then click 'Acknowledge' and 'Isolate Pod')*  
*"When a SOC analyst inspects an incident, the triage modal presents complete forensic evidence: executable path, arguments, process PID, and the affected container ID.

From this console, the analyst can acknowledge the incident and trigger an automated pod isolation response. In this prototype, the response is safely **simulated** — enforcing security governance without terminating developer workloads.

Every alert, telemetry event, and mitigation decision is persisted in **PostgreSQL 16** with an immutable audit trail that survives container restarts."*

### [2:30 – 2:45] Conclusion
*"ContainerShield AI delivers an end-to-end container security solution: containerized microservices, dual-layer threat detection, live WebSocket streaming, and ACID-compliant compliance logging — fully demonstrable on Docker Compose. Thank you, and I look forward to your questions."*

---

## 2. Professional Resume & LinkedIn Descriptions

### Resume Bullet Points (Software Engineering / Cybersecurity / Cloud-Native)
- **ContainerShield AI — Container Runtime Threat Detection Platform** | *Python, FastAPI, Docker, PostgreSQL, Scikit-Learn, WebSockets*
  - Engineered an end-to-end container security monitoring platform in Docker Compose comprising an asynchronous FastAPI backend, PostgreSQL 16 database, Nginx reverse proxy, and telemetry collector.
  - Implemented a dual-layer threat detection engine integrating 7 deterministic container attack heuristics (R001–R007) and an 8-dimensional Isolation Forest ML anomaly scoring pipeline.
  - Built a real-time reactive SOC dashboard across 8 views with live WebSocket event streaming, forensic evidence modals, and simulated incident response workflows.
  - Guaranteed database persistence and immutable audit trail logging across container lifecycle restarts using Docker named volumes and non-destructive migrations.

---

### LinkedIn Project Post

🚀 **Excited to share my latest cloud-native security project: ContainerShield AI!**

As containerized workloads become standard in modern infrastructure, detecting runtime threats, privilege escalations, and container escapes inside microservices is critical.

I built **ContainerShield AI** — an AI-powered container runtime security and anomaly detection platform designed for development and SOC analysis:

🛡️ **Dual-Layer Threat Detection**: Pairs 7 deterministic heuristic rules (container escape tools, sensitive file dumps, reverse shells) with an unsupervised **Isolation Forest** ML model evaluating runtime feature vectors.  
📡 **Live Streaming Architecture**: Autonomous telemetry collector pushes container events to an asynchronous **FastAPI backend**, broadcasting real-time security updates via **WebSockets**.  
💾 **Enterprise Persistence**: Full persistence and immutable audit logging backed by **PostgreSQL 16**, ensuring zero data loss across container lifecycle restarts.  
🖥️ **Interactive SOC Dashboard**: 8 functional views including live telemetry monitoring, forensic evidence triage modals, AI analytics distributions, and simulated incident response gates.  
🐳 **Production Orchestration**: 100% containerized with Docker and Docker Compose, complete with health checks and Nginx reverse proxying.

Check out the code and architecture on GitHub:  
🔗 https://github.com/PILOT-SHARMA/ebpf-shield-ai

#Cybersecurity #ContainerSecurity #CloudNative #Python #FastAPI #Docker #MachineLearning #DevOps #SecurityOperations
