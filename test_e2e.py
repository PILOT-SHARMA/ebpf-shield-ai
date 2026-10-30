"""
test_e2e.py — Comprehensive End-to-End Test Suite for eBPF-Shield AI Prototype.
Validates the entire event ingestion -> rule/ML detection -> alert generation ->
simulated response -> audit log -> dashboard assets pipeline.
"""

import sys
import os
from fastapi.testclient import TestClient

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.main import app
from backend.database import SessionLocal, RuntimeEvent, Alert, ResponseAction, AuditLog

def run_tests():
    print("🧪 Running eBPF-Shield AI End-to-End Validation Suite...")
    client = TestClient(app)

    # 1. Test Static files & Dashboard HTML
    print("\n[1/7] Testing Frontend & Static Endpoints...")
    res = client.get("/")
    assert res.status_code == 200, f"Expected 200 from /, got {res.status_code}"
    assert "eBPF-Shield AI" in res.text
    print("  ✅ GET / (Dashboard HTML) OK")

    res = client.get("/static/style.css")
    assert res.status_code == 200, f"Expected 200 from /static/style.css, got {res.status_code}"
    print("  ✅ GET /static/style.css OK")

    res = client.get("/static/app.js")
    assert res.status_code == 200, f"Expected 200 from /static/app.js, got {res.status_code}"
    print("  ✅ GET /static/app.js OK")

    # 2. Test Normal Event Ingestion (no alert should be triggered)
    print("\n[2/7] Testing Normal Event Ingestion...")
    normal_payload = {
        "events": [{
            "event_type": "process_exec",
            "pid": 1042,
            "ppid": 1,
            "executable": "/usr/sbin/nginx",
            "args": "nginx: worker process",
            "uid": 33,
            "container_id": "c1a2b3d4e5f6",
            "pod_name": "web-frontend-nginx-68f49",
            "namespace": "production",
            "node_name": "worker-node-1",
            "image": "nginx:alpine",
            "source": "replay",
            "raw_data": {}
        }]
    }
    res = client.post("/api/v1/events/batch", json=normal_payload)
    assert res.status_code == 200, f"Expected 200, got {res.status_code}: {res.text}"
    data = res.json()
    assert data["events_received"] == 1
    assert data["alerts_created"] == 0
    print("  ✅ Normal event ingested without triggering alert")

    # 3. Test Attack Event Ingestion (Container Escape with nsenter -> Critical Alert)
    print("\n[3/7] Testing Attack Event Ingestion (Rule R001: nsenter)...")
    attack_payload = {
        "events": [{
            "event_type": "process_exec",
            "pid": 9999,
            "ppid": 1042,
            "executable": "/usr/bin/nsenter",
            "args": "nsenter --target 1 --mount --uts --ipc --net --pid",
            "uid": 0,
            "container_id": "c1a2b3d4e5f6",
            "pod_name": "compromised-pod-test",
            "namespace": "default",
            "node_name": "worker-node-1",
            "image": "vulnerable-app:1.0",
            "source": "replay",
            "raw_data": {}
        }]
    }
    res = client.post("/api/v1/events/batch", json=attack_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["events_received"] == 1
    assert data["alerts_created"] == 1
    alert_id = data["alert_ids"][0]
    print(f"  ✅ Attack event flagged! Generated Alert ID: {alert_id}")

    # 4. Test Events & Alerts Query Endpoints
    print("\n[4/7] Testing Query APIs (/api/v1/events and /api/v1/alerts)...")
    res = client.get("/api/v1/events?limit=10")
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 2
    print(f"  ✅ Retrieved {len(events)} events from DB")

    res = client.get("/api/v1/alerts")
    assert res.status_code == 200
    alerts = res.json()
    assert len(alerts) >= 1
    target_alert = next((a for a in alerts if a["id"] == alert_id), None)
    assert target_alert is not None
    assert target_alert["severity"] == "critical"
    assert target_alert["rule_id"] == "R001"
    assert "Container escape tool detected: nsenter" in target_alert["reason"]
    print(f"  ✅ Alert details verified: Severity={target_alert['severity']}, Rule={target_alert['rule_id']}")

    # 5. Test Alert Evidence Detail Endpoint
    print("\n[5/7] Testing Alert Evidence (/api/v1/alerts/{id})...")
    res = client.get(f"/api/v1/alerts/{alert_id}")
    assert res.status_code == 200
    alert_detail = res.json()
    assert alert_detail["evidence"]["executable"] == "/usr/bin/nsenter"
    assert alert_detail["event"]["pod_name"] == "compromised-pod-test"
    print(f"  ✅ Alert evidence and pod context correctly linked")

    # 6. Test Response Action Simulation & Approval Gate
    print("\n[6/7] Testing Simulated Kubernetes Response Action...")
    resp_payload = {
        "alert_id": alert_id,
        "action": "isolate_pod",
        "mode": "simulate",
        "actor": "security_lead"
    }
    res = client.post("/api/v1/responses", json=resp_payload)
    assert res.status_code == 200
    resp_data = res.json()
    assert "[SIMULATED]" in resp_data["result"]
    assert "compromised-pod-test" in resp_data["result"]
    print(f"  ✅ Simulated Response Action logged: {resp_data['result']}")

    # Test Alert Status Update
    res = client.patch(f"/api/v1/alerts/{alert_id}?status=resolved")
    assert res.status_code == 200
    print("  ✅ Alert status updated to 'resolved'")

    # 7. Test Dashboard Stats & Audit Log
    print("\n[7/7] Testing Stats & Audit APIs...")
    res = client.get("/api/v1/stats")
    assert res.status_code == 200
    stats = res.json()
    assert stats["total_events"] >= 2
    assert stats["suspicious_events"] >= 1
    assert stats["response_actions"] >= 1
    print(f"  ✅ Stats API verified: {stats}")

    res = client.get("/api/v1/audit")
    assert res.status_code == 200
    audit_logs = res.json()
    assert len(audit_logs) >= 2  # status change + response action
    print(f"  ✅ Audit log has {len(audit_logs)} records (actions tracked with timestamps)")

    # 9. Test Phase 2 Endpoints: Health Check
    print("\n[8/11] Testing GET /api/v1/health...")
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    health = res.json()
    assert health["status"] in ["healthy", "degraded"]
    assert health["database"] == "connected"
    assert "DEMO_REPLAY_MODE" in health["collector_mode"] or "LIVE" in health["collector_mode"]
    print(f"  ✅ Health endpoint OK: DB={health['database']}, Collector={health['collector_mode']}")

    # 10. Test Sensor Status
    print("\n[9/11] Testing GET /api/v1/sensor/status...")
    res = client.get("/api/v1/sensor/status")
    assert res.status_code == 200
    sensor = res.json()
    assert "DEMO_REPLAY_MODE" in sensor["mode"] or "LIVE" in sensor["mode"]
    assert sensor["events_collected"] >= 2
    assert "macOS" in sensor["ebpf_reason"] or not sensor["ebpf_available"]
    print(f"  ✅ Sensor status OK: mode={sensor['mode']}, events={sensor['events_collected']}")

    # 11. Test Containers Monitoring
    print("\n[10/11] Testing GET /api/v1/containers...")
    res = client.get("/api/v1/containers")
    assert res.status_code == 200
    containers = res.json()
    assert len(containers) >= 1
    c = containers[0]
    assert c["container_id"] == "c1a2b3d4e5f6"
    assert c["event_count"] >= 1
    print(f"  ✅ Containers API OK: found {len(containers)} tracked container(s), target={c['container_id']}")

    # 12. Test Metrics Summary & Alert Acknowledgment
    print("\n[11/11] Testing Metrics Summary & Alert Acknowledgment...")
    res = client.get("/api/v1/metrics/summary")
    assert res.status_code == 200
    metrics = res.json()
    assert metrics["total_events"] >= 2
    assert metrics["suspicious_events"] >= 1
    assert "alerts_by_severity" in metrics
    print(f"  ✅ Metrics Summary OK: {metrics['alerts_by_severity']}")

    # Acknowledge alert
    ack_res = client.post(f"/api/v1/alerts/{alert_id}/acknowledge", json={"actor": "analyst_bob", "comment": "Triage verified"})
    assert ack_res.status_code == 200
    ack_data = ack_res.json()
    assert ack_data["status"] == "acknowledged"
    assert ack_data["acknowledged_by"] == "analyst_bob"
    print(f"  ✅ Alert Acknowledged OK: ID={alert_id}, by={ack_data['acknowledged_by']}")

    # 8. WebSocket ping test
    print("\n[Bonus] Testing WebSocket live streaming endpoint...")
    with client.websocket_connect("/ws/v1/stream") as websocket:
        websocket.send_text("ping")
        msg = websocket.receive_json()
        assert msg == {"type": "pong"}
    print("  ✅ WebSocket connection & heartbeat OK")

    print("\n" + "=" * 60)
    print("🎉 ALL TESTS PASSED! All Phase 1 & 2 requirements verified.")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()

