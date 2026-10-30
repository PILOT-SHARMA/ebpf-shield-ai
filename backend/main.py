"""
main.py — FastAPI application for ContainerShield AI.
Owner: Aryan Gupta (backend)

API endpoints:
  GET  /api/v1/health           — Application health
  GET  /api/v1/containers       — Monitored containers
  GET  /api/v1/events           — View runtime events
  POST /api/v1/events/batch     — Receive sensor events
  GET  /api/v1/alerts           — View alerts
  GET  /api/v1/alerts/{id}      — View alert evidence
  POST /api/v1/alerts/{id}/acknowledge — Acknowledge alert
  PATCH /api/v1/alerts/{id}     — Update alert status
  GET  /api/v1/metrics/summary  — Security statistics
  GET  /api/v1/sensor/status    — Telemetry status
  POST /api/v1/responses        — Request response action
  GET  /api/v1/responses        — List response actions
  GET  /api/v1/stats            — Dashboard stats
  GET  /api/v1/audit            — Audit log
  GET  /api/v1/predictions      — Anomaly predictions
  WS   /ws/events               — Live event streaming (also /ws/v1/stream)
"""

import os
import sys
import time
import datetime as dt
from typing import List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, text

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.database import (
    init_db, get_db, RuntimeEvent, Alert, ResponseAction, AuditLog,
    ContainerInfo, AnomalyPrediction, new_uuid, utcnow
)
from backend.schemas import (
    EventCreate, EventBatch, EventResponse,
    AlertResponse, AcknowledgeRequest, ResponseCreate, ResponseActionResponse,
    DashboardStats, ContainerResponse, HealthResponse, SensorStatusResponse,
    MetricsSummary, AnomalyPredictionResponse,
)
from backend.websocket import manager
from detection.rules import evaluate_rules, RULES
from detection.ml_engine import score_event, combine_scores

# ──────────────────────────────────────────────
# App startup time tracking
# ──────────────────────────────────────────────
APP_START_TIME = time.time()
COLLECTOR_MODE = os.environ.get("COLLECTOR_MODE", "replay").upper()

# ──────────────────────────────────────────────
# App setup
# ──────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database on startup."""
    init_db()
    print("✅ ContainerShield AI backend started")
    print(f"🔧 Collector Mode: {'DEMO_REPLAY_MODE' if COLLECTOR_MODE == 'REPLAY' else 'LIVE_EBPF_MODE'}")
    print("📊 Dashboard: http://localhost:8000")
    print("📡 API docs:  http://localhost:8000/docs")
    yield

app = FastAPI(
    title="ContainerShield AI",
    description="AI-Powered Container Security Monitoring and Anomaly Detection Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────
# Static files — serve the dashboard
# ──────────────────────────────────────────────

frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")


@app.get("/", include_in_schema=False)
async def serve_dashboard():
    return FileResponse(os.path.join(frontend_dir, "index.html"))


# Mount static files for CSS/JS
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")


# ──────────────────────────────────────────────
# Helper: process detection on an event
# ──────────────────────────────────────────────

def process_detection(event_dict: dict, db: Session) -> dict:
    """Run rule + ML detection and create alert if suspicious."""
    # Rule-based detection
    rule_result = evaluate_rules(event_dict)

    # ML-based detection
    ml_score, ml_reason = score_event(event_dict)

    # Combine scores
    verdict = combine_scores(rule_result, ml_score, ml_reason)

    return verdict


def update_container_info(ev: EventCreate, is_suspicious: bool, db: Session):
    """Track container information from events."""
    if not ev.container_id:
        return
    container = db.query(ContainerInfo).filter(
        ContainerInfo.container_id == ev.container_id
    ).first()
    if container:
        container.last_seen = utcnow()
        container.event_count += 1
        if is_suspicious:
            container.alert_count += 1
            container.threat_level = "critical" if container.alert_count >= 3 else "elevated"
            container.status = "suspicious"
        # Update metadata if available
        if ev.image:
            container.image = ev.image
        if ev.pod_name:
            container.pod_name = ev.pod_name
    else:
        container = ContainerInfo(
            id=new_uuid(),
            container_id=ev.container_id,
            image=ev.image,
            pod_name=ev.pod_name,
            namespace=ev.namespace,
            node_name=ev.node_name,
            status="suspicious" if is_suspicious else "running",
            event_count=1,
            alert_count=1 if is_suspicious else 0,
            threat_level="elevated" if is_suspicious else "normal",
        )
        db.add(container)


# ──────────────────────────────────────────────
# API: Health
# ──────────────────────────────────────────────

@app.get("/api/v1/health", response_model=HealthResponse)
async def health_check(db: Session = Depends(get_db)):
    """Application health check."""
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_status = "disconnected"

    return HealthResponse(
        status="healthy" if db_status == "connected" else "degraded",
        version="1.0.0",
        database=db_status,
        collector_mode="DEMO_REPLAY_MODE" if COLLECTOR_MODE == "REPLAY" else "LIVE_EBPF_MODE",
        uptime_seconds=round(time.time() - APP_START_TIME, 1),
        timestamp=dt.datetime.now(dt.timezone.utc),
    )


# ──────────────────────────────────────────────
# API: Sensor Status
# ──────────────────────────────────────────────

@app.get("/api/v1/sensor/status", response_model=SensorStatusResponse)
async def sensor_status(db: Session = Depends(get_db)):
    """Telemetry sensor status."""
    total_events = db.query(func.count(RuntimeEvent.id)).scalar() or 0
    last_event = db.query(RuntimeEvent).order_by(desc(RuntimeEvent.observed_at)).first()

    return SensorStatusResponse(
        mode="DEMO_REPLAY_MODE" if COLLECTOR_MODE == "REPLAY" else "LIVE_EBPF_MODE",
        status="active" if total_events > 0 else "waiting",
        events_collected=total_events,
        last_event_at=last_event.observed_at if last_event else None,
        ebpf_available=False,
        ebpf_reason="Running in Docker on macOS — eBPF requires Linux kernel with BPF support",
        collector_uptime_seconds=round(time.time() - APP_START_TIME, 1),
    )


# ──────────────────────────────────────────────
# API: Containers
# ──────────────────────────────────────────────

@app.get("/api/v1/containers", response_model=List[ContainerResponse])
async def list_containers(
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """List monitored containers."""
    query = db.query(ContainerInfo)
    if status:
        query = query.filter(ContainerInfo.status == status)
    containers = query.order_by(desc(ContainerInfo.last_seen)).limit(limit).all()
    return containers


@app.get("/api/v1/rules")
async def list_rules():
    """List registered detection rules."""
    return [
        {
            "rule_id": getattr(fn, "rule_id", "R000"),
            "name": fn.__name__.replace("detect_", "").replace("_", " ").title(),
            "severity": getattr(fn, "severity", "medium"),
            "description": fn.__doc__.strip() if fn.__doc__ else "",
        }
        for fn in RULES
    ]



# ──────────────────────────────────────────────
# API: Events
# ──────────────────────────────────────────────

@app.post("/api/v1/events/batch", response_model=dict)
async def ingest_events(batch: EventBatch, db: Session = Depends(get_db)):
    """
    Receive a batch of events from the eBPF sensor or replay script.
    Each event is scored by the detection engine and stored.
    Suspicious events generate alerts.
    """
    created_events = []
    created_alerts = []

    for ev in batch.events:
        event_dict = ev.model_dump()

        # Run detection
        verdict = process_detection(event_dict, db)

        # Create event record
        event_id = new_uuid()
        db_event = RuntimeEvent(
            id=event_id,
            event_type=ev.event_type,
            pid=ev.pid,
            ppid=ev.ppid,
            executable=ev.executable,
            args=ev.args,
            uid=ev.uid,
            container_id=ev.container_id,
            pod_name=ev.pod_name,
            namespace=ev.namespace,
            node_name=ev.node_name,
            image=ev.image,
            source=ev.source,
            raw_data=ev.raw_data,
            threat_score=verdict["threat_score"],
            is_suspicious=verdict["is_suspicious"],
            detection_method=verdict["detection_method"],
            detection_reason=verdict["detection_reason"],
        )
        db.add(db_event)
        db.flush()
        created_events.append(event_id)

        # Store anomaly prediction for analytics
        from detection.ml_engine import extract_features
        import numpy as np
        features = extract_features(event_dict)
        prediction = AnomalyPrediction(
            id=new_uuid(),
            event_id=event_id,
            model_name="isolation_forest_v1",
            ml_score=verdict.get("threat_score", 0.0),
            rule_score=verdict.get("threat_score", 0.0) if verdict.get("rule_id") else 0.0,
            final_score=verdict["threat_score"],
            is_anomaly=verdict["is_suspicious"],
            features_used={
                "event_type_code": float(features[0][0]),
                "pid_norm": float(features[0][1]),
                "ppid_norm": float(features[0][2]),
                "uid_root": float(features[0][3]),
                "exe_length": float(features[0][4]),
                "args_length": float(features[0][5]),
                "has_container": float(features[0][6]),
                "slash_count": float(features[0][7]),
            },
        )
        db.add(prediction)

        # Update container tracking
        update_container_info(ev, verdict["is_suspicious"] == 1, db)

        # Create alert if suspicious
        if verdict["is_suspicious"]:
            alert_id = new_uuid()
            db_alert = Alert(
                id=alert_id,
                event_id=event_id,
                severity=verdict["severity"],
                score=verdict["threat_score"],
                rule_id=verdict.get("rule_id", ""),
                reason=verdict["detection_reason"],
                evidence={
                    "executable": ev.executable,
                    "args": ev.args,
                    "pid": ev.pid,
                    "pod": ev.pod_name,
                    "namespace": ev.namespace,
                    "container": ev.container_id,
                    "detection_method": verdict["detection_method"],
                    "recommended_action": _get_recommended_action(verdict),
                },
            )
            db.add(db_alert)
            created_alerts.append(alert_id)

            # Broadcast alert via WebSocket
            alert_broadcast = {
                "id": alert_id,
                "event_id": event_id,
                "severity": verdict["severity"],
                "score": verdict["threat_score"],
                "reason": verdict["detection_reason"],
                "status": "open",
                "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "event": {
                    "executable": ev.executable,
                    "args": ev.args,
                    "event_type": ev.event_type,
                    "pod_name": ev.pod_name,
                    "namespace": ev.namespace,
                    "container_id": ev.container_id,
                },
            }
            await manager.broadcast_alert(alert_broadcast)

        # Broadcast event via WebSocket
        event_broadcast = {
            "id": event_id,
            "observed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "event_type": ev.event_type,
            "executable": ev.executable,
            "args": ev.args,
            "pid": ev.pid,
            "pod_name": ev.pod_name,
            "namespace": ev.namespace,
            "container_id": ev.container_id,
            "threat_score": verdict["threat_score"],
            "is_suspicious": verdict["is_suspicious"],
            "detection_method": verdict["detection_method"],
            "detection_reason": verdict["detection_reason"],
            "source": ev.source,
        }
        await manager.broadcast_event(event_broadcast)

    db.commit()

    return {
        "status": "ok",
        "events_received": len(created_events),
        "alerts_created": len(created_alerts),
        "event_ids": created_events,
        "alert_ids": created_alerts,
    }


def _get_recommended_action(verdict: dict) -> str:
    """Generate a recommended investigation action based on the verdict."""
    severity = verdict.get("severity", "none")
    rule_id = verdict.get("rule_id", "")

    if severity == "critical":
        return "IMMEDIATE: Isolate the container and investigate the process chain. Check for container escape indicators."
    elif severity == "high":
        return "HIGH PRIORITY: Review process activity and network connections. Consider container isolation."
    elif severity == "medium":
        return "INVESTIGATE: Monitor the container for additional suspicious activity. Review detection context."
    else:
        return "MONITOR: Continue monitoring. No immediate action required."


@app.get("/api/v1/events", response_model=List[EventResponse])
async def list_events(
    limit: int = Query(50, ge=1, le=200),
    suspicious_only: bool = False,
    event_type: Optional[str] = None,
    container_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """View runtime events, newest first."""
    query = db.query(RuntimeEvent)
    if suspicious_only:
        query = query.filter(RuntimeEvent.is_suspicious == 1)
    if event_type:
        query = query.filter(RuntimeEvent.event_type == event_type)
    if container_id:
        query = query.filter(RuntimeEvent.container_id == container_id)
    events = query.order_by(desc(RuntimeEvent.observed_at)).limit(limit).all()
    return events


# ──────────────────────────────────────────────
# API: Alerts
# ──────────────────────────────────────────────

@app.get("/api/v1/alerts", response_model=List[AlertResponse])
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """View alerts, newest first."""
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    alerts = query.order_by(desc(Alert.created_at)).limit(limit).all()

    result = []
    for alert in alerts:
        alert_dict = AlertResponse.model_validate(alert)
        # Attach event data
        if alert.event:
            alert_dict.event = EventResponse.model_validate(alert.event)
        result.append(alert_dict)

    return result


@app.get("/api/v1/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, db: Session = Depends(get_db)):
    """View alert evidence."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    result = AlertResponse.model_validate(alert)
    if alert.event:
        result.event = EventResponse.model_validate(alert.event)
    return result


@app.post("/api/v1/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, req: AcknowledgeRequest, db: Session = Depends(get_db)):
    """Acknowledge an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = "acknowledged"
    alert.acknowledged_at = utcnow()
    alert.acknowledged_by = req.actor
    db.add(AuditLog(
        id=new_uuid(),
        actor=req.actor,
        action="alert_acknowledged",
        target=alert_id,
        detail=f"Alert acknowledged by {req.actor}. Notes: {req.notes}",
    ))
    db.commit()
    return {
        "status": "acknowledged",
        "alert_id": alert_id,
        "acknowledged_by": req.actor,
        "acknowledged_at": alert.acknowledged_at.isoformat() if alert.acknowledged_at else None
    }


@app.patch("/api/v1/alerts/{alert_id}")
async def update_alert_status(alert_id: str, status: str = Query(...), db: Session = Depends(get_db)):
    """Update alert status (open, investigating, resolved, false_positive)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = status
    db.add(AuditLog(
        id=new_uuid(),
        actor="analyst",
        action="alert_status_change",
        target=alert_id,
        detail=f"Status changed to {status}",
    ))
    db.commit()
    return {"status": "ok", "alert_id": alert_id, "new_status": status}


# ──────────────────────────────────────────────
# API: Response Actions
# ──────────────────────────────────────────────

@app.post("/api/v1/responses", response_model=ResponseActionResponse)
async def create_response(req: ResponseCreate, db: Session = Depends(get_db)):
    """
    Request a response action (simulate, approve, execute).
    In this prototype, all actions are simulated — no real container changes.
    """
    alert = db.query(Alert).filter(Alert.id == req.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Simulate the response safely
    pod = (alert.event.pod_name if alert.event and alert.event.pod_name else "target-workload")
    cid = (alert.event.container_id[:12] if alert.event and alert.event.container_id else "unknown-container")
    action_results = {
        "isolate_pod": f"[SIMULATED] Pod {pod} network policy applied — isolated from cluster network",
        "terminate_container": f"[SIMULATED] Container {cid} terminated gracefully",
        "quarantine": f"[SIMULATED] Pod {pod} moved to quarantine namespace",
    }
    result = action_results.get(req.action, f"[SIMULATED] Action {req.action} completed")

    response_action = ResponseAction(
        id=new_uuid(),
        alert_id=req.alert_id,
        action=req.action,
        mode=req.mode,
        actor=req.actor,
        result=result,
    )
    db.add(response_action)

    # Update alert status
    alert.status = "investigating"

    # Audit log
    db.add(AuditLog(
        id=new_uuid(),
        actor=req.actor,
        action=f"response_{req.action}",
        target=req.alert_id,
        detail=result,
    ))
    db.commit()

    return response_action


@app.get("/api/v1/responses", response_model=List[ResponseActionResponse])
async def list_responses(
    alert_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """View response actions."""
    query = db.query(ResponseAction)
    if alert_id:
        query = query.filter(ResponseAction.alert_id == alert_id)
    return query.order_by(desc(ResponseAction.created_at)).limit(limit).all()


# ──────────────────────────────────────────────
# API: Dashboard Stats
# ──────────────────────────────────────────────

@app.get("/api/v1/stats", response_model=DashboardStats)
async def get_stats(db: Session = Depends(get_db)):
    """Aggregate stats for the dashboard header."""
    total_events = db.query(func.count(RuntimeEvent.id)).scalar() or 0
    suspicious_events = db.query(func.count(RuntimeEvent.id)).filter(
        RuntimeEvent.is_suspicious == 1
    ).scalar() or 0
    open_alerts = db.query(func.count(Alert.id)).filter(
        Alert.status == "open"
    ).scalar() or 0
    critical_alerts = db.query(func.count(Alert.id)).filter(
        Alert.severity.in_(["critical", "high"])
    ).scalar() or 0
    response_actions = db.query(func.count(ResponseAction.id)).scalar() or 0

    return DashboardStats(
        total_events=total_events,
        suspicious_events=suspicious_events,
        open_alerts=open_alerts,
        critical_alerts=critical_alerts,
        response_actions=response_actions,
    )


# ──────────────────────────────────────────────
# API: Metrics Summary (Extended Analytics)
# ──────────────────────────────────────────────

@app.get("/api/v1/metrics/summary", response_model=MetricsSummary)
async def get_metrics_summary(db: Session = Depends(get_db)):
    """Extended security metrics for the analytics dashboard."""
    total_events = db.query(func.count(RuntimeEvent.id)).scalar() or 0
    suspicious_events = db.query(func.count(RuntimeEvent.id)).filter(
        RuntimeEvent.is_suspicious == 1
    ).scalar() or 0

    # Alert counts by severity
    critical = db.query(func.count(Alert.id)).filter(Alert.severity == "critical").scalar() or 0
    high = db.query(func.count(Alert.id)).filter(Alert.severity == "high").scalar() or 0
    medium = db.query(func.count(Alert.id)).filter(Alert.severity == "medium").scalar() or 0
    low = db.query(func.count(Alert.id)).filter(Alert.severity == "low").scalar() or 0
    open_alerts = db.query(func.count(Alert.id)).filter(Alert.status == "open").scalar() or 0

    # Events by type
    process_events = db.query(func.count(RuntimeEvent.id)).filter(
        RuntimeEvent.event_type == "process_exec"
    ).scalar() or 0
    file_events = db.query(func.count(RuntimeEvent.id)).filter(
        RuntimeEvent.event_type == "file_open"
    ).scalar() or 0
    net_events = db.query(func.count(RuntimeEvent.id)).filter(
        RuntimeEvent.event_type == "net_connect"
    ).scalar() or 0

    # Detection methods
    rule_detections = db.query(func.count(RuntimeEvent.id)).filter(
        RuntimeEvent.detection_method == "rule"
    ).scalar() or 0
    ml_detections = db.query(func.count(RuntimeEvent.id)).filter(
        RuntimeEvent.detection_method == "ml"
    ).scalar() or 0
    hybrid_detections = db.query(func.count(RuntimeEvent.id)).filter(
        RuntimeEvent.detection_method == "hybrid"
    ).scalar() or 0

    # Top triggered rules
    rule_counts = db.query(
        Alert.rule_id, func.count(Alert.id).label("count")
    ).filter(Alert.rule_id != "").group_by(Alert.rule_id).order_by(
        desc("count")
    ).limit(5).all()

    # Recent threat scores
    recent_events = db.query(RuntimeEvent.threat_score).filter(
        RuntimeEvent.is_suspicious == 1
    ).order_by(desc(RuntimeEvent.observed_at)).limit(20).all()

    # Container count
    containers = db.query(func.count(ContainerInfo.id)).scalar() or 0

    response_actions = db.query(func.count(ResponseAction.id)).scalar() or 0

    # Events/alerts in last hour
    one_hour_ago = utcnow() - dt.timedelta(hours=1)
    events_last_hour = db.query(func.count(RuntimeEvent.id)).filter(
        RuntimeEvent.observed_at >= one_hour_ago
    ).scalar() or 0
    alerts_last_hour = db.query(func.count(Alert.id)).filter(
        Alert.created_at >= one_hour_ago
    ).scalar() or 0

    return MetricsSummary(
        total_events=total_events,
        suspicious_events=suspicious_events,
        open_alerts=open_alerts,
        critical_alerts=critical,
        high_alerts=high,
        medium_alerts=medium,
        low_alerts=low,
        response_actions=response_actions,
        containers_monitored=containers,
        events_by_type={
            "process_exec": process_events,
            "file_open": file_events,
            "net_connect": net_events,
        },
        alerts_by_severity={
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        detection_methods={
            "rule": rule_detections,
            "ml": ml_detections,
            "hybrid": hybrid_detections,
        },
        top_triggered_rules=[
            {"rule_id": r[0], "count": r[1]} for r in rule_counts
        ],
        recent_threat_scores=[r[0] for r in recent_events],
        events_last_hour=events_last_hour,
        alerts_last_hour=alerts_last_hour,
    )


# ──────────────────────────────────────────────
# API: Anomaly Predictions
# ──────────────────────────────────────────────

@app.get("/api/v1/predictions", response_model=List[AnomalyPredictionResponse])
async def list_predictions(
    limit: int = Query(50, ge=1, le=200),
    anomaly_only: bool = False,
    db: Session = Depends(get_db),
):
    """View anomaly prediction records."""
    query = db.query(AnomalyPrediction)
    if anomaly_only:
        query = query.filter(AnomalyPrediction.is_anomaly == 1)
    return query.order_by(desc(AnomalyPrediction.created_at)).limit(limit).all()


# ──────────────────────────────────────────────
# API: Audit Log
# ──────────────────────────────────────────────

@app.get("/api/v1/audit")
async def list_audit(limit: int = Query(50, ge=1, le=200), db: Session = Depends(get_db)):
    """View audit log."""
    logs = db.query(AuditLog).order_by(desc(AuditLog.timestamp)).limit(limit).all()
    return [
        {
            "id": log.id,
            "actor": log.actor,
            "action": log.action,
            "target": log.target,
            "detail": log.detail,
            "timestamp": log.timestamp.isoformat() if log.timestamp is not None else "",
        }
        for log in logs
    ]


# ──────────────────────────────────────────────
# WebSocket: Live stream (both /ws/events and /ws/v1/stream for compat)
# ──────────────────────────────────────────────

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket endpoint for live event/alert streaming to the dashboard."""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.websocket("/ws/v1/stream")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for live event/alert streaming to the dashboard (legacy)."""
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
