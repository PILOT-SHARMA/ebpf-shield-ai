"""
schemas.py — Pydantic models for API request/response validation.
Owner: Aryan Gupta (backend)
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


# ──────────────────────────────────────────────
# Event Schemas
# ──────────────────────────────────────────────

class EventCreate(BaseModel):
    """Schema for a single incoming event from the eBPF sensor or replay."""
    event_type: str = Field(..., description="process_exec | file_open | net_connect")
    pid: int = 0
    ppid: int = 0
    executable: str = ""
    args: str = ""
    uid: int = 0
    container_id: str = ""
    pod_name: str = ""
    namespace: str = "default"
    node_name: str = ""
    image: str = ""
    source: str = "replay"
    raw_data: dict = {}


class EventBatch(BaseModel):
    """Batch of events from the collector — matches /api/v1/events/batch."""
    events: List[EventCreate]


class EventResponse(BaseModel):
    """Full event as returned from the API."""
    id: str
    observed_at: datetime
    event_type: str
    pid: int
    ppid: int
    executable: str
    args: str
    uid: int
    container_id: str
    pod_name: str
    namespace: str
    node_name: str
    image: str
    threat_score: float
    is_suspicious: int
    detection_method: str
    detection_reason: str
    source: str

    class Config:
        from_attributes = True


# ──────────────────────────────────────────────
# Alert Schemas
# ──────────────────────────────────────────────

class AlertResponse(BaseModel):
    """Alert as returned from the API."""
    id: str
    created_at: datetime
    event_id: str
    severity: str
    score: float
    status: str
    rule_id: str
    model_version: str
    reason: str
    evidence: dict
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: str = ""
    event: Optional[EventResponse] = None

    class Config:
        from_attributes = True


class AcknowledgeRequest(BaseModel):
    """Request to acknowledge an alert."""
    actor: str = "analyst"
    notes: str = ""


# ──────────────────────────────────────────────
# Response Action Schemas
# ──────────────────────────────────────────────

class ResponseCreate(BaseModel):
    """Request to create a response action."""
    alert_id: str
    action: str = "isolate_pod"
    mode: str = "simulate"
    actor: str = "analyst"


class ResponseActionResponse(BaseModel):
    """Response action as returned from the API."""
    id: str
    alert_id: str
    action: str
    mode: str
    actor: str
    result: str
    created_at: datetime

    class Config:
        from_attributes = True


# ──────────────────────────────────────────────
# Dashboard Stats
# ──────────────────────────────────────────────

class DashboardStats(BaseModel):
    """Aggregate stats for the dashboard header."""
    total_events: int = 0
    suspicious_events: int = 0
    open_alerts: int = 0
    critical_alerts: int = 0
    response_actions: int = 0


# ──────────────────────────────────────────────
# Container Info
# ──────────────────────────────────────────────

class ContainerResponse(BaseModel):
    """Container info as returned from the API."""
    id: str
    container_id: str
    image: str
    pod_name: str
    namespace: str
    node_name: str
    status: str
    first_seen: datetime
    last_seen: datetime
    event_count: int
    alert_count: int
    threat_level: str

    class Config:
        from_attributes = True


# ──────────────────────────────────────────────
# Health & Sensor Status
# ──────────────────────────────────────────────

class HealthResponse(BaseModel):
    """Application health status."""
    status: str = "healthy"
    version: str = "1.0.0"
    database: str = "connected"
    collector_mode: str = "replay"
    uptime_seconds: float = 0.0
    timestamp: datetime


class SensorStatusResponse(BaseModel):
    """Telemetry sensor status."""
    mode: str = "DEMO_REPLAY_MODE"
    status: str = "active"
    events_collected: int = 0
    last_event_at: Optional[datetime] = None
    ebpf_available: bool = False
    ebpf_reason: str = ""
    collector_uptime_seconds: float = 0.0


# ──────────────────────────────────────────────
# Metrics Summary
# ──────────────────────────────────────────────

class MetricsSummary(BaseModel):
    """Extended security metrics for analytics."""
    total_events: int = 0
    suspicious_events: int = 0
    open_alerts: int = 0
    critical_alerts: int = 0
    high_alerts: int = 0
    medium_alerts: int = 0
    low_alerts: int = 0
    response_actions: int = 0
    containers_monitored: int = 0
    events_by_type: dict = {}
    alerts_by_severity: dict = {}
    detection_methods: dict = {}
    top_triggered_rules: List[dict] = []
    recent_threat_scores: List[float] = []
    events_last_hour: int = 0
    alerts_last_hour: int = 0


# ──────────────────────────────────────────────
# Anomaly Prediction
# ──────────────────────────────────────────────

class AnomalyPredictionResponse(BaseModel):
    """Anomaly prediction record."""
    id: str
    event_id: str
    model_name: str
    ml_score: float
    rule_score: float
    final_score: float
    is_anomaly: int
    features_used: dict
    created_at: datetime

    class Config:
        from_attributes = True
