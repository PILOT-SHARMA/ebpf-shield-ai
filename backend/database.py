"""
database.py — SQLAlchemy models and PostgreSQL/SQLite engine for eBPF-Shield AI.
Owner: Aryan Gupta (backend / database)

Supports both PostgreSQL (Docker) and SQLite (local development) via DATABASE_URL.
"""

import os
import uuid
import time
import datetime as dt
from typing import Optional, List, Any
from sqlalchemy import (
    create_engine, String, Float, Integer, DateTime,
    Text, ForeignKey, JSON, Boolean, Index, text
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker

# Use PostgreSQL in Docker, fall back to SQLite for local dev
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "sqlite:///./ebpf_shield.db"
)

# Handle PostgreSQL driver prefix
if DATABASE_URL.startswith("postgresql://"):
    try:
        import psycopg
    except ImportError:
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg2://", 1)

# Handle connection args based on database type
connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    echo=False,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def new_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ──────────────────────────────────────────────
# Models (match the synopsis data dictionary)
# ──────────────────────────────────────────────

class RuntimeEvent(Base):
    """Stores normalized process, file, or network events."""
    __tablename__ = "runtime_events"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    observed_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    event_type: Mapped[str] = mapped_column(String, nullable=False)       # process_exec, file_open, net_connect
    pid: Mapped[int] = mapped_column(Integer, default=0)
    ppid: Mapped[int] = mapped_column(Integer, default=0)
    executable: Mapped[str] = mapped_column(String, default="")
    args: Mapped[str] = mapped_column(Text, default="")
    uid: Mapped[int] = mapped_column(Integer, default=0)
    # Container context (enrichment)
    container_id: Mapped[str] = mapped_column(String, default="", index=True)
    pod_name: Mapped[str] = mapped_column(String, default="")
    namespace: Mapped[str] = mapped_column(String, default="default", index=True)
    node_name: Mapped[str] = mapped_column(String, default="")
    image: Mapped[str] = mapped_column(String, default="")
    # Detection results
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_suspicious: Mapped[int] = mapped_column(Integer, default=0)        # 0/1 flag
    detection_method: Mapped[str] = mapped_column(String, default="")     # rule / ml / hybrid
    detection_reason: Mapped[str] = mapped_column(Text, default="")
    # Source tracking
    source: Mapped[str] = mapped_column(String, default="replay")         # replay / ebpf / manual
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)

    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="event")


class Alert(Base):
    """Stores investigation results for flagged events."""
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow, index=True)
    event_id: Mapped[str] = mapped_column(String, ForeignKey("runtime_events.id"), nullable=False)
    severity: Mapped[str] = mapped_column(String, default="medium", index=True)       # low, medium, high, critical
    score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[str] = mapped_column(String, default="open", index=True)           # open, investigating, resolved, false_positive, acknowledged
    rule_id: Mapped[str] = mapped_column(String, default="")
    model_version: Mapped[str] = mapped_column(String, default="isolation_forest_v1")
    reason: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    acknowledged_at: Mapped[Optional[dt.datetime]] = mapped_column(DateTime, nullable=True)
    acknowledged_by: Mapped[str] = mapped_column(String, default="")

    event: Mapped[Optional["RuntimeEvent"]] = relationship("RuntimeEvent", back_populates="alerts")
    responses: Mapped[List["ResponseAction"]] = relationship("ResponseAction", back_populates="alert")


class ResponseAction(Base):
    """Records simulation, approval, and execution of response actions."""
    __tablename__ = "response_actions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    alert_id: Mapped[str] = mapped_column(String, ForeignKey("alerts.id"), nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)           # isolate_pod, terminate_container, quarantine
    mode: Mapped[str] = mapped_column(String, default="simulate")         # simulate, approved, executed
    actor: Mapped[str] = mapped_column(String, default="analyst")
    result: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)

    alert: Mapped[Optional["Alert"]] = relationship("Alert", back_populates="responses")


class AuditLog(Base):
    """Records important user and system actions."""
    __tablename__ = "audit_log"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    actor: Mapped[str] = mapped_column(String, nullable=False)
    action: Mapped[str] = mapped_column(String, nullable=False)
    target: Mapped[str] = mapped_column(String, default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


class ContainerInfo(Base):
    """Tracks monitored containers and their status."""
    __tablename__ = "container_info"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    container_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    image: Mapped[str] = mapped_column(String, default="")
    pod_name: Mapped[str] = mapped_column(String, default="")
    namespace: Mapped[str] = mapped_column(String, default="default")
    node_name: Mapped[str] = mapped_column(String, default="")
    status: Mapped[str] = mapped_column(String, default="running")  # running, stopped, suspicious
    first_seen: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    alert_count: Mapped[int] = mapped_column(Integer, default=0)
    threat_level: Mapped[str] = mapped_column(String, default="normal")  # normal, elevated, critical


class AnomalyPrediction(Base):
    """Stores individual anomaly prediction results for analytics."""
    __tablename__ = "anomaly_predictions"

    id: Mapped[str] = mapped_column(String, primary_key=True, default=new_uuid)
    event_id: Mapped[str] = mapped_column(String, index=True, default="")
    model_name: Mapped[str] = mapped_column(String, default="isolation_forest_v1")
    ml_score: Mapped[float] = mapped_column(Float, default=0.0)
    rule_score: Mapped[float] = mapped_column(Float, default=0.0)
    final_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_anomaly: Mapped[int] = mapped_column(Integer, default=0)
    features_used: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime, default=utcnow)


# ──────────────────────────────────────────────
# Init
# ──────────────────────────────────────────────

def wait_for_db(max_retries: int = 30, delay: float = 1.5) -> bool:
    """Ensure database connection is ready (useful for PostgreSQL in Docker)."""
    for attempt in range(1, max_retries + 1):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
                return True
        except Exception as e:
            if attempt % 5 == 0 or attempt == 1:
                print(f"⏳ Waiting for database readiness (attempt {attempt}/{max_retries})...")
            time.sleep(delay)
    return False


def init_db():
    """Create all tables and perform non-destructive schema migrations."""
    if not DATABASE_URL.startswith("sqlite"):
        wait_for_db()
    Base.metadata.create_all(bind=engine)

    # Ensure schema migrations for existing databases
    with engine.begin() as conn:
        try:
            if "sqlite" in str(engine.url):
                res = conn.execute(text("PRAGMA table_info(alerts)")).fetchall()
                cols = {row[1] for row in res}
                if cols:
                    if "acknowledged_at" not in cols:
                        conn.execute(text("ALTER TABLE alerts ADD COLUMN acknowledged_at TIMESTAMP"))
                    if "acknowledged_by" not in cols:
                        conn.execute(text("ALTER TABLE alerts ADD COLUMN acknowledged_by VARCHAR DEFAULT ''"))
            else:
                # PostgreSQL safe column addition
                conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP"))
                conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS acknowledged_by VARCHAR DEFAULT ''"))
        except Exception as e:
            print(f"Schema migration notice: {e}")

# Auto-initialize tables when database is reachable (e.g., SQLite or existing DB)
try:
    init_db()
except Exception:
    pass


def get_db():
    """FastAPI dependency: yield a session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

