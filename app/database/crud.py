from __future__ import annotations

import uuid
from typing import Optional, List
from datetime import datetime

from sqlalchemy.orm import Session

from app.database.models import Alert, EnrichmentResult, ActionLog, Playbook, User


# ─── Alert Operations ─────────────────────────────────────────────────────────

def create_alert(
    db: Session,
    source_integration: str,
    raw_data: dict,
    external_id: Optional[str] = None,
) -> Alert:
    alert = Alert(
        source_integration=source_integration,
        raw_data=raw_data,
        external_id=external_id,
        status="New",
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def get_alert(db: Session, alert_id: str) -> Optional[Alert]:
    return db.query(Alert).filter(Alert.id == alert_id).first()


def list_alerts(
    db: Session,
    page: int = 1,
    limit: int = 20,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    date_start: Optional[datetime] = None,
    date_end: Optional[datetime] = None,
) -> tuple[List[Alert], int]:
    query = db.query(Alert)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        query = query.filter(Alert.severity == severity)
    if date_start:
        query = query.filter(Alert.created_at >= date_start)
    if date_end:
        query = query.filter(Alert.created_at <= date_end)
    total = query.count()
    alerts = query.order_by(Alert.created_at.desc()).offset((page - 1) * limit).limit(limit).all()
    return alerts, total


def update_alert_status(db: Session, alert_id: str, status: str) -> Optional[Alert]:
    alert = get_alert(db, alert_id)
    if alert:
        alert.status = status
        db.commit()
        db.refresh(alert)
    return alert


def update_alert_normalized_data(db: Session, alert_id: str, normalized_data: dict) -> Optional[Alert]:
    alert = get_alert(db, alert_id)
    if alert:
        alert.normalized_data = normalized_data
        db.commit()
        db.refresh(alert)
    return alert


def update_alert_risk(db: Session, alert_id: str, risk_score: int, severity: str) -> Optional[Alert]:
    alert = get_alert(db, alert_id)
    if alert:
        alert.risk_score = risk_score
        alert.severity = severity
        db.commit()
        db.refresh(alert)
    return alert


# ─── Enrichment Operations ────────────────────────────────────────────────────

def create_enrichment_result(
    db: Session,
    alert_id: str,
    observable_type: str,
    observable_value: str,
    source_provider: str,
    result_data: dict,
    reputation_score: float,
) -> EnrichmentResult:
    record = EnrichmentResult(
        alert_id=alert_id,
        observable_type=observable_type,
        observable_value=observable_value,
        source_provider=source_provider,
        result_data=result_data,
        reputation_score=reputation_score,
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


def get_enrichment_results(db: Session, alert_id: str) -> List[EnrichmentResult]:
    return db.query(EnrichmentResult).filter(EnrichmentResult.alert_id == alert_id).all()


# ─── Action Log Operations ────────────────────────────────────────────────────

def create_action_log(
    db: Session,
    alert_id: str,
    action_name: str,
    status: str,
    output_log: Optional[str] = None,
    playbook_id: Optional[str] = None,
    executed_by: str = "system",
) -> ActionLog:
    log = ActionLog(
        alert_id=alert_id,
        action_name=action_name,
        status=status,
        output_log=output_log,
        playbook_id=playbook_id,
        executed_by=executed_by,
    )
    db.add(log)
    db.commit()
    db.refresh(log)
    return log


def get_action_logs(db: Session, alert_id: str) -> List[ActionLog]:
    return db.query(ActionLog).filter(ActionLog.alert_id == alert_id).all()


# ─── Metrics ──────────────────────────────────────────────────────────────────

def get_metrics(db: Session) -> dict:
    from sqlalchemy import func
    total = db.query(func.count(Alert.id)).scalar()
    by_status = db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
    by_severity = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    avg_score = db.query(func.avg(Alert.risk_score)).scalar()
    return {
        "total_alerts": total,
        "by_status": {s: c for s, c in by_status},
        "by_severity": {s: c for s, c in by_severity if s},
        "average_risk_score": round(float(avg_score or 0), 2),
    }
