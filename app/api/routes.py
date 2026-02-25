from __future__ import annotations

import logging
from typing import Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.api.auth import verify_api_key
from app.api.models import (
    AlertIngestionRequest,
    AlertIngestionResponse,
    AlertResponse,
    AlertListResponse,
    MetricsResponse,
    ManualActionRequest,
)
from app.database.session import get_db
from app.database import crud
from app.core.tasks import process_alert

logger = logging.getLogger(__name__)

router = APIRouter()


# ─── Alert Ingestion ──────────────────────────────────────────────────────────

@router.post(
    "/alert",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AlertIngestionResponse,
    summary="Ingest a new security alert",
    tags=["Ingestion"],
)
async def ingest_alert(
    payload: AlertIngestionRequest,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    """
    Accepts a security alert from any source (Wazuh, Splunk, Generic webhook).
    Returns 202 Accepted immediately and queues processing via Celery.
    """
    # Build raw_data from payload (merge extra fields)
    raw = payload.model_dump(exclude_none=False)
    if payload.raw_data:
        raw.update(payload.raw_data)

    alert = crud.create_alert(
        db=db,
        source_integration=payload.source,
        raw_data=raw,
        external_id=payload.external_id,
    )

    # Queue the processing task
    task = process_alert.delay(str(alert.id))
    logger.info(f"[API] Alert {alert.id} queued as task {task.id}")

    return AlertIngestionResponse(
        job_id=task.id,
        alert_id=str(alert.id),
        status="accepted",
        message="Alert queued for processing.",
    )


# ─── Alert Listing ────────────────────────────────────────────────────────────

@router.get(
    "/alerts",
    response_model=AlertListResponse,
    summary="List all alerts with filtering and pagination",
    tags=["Alerts"],
)
async def list_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, alias="status"),
    severity: Optional[str] = Query(None),
    date_start: Optional[datetime] = Query(None),
    date_end: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    alerts, total = crud.list_alerts(
        db,
        page=page,
        limit=limit,
        status=status_filter,
        severity=severity,
        date_start=date_start,
        date_end=date_end,
    )
    return AlertListResponse(
        total=total,
        page=page,
        limit=limit,
        alerts=alerts,
    )


# ─── Alert Detail ─────────────────────────────────────────────────────────────

@router.get(
    "/alerts/{alert_id}",
    response_model=AlertResponse,
    summary="Get full details of a specific alert",
    tags=["Alerts"],
)
async def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    alert = crud.get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert


# ─── Manual Action Trigger ────────────────────────────────────────────────────

@router.post(
    "/alerts/{alert_id}/actions/{action_name}",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Manually trigger a response action on an alert",
    tags=["Actions"],
)
async def trigger_action(
    alert_id: str,
    action_name: str,
    body: ManualActionRequest,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    alert = crud.get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    supported_actions = ["block_ip", "notify_slack", "create_jira_ticket", "isolate_host"]
    if action_name not in supported_actions:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported action '{action_name}'. Supported: {supported_actions}",
        )

    # Dispatch action
    from app.modules.response.playbook_engine import PlaybookEngine
    engine = PlaybookEngine(db=db, alert_id=alert_id)
    result = engine.run_single_action(
        action_name=action_name,
        params=body.parameters,
        executed_by=body.executed_by or "analyst",
    )

    return {
        "alert_id": alert_id,
        "action": action_name,
        "result": result,
    }


# ─── Metrics ──────────────────────────────────────────────────────────────────

@router.get(
    "/metrics",
    response_model=MetricsResponse,
    summary="Get system-wide alert metrics",
    tags=["Dashboard"],
)
async def get_metrics(
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
):
    return crud.get_metrics(db)
