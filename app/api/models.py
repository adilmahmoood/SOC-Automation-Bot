from __future__ import annotations

from datetime import datetime
from typing import Optional, Any, Dict, List
from uuid import UUID

from pydantic import BaseModel, Field, validator


# ─── Request Models ───────────────────────────────────────────────────────────

class AlertIngestionRequest(BaseModel):
    """Payload for POST /api/v1/alert"""
    source: str = Field(..., description="Source system (e.g. 'Wazuh', 'Splunk', 'Generic')")
    event_type: Optional[str] = Field(None, description="Type of event (e.g. 'brute_force')")
    severity: Optional[str] = Field(None, description="Initial severity from source")
    src_ip: Optional[str] = Field(None, description="Source IP address")
    dest_ip: Optional[str] = Field(None, description="Destination IP address")
    domain: Optional[str] = Field(None, description="Domain name involved")
    file_hash: Optional[str] = Field(None, description="File hash (MD5/SHA256)")
    external_id: Optional[str] = Field(None, description="ID from source system")
    raw_data: Optional[Dict[str, Any]] = Field(None, description="Full raw alert payload")

    class Config:
        extra = "allow"  # Accept any extra fields from various SIEMs


class ManualActionRequest(BaseModel):
    """Payload for manual action trigger"""
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    executed_by: Optional[str] = Field("analyst", description="User triggering the action")


# ─── Response Models ──────────────────────────────────────────────────────────

class AlertIngestionResponse(BaseModel):
    job_id: str
    alert_id: str
    status: str
    message: str


class EnrichmentResultResponse(BaseModel):
    id: UUID
    observable_type: str
    observable_value: str
    source_provider: str
    reputation_score: Optional[float]
    queried_at: datetime

    class Config:
        from_attributes = True


class ActionLogResponse(BaseModel):
    id: UUID
    action_name: str
    status: str
    output_log: Optional[str]
    executed_at: datetime
    executed_by: str

    class Config:
        from_attributes = True


class AlertResponse(BaseModel):
    id: UUID
    source_integration: str
    external_id: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]
    risk_score: Optional[int]
    severity: Optional[str]
    status: str
    normalized_data: Optional[Dict[str, Any]]
    enrichment_results: List[EnrichmentResultResponse] = []
    action_logs: List[ActionLogResponse] = []

    class Config:
        from_attributes = True


class AlertListResponse(BaseModel):
    total: int
    page: int
    limit: int
    alerts: List[AlertResponse]


class MetricsResponse(BaseModel):
    total_alerts: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    average_risk_score: float


class HealthResponse(BaseModel):
    status: str
    version: str = "1.0.0"
    environment: str
