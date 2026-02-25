from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional, List

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, Text, ForeignKey,
    TIMESTAMP, ARRAY, CheckConstraint
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship, DeclarativeBase
from sqlalchemy.sql import func


class Base(DeclarativeBase):
    pass


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_integration = Column(String(50), nullable=False)
    external_id = Column(String(100), nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now())
    raw_data = Column(JSONB, nullable=False)
    normalized_data = Column(JSONB, nullable=True)
    risk_score = Column(Integer, CheckConstraint("risk_score >= 0 AND risk_score <= 100"), nullable=True)
    severity = Column(
        String(20),
        CheckConstraint("severity IN ('Info','Low','Medium','High','Critical')"),
        nullable=True,
    )
    status = Column(
        String(20),
        CheckConstraint("status IN ('New','InProgress','Closed','FalsePositive')"),
        default="New",
        nullable=False,
    )

    # Relationships
    enrichment_results = relationship("EnrichmentResult", back_populates="alert", cascade="all, delete")
    action_logs = relationship("ActionLog", back_populates="alert", cascade="all, delete")

    def __repr__(self):
        return f"<Alert id={self.id} severity={self.severity} status={self.status}>"


class EnrichmentResult(Base):
    __tablename__ = "enrichment_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    observable_type = Column(String(50), nullable=False)   # ip, domain, hash, url
    observable_value = Column(Text, nullable=False)
    source_provider = Column(String(50), nullable=False)   # VirusTotal, AbuseIPDB, OTX
    result_data = Column(JSONB, nullable=True)
    reputation_score = Column(Float, nullable=True)        # 0.0 (clean) – 1.0 (malicious)
    queried_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    # Relationship
    alert = relationship("Alert", back_populates="enrichment_results")

    def __repr__(self):
        return f"<EnrichmentResult {self.source_provider}:{self.observable_value}>"


class ActionLog(Base):
    __tablename__ = "action_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id = Column(UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="CASCADE"), nullable=False)
    playbook_id = Column(UUID(as_uuid=True), ForeignKey("playbooks.id"), nullable=True)
    action_name = Column(String(100), nullable=False)
    status = Column(
        String(20),
        CheckConstraint("status IN ('Pending','Success','Failure','Skipped')"),
        nullable=False,
    )
    output_log = Column(Text, nullable=True)
    executed_at = Column(TIMESTAMP(timezone=True), server_default=func.now())
    executed_by = Column(String(100), default="system")

    # Relationships
    alert = relationship("Alert", back_populates="action_logs")

    def __repr__(self):
        return f"<ActionLog {self.action_name} → {self.status}>"


class Playbook(Base):
    __tablename__ = "playbooks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    trigger_severity = Column(ARRAY(String), nullable=True)
    steps_definition = Column(JSONB, nullable=False)

    def __repr__(self):
        return f"<Playbook {self.name}>"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(
        String(20),
        CheckConstraint("role IN ('Admin','Analyst','Auditor')"),
        default="Analyst",
    )
    is_active = Column(Boolean, default=True)
    created_at = Column(TIMESTAMP(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"
