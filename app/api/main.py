from __future__ import annotations

import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.models import HealthResponse
from app.api.routes import router
from app.core.config import settings

# Configure structured logging
logging.basicConfig(
    level=logging.DEBUG if settings.APP_DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="SOC Automation Bot API",
    description=(
        "A SOAR-based Security Incident Automation System. "
        "Ingests security alerts, enriches them with threat intelligence, "
        "scores risk, and executes automated response playbooks."
    ),
    version="1.2.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ─── CORS ─────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Routes ───────────────────────────────────────────────────────────────────
app.include_router(router, prefix="/api/v1")


# ─── Health Check ─────────────────────────────────────────────────────────────
@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check():
    return HealthResponse(
        status="ok",
        version="1.2.0",
        environment=settings.APP_ENV,
    )


@app.get("/", tags=["System"])
async def root():
    return {
        "service": "SOC Automation Bot",
        "version": "1.2.0",
        "docs": "/docs",
        "health": "/health",
    }
