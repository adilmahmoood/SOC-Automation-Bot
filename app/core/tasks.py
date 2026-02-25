from __future__ import annotations

import uuid
import logging
from typing import Optional

from sqlalchemy.orm import Session

from app.core.celery_app import celery_app
from app.database.session import SessionLocal
from app.database import crud

logger = logging.getLogger(__name__)


@celery_app.task(
    bind=True,
    name="app.core.tasks.process_alert",
    max_retries=3,
    default_retry_delay=5,
    acks_late=True,
)
def process_alert(self, alert_id: str) -> dict:
    """
    Main orchestration task for processing a security alert.
    Pipeline: Normalize → Enrich → Analyze → Respond
    """
    db: Session = SessionLocal()
    try:
        logger.info(f"[Task] Starting processing for alert {alert_id}")

        # ── 1. Fetch alert from DB ─────────────────────────────────────────────
        alert = crud.get_alert(db, alert_id)
        if not alert:
            logger.error(f"[Task] Alert {alert_id} not found in DB")
            return {"status": "error", "message": "Alert not found"}

        crud.update_alert_status(db, alert_id, "InProgress")

        # ── 2. Normalize ───────────────────────────────────────────────────────
        from app.modules.normalization.normalizer import Normalizer
        normalizer = Normalizer()
        normalized_data = normalizer.normalize(alert.raw_data, alert.source_integration)
        crud.update_alert_normalized_data(db, alert_id, normalized_data)
        logger.info(f"[Task] Normalization complete for {alert_id}")

        # ── 3. Extract observables & Enrich ───────────────────────────────────
        from app.modules.enrichment.cache import EnrichmentCache
        from app.modules.enrichment.virustotal import VirusTotalEnricher
        from app.modules.enrichment.abuseipdb import AbuseIPDBEnricher
        from app.modules.enrichment.otx import OTXEnricher

        cache = EnrichmentCache()
        enrichers = [VirusTotalEnricher(), AbuseIPDBEnricher(), OTXEnricher()]

        observables = _extract_observables(normalized_data)
        enrichment_results = []

        for obs_type, obs_value in observables:
            for enricher in enrichers:
                result = cache.get(enricher.provider_name, obs_value)
                if result is None:
                    result = enricher.enrich(obs_type, obs_value)
                    cache.set(enricher.provider_name, obs_value, result)

                enrich_record = crud.create_enrichment_result(
                    db,
                    alert_id=alert_id,
                    observable_type=obs_type,
                    observable_value=obs_value,
                    source_provider=enricher.provider_name,
                    result_data=result,
                    reputation_score=result.get("reputation_score", 0.0),
                )
                enrichment_results.append(result)

        logger.info(f"[Task] Enrichment complete: {len(enrichment_results)} results")

        # ── 4. Risk Scoring ───────────────────────────────────────────────────
        from app.modules.analysis.risk_scorer import RiskScorer
        scorer = RiskScorer()
        risk_score, severity = scorer.calculate(
            normalized_data,
            enrichment_results,
            alert.source_integration,
        )
        crud.update_alert_risk(db, alert_id, risk_score, severity)
        logger.info(f"[Task] Risk score: {risk_score} → Severity: {severity}")

        # ── 5. Execute Playbook ────────────────────────────────────────────────
        from app.modules.response.playbook_engine import PlaybookEngine
        engine = PlaybookEngine(db=db, alert_id=alert_id)
        engine.run(severity=severity, normalized_data=normalized_data)
        logger.info(f"[Task] Playbook execution complete for {alert_id}")

        # ── 6. Finalize ────────────────────────────────────────────────────────
        crud.update_alert_status(db, alert_id, "Closed" if severity in ("Info", "Low") else "InProgress")

        return {
            "status": "success",
            "alert_id": alert_id,
            "risk_score": risk_score,
            "severity": severity,
        }

    except Exception as exc:
        logger.exception(f"[Task] Processing failed for alert {alert_id}: {exc}")
        crud.update_alert_status(db, alert_id, "New")
        raise self.retry(exc=exc, countdown=5)
    finally:
        db.close()


def _extract_observables(normalized_data: dict) -> list[tuple[str, str]]:
    """Extract IP addresses, domains, and file hashes from normalized alert data."""
    import re
    observables: list[tuple[str, str]] = []

    ip_fields = ["src_ip", "dest_ip", "source_ip", "destination_ip"]
    for field in ip_fields:
        val = normalized_data.get(field)
        if val and val not in ("unknown", "null", None):
            observables.append(("ip", val))

    domain_fields = ["domain", "hostname", "fqdn"]
    for field in domain_fields:
        val = normalized_data.get(field)
        if val and val not in ("unknown", "null", None):
            observables.append(("domain", val))

    hash_fields = ["file_hash", "md5", "sha256", "sha1"]
    for field in hash_fields:
        val = normalized_data.get(field)
        if val and val not in ("unknown", "null", None):
            observables.append(("hash", val))

    return list(set(observables))  # deduplicate
