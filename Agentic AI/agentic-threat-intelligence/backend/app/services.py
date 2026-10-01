from pathlib import Path

from azure.core.exceptions import ResourceExistsError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agents.graph import investigation_graph
from app.config import get_settings
from app.models import AuditEvent, BlocklistEntry, Investigation
from app.agents.live_analysis import decode_and_store_screenshot
from app.security import normalize_indicator
from app.screenshot_capture import ScreenshotCaptureError, capture_url_screenshot
from app.azure.clients import azure_blob_client


def add_audit(db: Session, investigation_id: str, actor: str, action: str, details: dict) -> None:
    db.add(AuditEvent(investigation_id=investigation_id, actor=actor, action=action, details=details))


def create_investigation(
    db: Session,
    indicator: str,
    title: str = "",
    screenshot_data_url: str | None = None,
    origin: str = "dashboard",
    extra_evidence: dict | None = None,
    auto_capture: bool = True,
) -> Investigation:
    try:
        indicator_type, normalized = normalize_indicator(indicator)
        record = Investigation(
            indicator=indicator,
            indicator_type=indicator_type,
            normalized_indicator=normalized,
            status="running",
        )
        db.add(record)
        db.flush()
        add_audit(db, record.id, origin, "investigation.created", {"indicator_type": indicator_type, "screenshot_included": bool(screenshot_data_url)})

        screenshot_path = None
        screenshot_source = "uploaded" if screenshot_data_url else "none"
        screenshot_error = None
        if indicator_type == "url" and not screenshot_data_url and auto_capture and get_settings().auto_capture_screenshots:
            try:
                screenshot_data_url, captured_title = capture_url_screenshot(normalized, get_settings())
                title = title or captured_title
                screenshot_source = "automatic"
                add_audit(db, record.id, "screenshot-agent", "screenshot.captured", {"source": "automatic"})
            except ScreenshotCaptureError as exc:
                screenshot_error = str(exc)
                add_audit(db, record.id, "screenshot-agent", "screenshot.failed", {"reason": screenshot_error})
        screenshot_storage = None
        if screenshot_data_url:
            screenshot_bytes, screenshot_path = decode_and_store_screenshot(screenshot_data_url, record.id, get_settings())
            screenshot_storage = {"provider": "local", "status": "stored", "path": screenshot_path}
            if get_settings().azure_storage_connection_string and screenshot_bytes:
                try:
                    blob_name = Path(screenshot_path).name
                    blob_service = azure_blob_client(get_settings())
                    container = blob_service.get_container_client(get_settings().azure_storage_container)
                    try:
                        container.create_container()
                    except ResourceExistsError:
                        pass
                    blob = blob_service.get_blob_client(
                        container=get_settings().azure_storage_container,
                        blob=blob_name,
                    )
                    blob.upload_blob(screenshot_bytes, overwrite=True)
                    screenshot_storage = {
                        "provider": "azure_blob",
                        "status": "stored",
                        "container": get_settings().azure_storage_container,
                        "blob_name": blob_name,
                    }
                except Exception as exc:
                    screenshot_storage["cloud_error"] = str(exc)[:240]

        result = investigation_graph.invoke(
            {
                "indicator": indicator,
                "indicator_type": indicator_type,
                "normalized_indicator": normalized,
                "page_title": title,
                "screenshot_data_url": screenshot_data_url,
                "screenshot_path": screenshot_path,
                "agent_trace": [],
            }
        )
        record.risk_score = result["risk_score"]
        record.confidence = result["confidence"]
        record.verdict = result["verdict"]
        record.recommended_action = result["recommended_action"]
        record.status = "awaiting_approval" if result["approval_required"] else "completed"
        record.agent_trace = result["agent_trace"]
        record.evidence = {
            "threat_intelligence": result["threat_intel"],
            "visual_analysis": result["visual_analysis"],
            "rag_context": result["rag_context"],
            "risk_explanation": result["risk_explanation"],
            "page": {
                "title": title,
                "screenshot_path": screenshot_path,
                "screenshot_included": bool(screenshot_data_url),
                "screenshot_source": screenshot_source,
                "screenshot_error": screenshot_error,
                "storage": screenshot_storage,
            },
            **(extra_evidence or {}),
        }
        add_audit(
            db,
            record.id,
            "orchestrator-agent",
            "investigation.assessed",
            {"verdict": record.verdict, "risk_score": record.risk_score, "action": record.recommended_action},
        )
        db.commit()
        db.refresh(record)
        return record
    except Exception:
        db.rollback()
        raise


def decide_investigation(db: Session, record: Investigation, decision: str, comment: str) -> Investigation:
    if record.status != "awaiting_approval":
        raise ValueError("This investigation is not awaiting analyst approval")

    record.analyst_decision = decision
    if decision == "approve":
        settings = get_settings()
        existing = db.scalar(
            select(BlocklistEntry).where(
                BlocklistEntry.indicator == record.normalized_indicator,
                BlocklistEntry.status == "active",
            )
        )
        if not existing:
            db.add(
                BlocklistEntry(
                    indicator=record.normalized_indicator,
                    indicator_type=record.indicator_type,
                    source_investigation_id=record.id,
                    reason=comment or f"Approved {record.verdict} investigation ({record.risk_score}/100)",
                    enforcement_mode=settings.response_mode,
                )
            )
        record.status = "blocked" if settings.response_mode == "enforce" else "response_simulated"
        response = f"Indicator added to the {settings.response_mode} blocklist"
    elif decision == "reject":
        record.status = "rejected"
        response = "Recommended response rejected; no block performed"
    else:
        record.status = "monitoring"
        record.recommended_action = "MONITOR"
        response = "Response overridden to monitoring"

    add_audit(db, record.id, "soc-analyst", f"decision.{decision}", {"comment": comment, "result": response})
    db.commit()
    db.refresh(record)
    return record


def list_investigations(db: Session) -> list[Investigation]:
    return list(db.scalars(select(Investigation).order_by(Investigation.created_at.desc())).all())


def list_blocklist(db: Session) -> list[BlocklistEntry]:
    return list(db.scalars(select(BlocklistEntry).order_by(BlocklistEntry.created_at.desc())).all())


def remove_blocklist_entry(db: Session, entry: BlocklistEntry) -> BlocklistEntry:
    if entry.status != "active":
        raise ValueError("This blocklist entry is already inactive")
    entry.status = "removed"
    add_audit(
        db,
        entry.source_investigation_id,
        "soc-analyst",
        "blocklist.removed",
        {"indicator": entry.indicator, "entry_id": entry.id},
    )
    db.commit()
    db.refresh(entry)
    return entry
