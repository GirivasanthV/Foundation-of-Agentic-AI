from contextlib import asynccontextmanager

import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import Base, engine, get_db
from app.models import AuditEvent, BlocklistEntry, Investigation
from app.extension_service import analyse_hash, analyse_page
from app.schemas import (
    AnalystDecision,
    AuditRead,
    BlocklistRead,
    ExtensionHashScan,
    ExtensionPageScan,
    InvestigationCreate,
    InvestigationRead,
    SystemStatusRead,
)
from app.security import UnsafeIndicator
from app.services import (
    create_investigation,
    decide_investigation,
    list_blocklist,
    list_investigations,
    remove_blocklist_entry,
)


@asynccontextmanager
async def lifespan(_: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


settings = get_settings()
app = FastAPI(title=settings.app_name, version="0.3.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_origin_regex=r"chrome-extension://.*|extension://.*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def verify_extension_token(x_extension_token: str = Header(default="")) -> None:
    if not secrets.compare_digest(x_extension_token, settings.extension_token):
        raise HTTPException(status_code=401, detail="Invalid browser-extension token")


@app.get("/health")
def health() -> dict:
    return {"status": "healthy", "service": settings.app_name, "mode": "live"}


@app.get("/api/v1/system/status", response_model=SystemStatusRead)
def system_status():
    local_vlm_ready = bool(settings.vlm_base_url and settings.vlm_model)
    warnings = []
    if not any((settings.virustotal_api_key, settings.abuseipdb_api_key, settings.urlscan_api_key)):
        warnings.append("No external threat-intelligence API key is configured; URL structural checks remain available.")
    if not local_vlm_ready:
        warnings.append("Local VLM is not configured; screenshots will be captured but pixel-level AI evaluation will be unavailable.")
    return {
        "mode": "live",
        "response_mode": settings.response_mode,
        "providers": {
            "VirusTotal": bool(settings.virustotal_api_key),
            "AbuseIPDB": bool(settings.abuseipdb_api_key),
            "URLScan": bool(settings.urlscan_api_key),
            "Docker VLM": local_vlm_ready,
            "Azure AI Search": bool(settings.azure_search_endpoint and settings.azure_search_api_key),
            "Azure Blob Storage": bool(settings.azure_storage_connection_string),
        },
        "capabilities": {
            "multi_agent": True,
            "local_rag": True,
            "automatic_screenshot": settings.auto_capture_screenshots,
            "vlm": local_vlm_ready,
            "hitl": True,
            "blocklist": True,
            "audit": True,
            "browser_extension": True,
        },
        "warnings": warnings,
    }


@app.get("/api/v1/investigations", response_model=list[InvestigationRead])
def investigations(db: Session = Depends(get_db)):
    return list_investigations(db)


@app.post("/api/v1/investigations", response_model=InvestigationRead, status_code=status.HTTP_201_CREATED)
def investigate(payload: InvestigationCreate, db: Session = Depends(get_db)):
    try:
        return create_investigation(db, payload.indicator, payload.title, payload.screenshot_data_url, auto_capture=payload.auto_capture)
    except (UnsafeIndicator, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/v1/investigations/{investigation_id}", response_model=InvestigationRead)
def investigation(investigation_id: str, db: Session = Depends(get_db)):
    record = db.get(Investigation, investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return record


@app.post("/api/v1/investigations/{investigation_id}/decision", response_model=InvestigationRead)
def analyst_decision(investigation_id: str, payload: AnalystDecision, db: Session = Depends(get_db)):
    record = db.get(Investigation, investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")
    try:
        return decide_investigation(db, record, payload.decision, payload.comment)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/v1/audit", response_model=list[AuditRead])
def audit_log(db: Session = Depends(get_db)):
    return list(db.scalars(select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(100)).all())


@app.get("/api/v1/blocklist", response_model=list[BlocklistRead])
def blocklist(db: Session = Depends(get_db)):
    return list_blocklist(db)


@app.delete("/api/v1/blocklist/{entry_id}", response_model=BlocklistRead)
def remove_from_blocklist(entry_id: str, db: Session = Depends(get_db)):
    entry = db.get(BlocklistEntry, entry_id)
    if not entry:
        raise HTTPException(status_code=404, detail="Blocklist entry not found")
    try:
        return remove_blocklist_entry(db, entry)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/api/v1/extension/analyze-page", response_model=InvestigationRead, dependencies=[Depends(verify_extension_token)])
def extension_page_scan(payload: ExtensionPageScan, db: Session = Depends(get_db)):
    try:
        return analyse_page(db, payload.url, payload.title, payload.screenshot_data_url)
    except (UnsafeIndicator, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/v1/extension/analyze-hash", response_model=InvestigationRead, dependencies=[Depends(verify_extension_token)])
def extension_hash_scan(payload: ExtensionHashScan, db: Session = Depends(get_db)):
    return analyse_hash(db, payload.sha256, payload.filename, payload.size_bytes)
