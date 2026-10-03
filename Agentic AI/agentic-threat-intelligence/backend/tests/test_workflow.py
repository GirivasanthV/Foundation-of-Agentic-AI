from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from app.agents.live_analysis import EICAR_SHA256, decision_from_scores
from app.database import Base
from app.models import AuditEvent, BlocklistEntry
from app.security import normalize_indicator
from app.services import create_investigation, decide_investigation, remove_blocklist_entry


def test_sha256_is_accepted_as_an_indicator():
    indicator_type, normalized = normalize_indicator(EICAR_SHA256.upper())
    assert indicator_type == "sha256"
    assert normalized == EICAR_SHA256


def test_risk_explanation_uses_full_intel_weight_without_screenshot():
    result = decision_from_scores(95, 0, visual_available=False)
    assert result["score"] == 95
    assert result["verdict"] == "CRITICAL"
    assert result["explanation"]["formula"] == "95.0 × 100% = 95.0"
    assert result["explanation"]["limitations"]


def test_approved_investigation_enters_and_leaves_blocklist():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        record = create_investigation(db, EICAR_SHA256)
        assert record.status == "awaiting_approval"
        assert record.evidence["risk_explanation"]["summary"]
        assert record.agent_trace[-1]["agent"] == "Orchestrator Agent"

        decided = decide_investigation(db, record, "approve", "Confirmed EICAR test signal")
        assert decided.status == "response_simulated"

        entry = db.scalar(select(BlocklistEntry))
        assert entry is not None
        assert entry.status == "active"
        assert entry.indicator == EICAR_SHA256

        removed = remove_blocklist_entry(db, entry)
        assert removed.status == "removed"
        actions = list(db.scalars(select(AuditEvent.action)).all())
        assert "decision.approve" in actions
        assert "blocklist.removed" in actions


def test_url_investigation_automatically_captures_screenshot(monkeypatch, tmp_path):
    image_data_url = "data:image/jpeg;base64,dGVzdC1pbWFnZS1ieXRlcw=="
    monkeypatch.setattr("app.services.capture_url_screenshot", lambda *_: (image_data_url, "Captured page"))
    monkeypatch.setattr(
        "app.services.investigation_graph.invoke",
        lambda state: {
            "risk_score": 10,
            "confidence": 0.8,
            "verdict": "LOW",
            "recommended_action": "ALLOW",
            "approval_required": False,
            "agent_trace": [{"agent": "Test", "status": "completed", "summary": "ok"}],
            "threat_intel": {"mode": "live", "score": 10, "sources": []},
            "visual_analysis": {"mode": "not_configured", "score": 0, "screenshot_available": True},
            "rag_context": [],
            "risk_explanation": {"summary": "test", "formula": "10", "factors": [], "threshold_reason": "test", "confidence_reason": "test", "limitations": []},
        },
    )
    monkeypatch.setattr("app.services.get_settings", lambda: __import__("app.config", fromlist=["Settings"]).Settings(evidence_directory=str(tmp_path)))
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        record = create_investigation(db, "https://example.com/login")
        assert record.evidence["page"]["screenshot_included"] is True
        assert record.evidence["page"]["screenshot_source"] == "automatic"
        assert record.evidence["page"]["title"] == "Captured page"
