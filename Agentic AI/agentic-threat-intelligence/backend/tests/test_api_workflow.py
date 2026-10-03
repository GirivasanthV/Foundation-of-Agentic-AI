from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.agents.live_analysis import EICAR_SHA256
from app.database import Base, get_db
from app.main import app


def test_full_api_approval_blocklist_and_audit_workflow():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    def override_db():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_db] = override_db
    try:
        with TestClient(app) as client:
            status = client.get("/api/v1/system/status")
            assert status.status_code == 200
            assert status.json()["capabilities"]["multi_agent"] is True

            created = client.post("/api/v1/investigations", json={"indicator": EICAR_SHA256})
            assert created.status_code == 201
            investigation = created.json()
            assert investigation["status"] == "awaiting_approval"
            assert investigation["evidence"]["risk_explanation"]["factors"]

            decision = client.post(
                f"/api/v1/investigations/{investigation['id']}/decision",
                json={"decision": "approve", "comment": "API workflow test"},
            )
            assert decision.status_code == 200

            entries = client.get("/api/v1/blocklist").json()
            assert len(entries) == 1
            assert entries[0]["status"] == "active"

            removed = client.delete(f"/api/v1/blocklist/{entries[0]['id']}")
            assert removed.status_code == 200
            assert removed.json()["status"] == "removed"

            actions = [event["action"] for event in client.get("/api/v1/audit").json()]
            assert "investigation.created" in actions
            assert "decision.approve" in actions
            assert "blocklist.removed" in actions
    finally:
        app.dependency_overrides.clear()
