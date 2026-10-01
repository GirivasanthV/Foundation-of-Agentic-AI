from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class InvestigationCreate(BaseModel):
    indicator: str = Field(min_length=3, max_length=2048)
    title: str = Field(default="", max_length=500)
    screenshot_data_url: str | None = Field(default=None, max_length=6_000_000)
    auto_capture: bool = True


class ExtensionPageScan(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    title: str = Field(default="", max_length=500)
    screenshot_data_url: str | None = Field(default=None, max_length=6_000_000)


class ExtensionHashScan(BaseModel):
    sha256: str = Field(pattern=r"^[A-Fa-f0-9]{64}$")
    filename: str = Field(default="unknown", max_length=260)
    size_bytes: int = Field(default=0, ge=0)


class AgentStep(BaseModel):
    agent: str
    status: str
    summary: str


class InvestigationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    indicator: str
    indicator_type: str
    normalized_indicator: str
    status: str
    verdict: str
    risk_score: float
    confidence: float
    recommended_action: str
    analyst_decision: str | None
    evidence: dict
    agent_trace: list
    created_at: datetime
    updated_at: datetime


class AnalystDecision(BaseModel):
    decision: Literal["approve", "reject", "override_monitor"]
    comment: str = Field(default="", max_length=1000)


class AuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    investigation_id: str
    actor: str
    action: str
    details: dict
    created_at: datetime


class BlocklistRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    indicator: str
    indicator_type: str
    source_investigation_id: str
    reason: str
    status: str
    enforcement_mode: str
    created_by: str
    created_at: datetime
    updated_at: datetime


class SystemStatusRead(BaseModel):
    mode: str
    response_mode: str
    providers: dict[str, bool]
    capabilities: dict[str, bool]
    warnings: list[str] = Field(default_factory=list)
