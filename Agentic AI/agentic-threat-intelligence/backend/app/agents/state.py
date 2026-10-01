from typing import Any, TypedDict


class InvestigationState(TypedDict, total=False):
    indicator: str
    indicator_type: str
    normalized_indicator: str
    page_title: str
    screenshot_data_url: str | None
    screenshot_path: str | None
    resolved_ips: list[str]
    threat_intel: dict[str, Any]
    visual_analysis: dict[str, Any]
    rag_context: list[dict[str, Any]]
    risk_score: float
    confidence: float
    verdict: str
    recommended_action: str
    approval_required: bool
    risk_explanation: dict[str, Any]
    agent_trace: list[dict[str, str]]


def append_trace(state: InvestigationState, agent: str, summary: str) -> list[dict[str, str]]:
    return [*state.get("agent_trace", []), {"agent": agent, "status": "completed", "summary": summary}]
