import json
import re

from app.agents.state import InvestigationState, append_trace
from app.config import get_settings
from app.security import resolve_public_ips


SUSPICIOUS_TERMS = {
    "verify": 10,
    "secure": 7,
    "login": 8,
    "account": 5,
    "update": 5,
    "wallet": 12,
    "bonus": 8,
    "free": 6,
    "password": 12,
}


KNOWLEDGE = [
    {
        "id": "MITRE-T1566",
        "title": "MITRE ATT&CK T1566 — Phishing",
        "text": "Adversaries use deceptive messages, links, cloned sign-in pages, and malicious attachments to steal credentials or deliver payloads.",
        "keywords": ["phishing", "login", "credential", "brand", "link", "password"],
        "url": "https://attack.mitre.org/techniques/T1566/",
    },
    {
        "id": "OWASP-SSRF",
        "title": "OWASP SSRF Prevention",
        "text": "Applications that process user-supplied URLs must validate destinations and prevent access to private, loopback, and link-local networks.",
        "keywords": ["url", "private", "network", "validation", "ssrf", "redirect"],
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
    },
    {
        "id": "NIST-IR",
        "title": "NIST Incident Response Guidance",
        "text": "Incident response requires documented detection, analysis, containment, eradication, recovery, and evidence-preserving decisions.",
        "keywords": ["incident", "containment", "block", "response", "evidence", "analyst"],
        "url": "https://csrc.nist.gov/pubs/sp/800/61/r3/final",
    },
    {
        "id": "MITRE-T1583.001",
        "title": "MITRE ATT&CK — Domains",
        "text": "Adversaries acquire domains that resemble trusted brands and use them for phishing, command and control, or payload delivery.",
        "keywords": ["domain", "impersonation", "brand", "typosquat", "phishing"],
        "url": "https://attack.mitre.org/techniques/T1583/001/",
    },
    {
        "id": "CISA-PHISHING",
        "title": "CISA Phishing Guidance",
        "text": "Unexpected requests for credentials, urgency, mismatched domains, and suspicious links are common indicators of phishing.",
        "keywords": ["urgent", "credential", "login", "domain", "suspicious", "phishing"],
        "url": "https://www.cisa.gov/secure-our-world/recognize-and-report-phishing",
    },
]


def _evidence_text(values: list) -> str:
    return " ".join(
        value if isinstance(value, str) else json.dumps(value, sort_keys=True)
        for value in values
        if value is not None
    )


def validation_node(state: InvestigationState) -> dict:
    kind = state["indicator_type"]
    resolved_ips: list[str] = []
    if kind == "url":
        resolved_ips = resolve_public_ips(state["normalized_indicator"])
    elif kind == "ip":
        resolved_ips = [state["normalized_indicator"]]
    return {
        "resolved_ips": resolved_ips,
        "agent_trace": append_trace(
            state,
            "Input Validation Agent",
            f"Validated a public {kind.upper()} indicator and applied SSRF-safe destination checks.",
        ),
    }


def threat_intel_node(state: InvestigationState) -> dict:
    # Local imports avoid a module cycle because the live adapters reuse URL term weights.
    from app.agents.live_analysis import collect_hash_intelligence, collect_ip_intelligence, collect_url_intelligence

    settings = get_settings()
    kind = state["indicator_type"]
    value = state["normalized_indicator"]
    if kind == "url":
        data = collect_url_intelligence(value, state.get("resolved_ips", []), settings)
    elif kind == "ip":
        data = collect_ip_intelligence(value, settings)
    else:
        data = collect_hash_intelligence(value, settings)
    usable = sum(1 for source in data.get("sources", []) if source.get("status") in {"ok", "not_found"})
    return {
        "threat_intel": data,
        "agent_trace": append_trace(
            state,
            "Threat Intelligence Agent",
            f"Queried {len(data.get('sources', []))} applicable source(s); {usable} returned usable evidence. Intelligence score: {float(data.get('score', 0)):.1f}/100.",
        ),
    }


def vlm_node(state: InvestigationState) -> dict:
    from app.agents.live_analysis import analyse_screenshot

    if state["indicator_type"] != "url":
        visual = {
            "mode": "not_applicable",
            "score": 0,
            "suspicious_elements": [],
            "summary": "Visual analysis is not applicable to IP or hash-only investigations.",
        }
    else:
        visual = analyse_screenshot(
            state.get("screenshot_data_url"),
            state["normalized_indicator"],
            state.get("page_title", ""),
            get_settings(),
        )
    return {
        "visual_analysis": visual,
        "agent_trace": append_trace(
            state,
            "VLM Agent",
            f"{visual.get('summary', 'Visual analysis completed.')} Visual score: {float(visual.get('score', 0)):.1f}/100.",
        ),
    }


def rag_node(state: InvestigationState) -> dict:
    intel = state.get("threat_intel", {})
    visual = state.get("visual_analysis", {})
    evidence_text = " ".join(
        [
            state["normalized_indicator"],
            state.get("page_title", ""),
            _evidence_text(intel.get("matched_indicators", [])),
            _evidence_text(visual.get("suspicious_elements", [])),
            _evidence_text(visual.get("brands_detected", visual.get("brand_tokens", []))),
        ]
    ).lower()
    settings = get_settings()
    if settings.azure_search_endpoint and settings.azure_search_api_key:
        try:
            from app.azure.clients import azure_search_client

            results = azure_search_client(settings).search(search_text=evidence_text, top=3)
            context = []
            for index, result in enumerate(results):
                item = dict(result)
                context.append(
                    {
                        "id": str(item.get("id") or item.get("key") or f"AZURE-{index + 1}"),
                        "title": str(item.get("title") or item.get("name") or "Cybersecurity knowledge result"),
                        "text": str(item.get("text") or item.get("content") or item.get("description") or "Relevant indexed security guidance."),
                        "url": str(item.get("url") or "https://learn.microsoft.com/azure/search/"),
                        "relevance_score": round(float(item.get("@search.score", 0)), 3),
                        "why_relevant": "Retrieved from the configured Azure AI Search cybersecurity index.",
                    }
                )
            if context:
                return {
                    "rag_context": context,
                    "agent_trace": append_trace(state, "RAG Agent", f"Retrieved {len(context)} live references from Azure AI Search."),
                }
        except Exception:
            # Continue with the curated local index so an optional search outage does not stop an investigation.
            pass

    query_terms = set(re.findall(r"[a-z0-9]+", evidence_text))
    ranked = []
    for item in KNOWLEDGE:
        searchable = set(re.findall(r"[a-z0-9]+", f"{item['title']} {item['text']} {' '.join(item['keywords'])}".lower()))
        matches = sorted(query_terms.intersection(searchable))
        score = len(matches) + sum(2 for keyword in item["keywords"] if keyword in evidence_text)
        ranked.append((score, matches, item))
    ranked.sort(key=lambda value: value[0], reverse=True)
    context = []
    for score, matches, item in ranked[:3]:
        context.append(
            {
                "id": item["id"],
                "title": item["title"],
                "text": item["text"],
                "url": item["url"],
                "relevance_score": score,
                "why_relevant": f"Matched investigation concepts: {', '.join(matches[:5])}." if matches else "Provides baseline incident-analysis guidance.",
            }
        )
    return {
        "rag_context": context,
        "agent_trace": append_trace(
            state,
            "RAG Agent",
            f"Retrieved {len(context)} curated references and recorded why each source is relevant.",
        ),
    }


def risk_node(state: InvestigationState) -> dict:
    from app.agents.live_analysis import decision_from_scores

    intel = state.get("threat_intel", {})
    visual = state.get("visual_analysis", {})
    visual_available = bool(visual.get("screenshot_available")) and visual.get("mode") not in {
        "not_captured",
        "not_configured",
        "provider_error",
        "not_applicable",
    }
    source_statuses = [source.get("status") for source in intel.get("sources", [])]
    evidence_available = any(status in {"ok", "not_found"} for status in source_statuses)
    result = decision_from_scores(
        float(intel.get("score", 0)),
        float(visual.get("score", 0)),
        evidence_available=evidence_available,
        visual_available=visual_available,
    )
    explanation = result["explanation"]
    intel_reasons = []
    for source in intel.get("sources", []):
        name = source.get("name", "Provider")
        status = source.get("status", "unknown")
        score = float(source.get("score", 0))
        stats = source.get("stats", {})
        if stats:
            intel_reasons.append(
                f"{name} reported {stats.get('malicious', 0)} malicious and {stats.get('suspicious', 0)} suspicious engine verdicts"
            )
        elif source.get("malicious_results"):
            intel_reasons.append(f"{name} found {source['malicious_results']} malicious historical scan result(s)")
        elif status == "ok":
            intel_reasons.append(f"{name} returned an intelligence score of {score:.1f}/100")
    if intel.get("matched_indicators"):
        intel_reasons.append(f"Suspicious terms matched: {', '.join(intel['matched_indicators'])}")
    if explanation.get("factors"):
        explanation["factors"][0]["reason"] = ". ".join(intel_reasons) + "." if intel_reasons else "No provider reported a positive reputation signal."
    if visual_available and len(explanation.get("factors", [])) > 1:
        visual_details = visual.get("suspicious_elements", [])
        explanation["factors"][1]["reason"] = visual.get("summary", "Screenshot analysis completed.")
        if visual_details:
            explanation["factors"][1]["reason"] += f" Detected: {_evidence_text(visual_details)}."
    unavailable = [
        source.get("name", "Unknown")
        for source in intel.get("sources", [])
        if source.get("status") in {"not_configured", "error"}
    ]
    if unavailable:
        explanation["limitations"].append(f"No usable result was available from: {', '.join(unavailable)}.")
    if visual.get("mode") in {"not_configured", "provider_error"} and visual.get("screenshot_available"):
        explanation["limitations"].append("A screenshot was captured, but the configured local VLM was unavailable, so it was not included in the score.")
    explanation["supporting_references"] = [item["id"] for item in state.get("rag_context", [])]
    explanation["provider_statuses"] = [
        {"name": source.get("name", "Unknown"), "status": source.get("status", "unknown"), "score": source.get("score", 0)}
        for source in intel.get("sources", [])
    ]
    return {
        "risk_score": result["score"],
        "confidence": result["confidence"],
        "verdict": result["verdict"],
        "recommended_action": result["action"],
        "approval_required": result["approval_required"],
        "risk_explanation": explanation,
        "agent_trace": append_trace(
            state,
            "Orchestrator Agent",
            f"Combined threat intelligence and visual evidence using {explanation['formula']}; assigned {result['verdict']} risk and recommended {result['action']}.",
        ),
    }
