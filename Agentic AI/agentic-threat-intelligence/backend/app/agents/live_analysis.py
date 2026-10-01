import base64
import json
import re
from pathlib import Path
from urllib.parse import urlparse

from app.agents.nodes import SUSPICIOUS_TERMS
from app.azure.clients import vlm_client
from app.config import Settings
from app.integrations.threat_intel import ThreatIntelClients, safely


EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def _vt_score(data: dict) -> float:
    stats = data.get("stats", {})
    return min(100.0, (float(stats.get("malicious", 0)) * 14) + (float(stats.get("suspicious", 0)) * 6))


def _url_structure_score(url: str) -> tuple[float, list[str]]:
    parsed = urlparse(url)
    lowered = url.lower()
    matches = [term for term in SUSPICIOUS_TERMS if term in lowered]
    reasons = [f"keyword:{term}" for term in matches]
    score = float(sum(SUSPICIOUS_TERMS[term] for term in matches))
    host = parsed.hostname or ""
    if host.startswith("xn--") or ".xn--" in host:
        score += 22
        reasons.append("punycode hostname")
    if "@" in parsed.netloc:
        score += 25
        reasons.append("embedded user information")
    if host.count("-") >= 3:
        score += 10
        reasons.append("many hostname hyphens")
    if len(host.split(".")) > 4:
        score += 8
        reasons.append("deep subdomain chain")
    if parsed.scheme == "http":
        score += 6
        reasons.append("unencrypted HTTP")
    return min(70.0, score), reasons


def collect_url_intelligence(url: str, resolved_ips: list[str], settings: Settings) -> dict:
    clients = ThreatIntelClients(settings.virustotal_api_key, settings.abuseipdb_api_key, settings.urlscan_api_key)
    vt = safely(lambda: clients.virustotal_url(url))
    urlscan = safely(lambda: clients.urlscan_lookup(url))
    abuse_results = [safely(lambda ip=ip: clients.abuseipdb(ip)) for ip in resolved_ips]
    local_score, local_reasons = _url_structure_score(url)
    scores = [local_score, _vt_score(vt)]
    scores.extend(float(item.get("abuse_confidence", 0)) for item in abuse_results)
    if urlscan.get("malicious_results", 0):
        scores.append(min(100.0, 50 + (urlscan["malicious_results"] * 10)))
    return {
        "mode": "live",
        "score": max(scores, default=0),
        "resolved_ips": resolved_ips,
        "matched_indicators": local_reasons,
        "sources": [
            {"name": "Local URL Heuristics", "status": "ok", "score": local_score, "message": ", ".join(local_reasons) if local_reasons else "No suspicious URL-structure signals detected."},
            {"name": "VirusTotal", **vt, "score": _vt_score(vt)},
            {"name": "AbuseIPDB", "status": "ok" if abuse_results else "no_ip", "results": abuse_results, "score": max((float(x.get("abuse_confidence", 0)) for x in abuse_results), default=0)},
            {"name": "URLScan", **urlscan, "score": min(100, 50 + (urlscan.get("malicious_results", 0) * 10)) if urlscan.get("malicious_results") else 0},
        ],
    }


def collect_ip_intelligence(ip: str, settings: Settings) -> dict:
    clients = ThreatIntelClients(settings.virustotal_api_key, settings.abuseipdb_api_key, settings.urlscan_api_key)
    vt = safely(lambda: clients.virustotal_ip(ip))
    abuse = safely(lambda: clients.abuseipdb(ip))
    score = max(_vt_score(vt), float(abuse.get("abuse_confidence", 0)))
    return {"mode": "live", "score": score, "resolved_ips": [ip], "sources": [{"name": "VirusTotal", **vt, "score": _vt_score(vt)}, {"name": "AbuseIPDB", **abuse, "score": float(abuse.get("abuse_confidence", 0))}]}


def collect_hash_intelligence(sha256: str, settings: Settings) -> dict:
    clients = ThreatIntelClients(settings.virustotal_api_key, settings.abuseipdb_api_key, settings.urlscan_api_key)
    vt = safely(lambda: clients.virustotal_hash(sha256))
    known_eicar = sha256.lower() == EICAR_SHA256
    signature_score = 95.0 if known_eicar else 0.0
    return {
        "mode": "live",
        "score": max(signature_score, _vt_score(vt)),
        "sources": [
            {"name": "Local Signature Database", "status": "ok", "known_eicar_test_hash": known_eicar, "score": signature_score},
            {"name": "VirusTotal", **vt, "score": _vt_score(vt)},
        ],
    }


def decode_and_store_screenshot(data_url: str | None, investigation_id: str, settings: Settings) -> tuple[bytes | None, str | None]:
    if not data_url:
        return None, None
    match = re.fullmatch(r"data:image/(jpeg|png);base64,([A-Za-z0-9+/=\r\n]+)", data_url)
    if not match:
        raise ValueError("Screenshot must be a JPEG or PNG data URL")
    raw = base64.b64decode(match.group(2), validate=True)
    if len(raw) > settings.screenshot_max_bytes:
        raise ValueError("Screenshot exceeds the configured size limit")
    extension = "jpg" if match.group(1) == "jpeg" else "png"
    directory = Path(settings.evidence_directory)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{investigation_id}.{extension}"
    path.write_bytes(raw)
    return raw, str(path)


def analyse_screenshot(data_url: str | None, page_url: str, title: str, settings: Settings) -> dict:
    if not data_url:
        return {"mode": "not_captured", "score": 0, "suspicious_elements": [], "summary": "Screenshot capture disabled."}
    client = vlm_client(settings)
    prompt = (
        "You are a phishing screenshot analyst. Inspect only the supplied screenshot and URL metadata. "
        "Return JSON with keys score (0-100), login_form_present (boolean), brands_detected (array), "
        "suspicious_elements (array), and summary (one short sentence). Do not declare a URL safe solely from appearance. "
        f"Page URL: {page_url}\nPage title: {title}"
    )
    try:
        response = client.chat.completions.create(
            model=settings.vlm_model,
            response_format={"type": "json_object"},
            temperature=0,
            messages=[{"role": "user", "content": [{"type": "text", "text": prompt}, {"type": "image_url", "image_url": {"url": data_url}}]}],
        )
    except Exception as exc:
        return {
            "mode": "provider_error",
            "score": 0,
            "screenshot_available": True,
            "brands_detected": [],
            "suspicious_elements": [],
            "summary": f"Screenshot captured, but local VLM analysis was unavailable: {str(exc)[:240]}",
        }
    content = response.choices[0].message.content or "{}"
    content = content.strip()
    if content.startswith("```"):
        content = content.split("\n", 1)[1].rsplit("```", 1)[0].strip()
    result = json.loads(content)
    result["mode"] = "docker_ministral"
    result["screenshot_available"] = True
    result["score"] = max(0, min(100, float(result.get("score", 0))))
    return result


def decision_from_scores(
    intel_score: float,
    visual_score: float,
    evidence_available: bool = True,
    visual_available: bool = True,
) -> dict:
    intel_weight, visual_weight = (0.65, 0.35) if visual_available else (1.0, 0.0)
    score = round((intel_score * intel_weight) + (visual_score * visual_weight), 1)
    confidence = round(min(0.97, 0.45 + (abs(score - 50) / 100) + (0.08 if evidence_available else 0)), 2)
    if score >= 70:
        verdict, action = "CRITICAL", "BLOCK"
    elif score >= 50:
        verdict, action = "HIGH", "BLOCK"
    elif score >= 25:
        verdict, action = "MEDIUM", "MONITOR"
    else:
        verdict, action = "LOW", "ALLOW"
    factors = [
        {
            "label": "Threat intelligence",
            "score": round(intel_score, 1),
            "weight": intel_weight,
            "contribution": round(intel_score * intel_weight, 1),
            "reason": "Reputation signals from applicable external providers and indicator heuristics.",
        }
    ]
    if visual_available:
        factors.append(
            {
                "label": "Visual phishing analysis",
                "score": round(visual_score, 1),
                "weight": visual_weight,
                "contribution": round(visual_score * visual_weight, 1),
                "reason": "Screenshot evidence for login forms, brand impersonation, and suspicious page elements.",
            }
        )
    threshold_reason = {
        "CRITICAL": "The combined score is 70 or higher, so blocking is recommended after analyst approval.",
        "HIGH": "The combined score is between 50 and 69.9, so blocking is recommended after analyst approval.",
        "MEDIUM": "The combined score is between 25 and 49.9, so monitoring is recommended.",
        "LOW": "The combined score is below 25, so no immediate blocking action is recommended.",
    }[verdict]
    explanation = {
        "summary": f"{verdict} risk because the final score is {score}/100. {threshold_reason}",
        "formula": f"({intel_score:.1f} × {intel_weight:.0%}) + ({visual_score:.1f} × {visual_weight:.0%}) = {score:.1f}" if visual_available else f"{intel_score:.1f} × 100% = {score:.1f}",
        "factors": factors,
        "threshold_reason": threshold_reason,
        "confidence_reason": "Confidence reflects distance from the decision boundary and whether usable provider evidence was returned.",
        "limitations": [] if visual_available else ["No screenshot evidence was available, so the score relies entirely on threat intelligence."],
    }
    return {
        "score": score,
        "confidence": confidence,
        "verdict": verdict,
        "action": action,
        "approval_required": action == "BLOCK" or confidence < 0.65,
        "explanation": explanation,
    }
