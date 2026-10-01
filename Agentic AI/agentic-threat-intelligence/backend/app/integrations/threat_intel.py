import base64
from urllib.parse import urlparse

import httpx


class ThreatIntelClients:
    def __init__(self, virustotal_key: str | None, abuseipdb_key: str | None, urlscan_key: str | None):
        self.virustotal_key = virustotal_key
        self.abuseipdb_key = abuseipdb_key
        self.urlscan_key = urlscan_key

    def virustotal_url(self, url: str) -> dict:
        if not self.virustotal_key:
            return {"status": "not_configured"}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        with httpx.Client(timeout=15) as client:
            response = client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": self.virustotal_key},
            )
            response.raise_for_status()
            stats = response.json()["data"]["attributes"].get("last_analysis_stats", {})
            return {"status": "ok", "stats": stats}

    def virustotal_ip(self, ip: str) -> dict:
        if not self.virustotal_key:
            return {"status": "not_configured"}
        with httpx.Client(timeout=15) as client:
            response = client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": self.virustotal_key},
            )
            if response.status_code == 404:
                return {"status": "not_found"}
            response.raise_for_status()
            stats = response.json()["data"]["attributes"].get("last_analysis_stats", {})
            return {"status": "ok", "stats": stats}

    def virustotal_hash(self, sha256: str) -> dict:
        if not self.virustotal_key:
            return {"status": "not_configured"}
        with httpx.Client(timeout=15) as client:
            response = client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": self.virustotal_key},
            )
            if response.status_code == 404:
                return {"status": "not_found", "stats": {}}
            response.raise_for_status()
            attributes = response.json()["data"]["attributes"]
            return {
                "status": "ok",
                "stats": attributes.get("last_analysis_stats", {}),
                "type_description": attributes.get("type_description"),
                "meaningful_name": attributes.get("meaningful_name"),
            }

    def abuseipdb(self, ip: str) -> dict:
        if not self.abuseipdb_key:
            return {"status": "not_configured"}
        with httpx.Client(timeout=15) as client:
            response = client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90},
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
            )
            response.raise_for_status()
            data = response.json()["data"]
            return {
                "status": "ok",
                "abuse_confidence": data.get("abuseConfidenceScore", 0),
                "reports": data.get("totalReports", 0),
            }

    def urlscan_lookup(self, url: str) -> dict:
        host = urlparse(url).hostname
        if not host:
            return {"status": "invalid_host"}
        headers = {"API-Key": self.urlscan_key} if self.urlscan_key else {}
        with httpx.Client(timeout=15) as client:
            response = client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{host}", "size": 10},
                headers=headers,
            )
            response.raise_for_status()
            results = response.json().get("results", [])
            malicious = sum(1 for result in results if result.get("verdicts", {}).get("overall", {}).get("malicious"))
            return {"status": "ok", "results": len(results), "malicious_results": malicious}


def safely(callable_):
    try:
        return callable_()
    except httpx.HTTPStatusError as exc:
        return {"status": "error", "http_status": exc.response.status_code}
    except (httpx.HTTPError, KeyError, TypeError, ValueError) as exc:
        return {"status": "error", "message": str(exc)[:200]}
