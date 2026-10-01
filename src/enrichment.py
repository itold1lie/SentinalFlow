"""
Threat Intelligence Enrichment module.
Queries VirusTotal API v3 for domain reputation and scan results.
"""

from typing import Any, Dict
import requests
from src.config import VT_API_KEY, VT_API_BASE_URL


def enrich_with_virustotal(domain: str, api_key: str = None) -> Dict[str, Any]:
    """
    Query VirusTotal API v3 for domain reputation.

    Args:
        domain: Domain name to investigate (e.g., 'google.com', 'malicious.xyz')
        api_key: Optional custom API key. Defaults to VT_API_KEY from config.

    Returns:
        Dict with keys: vt_available, malicious, suspicious, harmless, total_scans, reputation
    """
    key = api_key or VT_API_KEY
    if not key or key.startswith("YOUR_"):
        return {
            "vt_available": False,
            "error": "VirusTotal API key not configured.",
            "reputation": "UNKNOWN",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "total_scans": 0,
        }

    url = f"{VT_API_BASE_URL}/domains/{domain}"
    headers = {
        "x-apikey": key,
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            reputation = "SUSPICIOUS" if (malicious > 0 or suspicious > 0) else "CLEAN"

            return {
                "vt_available": True,
                "domain": domain,
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "total_scans": total,
                "reputation": reputation,
            }
        elif response.status_code == 404:
            return {
                "vt_available": False,
                "error": "Domain not found in VirusTotal database",
                "reputation": "UNKNOWN",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "total_scans": 0,
            }
        else:
            return {
                "vt_available": False,
                "error": f"VirusTotal API HTTP {response.status_code}",
                "reputation": "UNKNOWN",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "total_scans": 0,
            }
    except requests.exceptions.RequestException as e:
        return {
            "vt_available": False,
            "error": f"Request exception: {str(e)}",
            "reputation": "UNKNOWN",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "total_scans": 0,
        }
