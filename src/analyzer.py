"""
AI Severity Analyzer module.
Leverages Groq API (Meta Llama 3.1) to triage alerts into severity classifications.
"""

import json
from typing import Any, Dict
import requests
from src.config import GROQ_API_KEY, GROQ_API_URL, GROQ_MODEL


def analyze_with_groq(
    alert_data: Dict[str, Any],
    vt_data: Dict[str, Any],
    api_key: str = None
) -> Dict[str, str]:
    """
    Send enriched alert information to Groq AI for severity and impact analysis.

    Args:
        alert_data: Alert metadata containing alertId, dstDomain, timestamp, etc.
        vt_data: Threat intelligence enrichment results from VirusTotal.
        api_key: Optional custom API key. Defaults to GROQ_API_KEY from config.

    Returns:
        Dict with keys: 'severity' ('Critical'|'High'|'Medium'|'Low'|'Unknown'), 'reason'
    """
    key = api_key or GROQ_API_KEY
    if not key or key.startswith("YOUR_"):
        # Heuristic fallback if no API key is provided
        malicious = vt_data.get("malicious", 0)
        suspicious = vt_data.get("suspicious", 0)
        if malicious >= 5:
            return {"severity": "Critical", "reason": f"High detection count ({malicious} engines marked malicious)"}
        elif malicious > 0:
            return {"severity": "High", "reason": f"Malicious flags detected ({malicious} detections)"}
        elif suspicious > 0:
            return {"severity": "Medium", "reason": f"Suspicious flags detected ({suspicious} detections)"}
        else:
            return {"severity": "Low", "reason": "No malicious or suspicious indicators detected"}

    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json"
    }

    if vt_data.get("vt_available"):
        vt_summary = (
            f"Reputation: {vt_data.get('reputation', 'UNKNOWN')}, "
            f"Malicious: {vt_data.get('malicious', 0)}, "
            f"Suspicious: {vt_data.get('suspicious', 0)}, "
            f"Harmless: {vt_data.get('harmless', 0)}"
        )
    else:
        vt_summary = f"Threat Intel Unavailable ({vt_data.get('error', 'N/A')})"

    prompt = f"""You are an elite Security Operations Center (SOC) Tier-1 Triage Analyst.
Analyze the following security event and classify its severity.

Alert Details:
- Alert ID: {alert_data.get('alertId', 'unknown')}
- Destination Domain: {alert_data.get('dstDomain', 'unknown')}
- Threat Intelligence (VirusTotal): {vt_summary}

Respond ONLY with valid JSON in this exact structure:
{{
  "severity": "Critical",
  "reason": "1-2 sentence concise technical justification."
}}

Severity Criteria:
- Critical: Confirmed malicious domain or active C2 / malware hosting.
- High: Suspicious indicators, known phish or multiple vendor detections.
- Medium: Anomalous domain, newly registered, or minor suspicious flags.
- Low: Known benign/popular domain, zero detections.
"""

    payload = {
        "model": GROQ_MODEL,
        "messages": [
            {"role": "system", "content": "You are a specialized cybersecurity alert triage assistant. Always output clean JSON."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }

    try:
        response = requests.post(GROQ_API_URL, headers=headers, json=payload, timeout=15)
        if response.status_code == 200:
            result = response.json()
            content = result["choices"][0]["message"]["content"]
            try:
                parsed = json.loads(content)
                severity = parsed.get("severity", "Unknown").capitalize()
                if severity not in ["Critical", "High", "Medium", "Low"]:
                    severity = "Medium"
                return {
                    "severity": severity,
                    "reason": parsed.get("reason", "No reason provided by analysis.")
                }
            except json.JSONDecodeError:
                return {
                    "severity": "Unknown",
                    "reason": f"Failed to parse LLM JSON: {content[:100]}"
                }
        else:
            return {
                "severity": "Error",
                "reason": f"Groq API error HTTP {response.status_code}: {response.text[:100]}"
            }
    except requests.exceptions.RequestException as e:
        return {
            "severity": "Error",
            "reason": f"Groq request exception: {str(e)}"
        }
