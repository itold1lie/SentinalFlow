"""
Notification delivery module.
Sends formatted, color-coded security alerts to Discord channels via webhooks.
"""

from datetime import datetime
from typing import Any, Dict
import requests
from src.config import DISCORD_WEBHOOK_URL


SEVERITY_COLORS = {
    "Critical": 0xDC2626,  # Vivid Red
    "High": 0xEA580C,      # Vivid Orange
    "Medium": 0xEAB308,    # Vibrant Yellow
    "Low": 0x16A34A,       # Emerald Green
    "Error": 0x64748B,     # Slate Gray
    "Unknown": 0x6B7280,   # Cool Gray
}

SEVERITY_BADGES = {
    "Critical": "CRITICAL",
    "High": "HIGH",
    "Medium": "MEDIUM",
    "Low": "LOW",
    "Error": "ERROR",
    "Unknown": "UNKNOWN",
}


def send_to_discord(
    alert_data: Dict[str, Any],
    vt_data: Dict[str, Any],
    ai_analysis: Dict[str, str],
    webhook_url: str = None
) -> bool:
    """
    Send formatted Discord embed notification for a triaged alert.

    Args:
        alert_data: Alert metadata dict
        vt_data: Threat intelligence enrichment results
        ai_analysis: AI classification analysis
        webhook_url: Optional custom webhook URL. Defaults to DISCORD_WEBHOOK_URL.

    Returns:
        bool: True if delivered successfully, False otherwise.
    """
    url = webhook_url or DISCORD_WEBHOOK_URL
    if not url or url.startswith("YOUR_"):
        # Skipped silently when unconfigured
        return False

    severity = ai_analysis.get("severity", "Unknown")
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["Unknown"])
    badge = SEVERITY_BADGES.get(severity, severity)

    if vt_data.get("vt_available"):
        vt_text = (
            f"**Malicious:** {vt_data.get('malicious', 0)} | "
            f"**Suspicious:** {vt_data.get('suspicious', 0)} | "
            f"**Reputation:** `{vt_data.get('reputation', 'UNKNOWN')}`"
        )
    else:
        vt_text = f"Unavailable ({vt_data.get('error', 'No data')})"

    payload = {
        "username": "SentinelFlow SOC",
        "avatar_url": "https://raw.githubusercontent.com/itold1lie/SentinalFlow/main/assets/shield.png",
        "embeds": [
            {
                "title": f"{badge} — Security Triage Decision",
                "color": color,
                "fields": [
                    {
                        "name": "Alert ID",
                        "value": f"`{alert_data.get('alertId', 'N/A')}`",
                        "inline": True
                    },
                    {
                        "name": "Domain Under Test",
                        "value": f"`{alert_data.get('dstDomain', 'N/A')}`",
                        "inline": True
                    },
                    {
                        "name": "Assigned Severity",
                        "value": f"**{severity}**",
                        "inline": True
                    },
                    {
                        "name": "Threat Intelligence (VirusTotal)",
                        "value": vt_text,
                        "inline": False
                    },
                    {
                        "name": "AI Triage Rationale (Groq Llama 3.1)",
                        "value": ai_analysis.get("reason", "No justification provided."),
                        "inline": False
                    }
                ],
                "footer": {
                    "text": "SentinelFlow • Automated Alert Reduction Engine"
                },
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }
        ]
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        return response.status_code in [200, 204]
    except requests.exceptions.RequestException:
        return False
