#!/usr/bin/env python3
"""
SentinelFlow — AI-Powered Security Alert Triage & Automation
Main CLI orchestrator and entry point.
"""

import argparse
from datetime import datetime
import json
import os
import sys
import time
from typing import Any, Dict, List

from src.analyzer import analyze_with_groq
from src.config import validate_config
from src.enrichment import enrich_with_virustotal
from src.notifier import send_to_discord

BANNER = r"""
  ____             _   _            _ _____ _                 
 / ___|  ___ _ __ | |_(_)_ __   ___| |  ___| | _____      __
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ | |_  | |/ _ \ \ /\ / /
  ___) |  __/ | | | |_| | | | |  __/ |  _| | | (_) \ V  V / 
 |____/ \___|_| |_|\__|_|_| |_|\___|_|_|   |_|\___/ \_/\_/  
         AI-Powered SOC Alert Reduction & Triage Engine
"""

DEMO_ALERTS = [
    {"alertId": "SEC-ALERT-001", "dstDomain": "google.com"},
    {"alertId": "SEC-ALERT-002", "dstDomain": "testphp.vulnweb.com"},
    {"alertId": "SEC-ALERT-003", "dstDomain": "malware-traffic-analysis.net"},
]


def process_alert(alert: Dict[str, Any], quiet: bool = False) -> Dict[str, Any]:
    """
    Run end-to-end triage pipeline for a single alert.
    """
    domain = alert.get("dstDomain", "unknown")
    alert_id = alert.get("alertId", "ALERT-X")
    timestamp = datetime.utcnow().isoformat() + "Z"

    if not quiet:
        print(f"\n[+] Processing Alert {alert_id} | Domain: {domain}")

    # Stage 1: Threat Intel Enrichment
    start_time = time.time()
    vt_result = enrich_with_virustotal(domain)
    if not quiet:
        if vt_result.get("vt_available"):
            print(f"    └── [VT] Malicious: {vt_result['malicious']}, Suspicious: {vt_result['suspicious']}")
        else:
            print(f"    └── [VT] Info: {vt_result.get('error', 'Skipped')}")

    # Stage 2: AI Severity Analysis
    ai_result = analyze_with_groq(alert, vt_result)
    severity = ai_result.get("severity", "Unknown")
    reason = ai_result.get("reason", "N/A")
    if not quiet:
        print(f"    └── [AI] Severity: {severity} | Justification: {reason}")

    # Stage 3: Notification
    discord_sent = send_to_discord(alert, vt_result, ai_result)
    if not quiet and discord_sent:
        print(f"    └── [Discord] Notification dispatched successfully.")

    elapsed = round(time.time() - start_time, 2)

    return {
        "alert": alert,
        "timestamp": timestamp,
        "vt_data": vt_result,
        "ai_analysis": ai_result,
        "discord_sent": discord_sent,
        "latency_seconds": elapsed,
    }


def run_pipeline(alerts: List[Dict[str, Any]], output_file: str = None) -> List[Dict[str, Any]]:
    """Execute pipeline for multiple alerts and print a summary table."""
    print("=" * 68)
    print(" SentinelFlow Pipeline Execution")
    print("=" * 68)

    results = []
    for alert in alerts:
        res = process_alert(alert)
        results.append(res)
        time.sleep(0.5)

    print("\n" + "=" * 68)
    print(" TRIAGE SUMMARY TABLE")
    print("=" * 68)
    print(f"{'Alert ID':<16} | {'Domain':<26} | {'Severity':<10} | {'Latency'}")
    print("-" * 68)
    for r in results:
        aid = r["alert"]["alertId"]
        dom = r["alert"]["dstDomain"]
        sev = r["ai_analysis"].get("severity", "Unknown")
        lat = f"{r['latency_seconds']}s"
        print(f"{aid:<16} | {dom:<26} | {sev:<10} | {lat}")
    print("=" * 68)

    if output_file:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            print(f"\n[+] Results successfully exported to: {output_file}")
        except IOError as e:
            print(f"\n[!] Failed to export results: {e}", file=sys.stderr)

    return results


def main():
    parser = argparse.ArgumentParser(
        description="SentinelFlow — AI-Powered Security Alert Triage Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=BANNER,
    )
    parser.add_argument(
        "-d", "--domain",
        type=str,
        help="Analyze a single domain directly (e.g. -d evil.example.com)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run default simulated alert scenario",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="sentinelflow_results.json",
        help="Path to export JSON results (default: sentinelflow_results.json)",
    )
    parser.add_argument(
        "--check-config",
        action="store_true",
        help="Check status of configured credentials",
    )

    args = parser.parse_args()

    print(BANNER)

    if args.check_config:
        cfg = validate_config()
        print("[*] Configuration Status:")
        print(f"    - VirusTotal API : {'Configured' if cfg['virustotal'] else 'Missing/Default'}")
        print(f"    - Groq AI API    : {'Configured' if cfg['groq'] else 'Missing/Default'}")
        print(f"    - Discord Webhook: {'Configured' if cfg['discord'] else 'Missing/Default'}")
        return

    if args.domain:
        alert = {
            "alertId": f"MANUAL-{int(time.time())}",
            "dstDomain": args.domain,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }
        run_pipeline([alert], output_file=args.output)
    else:
        # Default run or explicit --demo
        print("[*] Running simulated alert batch...")
        run_pipeline(DEMO_ALERTS, output_file=args.output)


if __name__ == "__main__":
    main()
