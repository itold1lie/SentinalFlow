<div align="center">

#  SentinelFlow

### Autonomous AI-Powered Security Operations & Incident Response (SOAR) Pipeline

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![n8n SOAR](https://img.shields.io/badge/n8n-SOAR%20Workflow-EA4B71?style=for-the-badge&logo=n8n&logoColor=white)](https://n8n.io/)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API%20v3-394EFF?style=for-the-badge&logo=virustotal&logoColor=white)](https://www.virustotal.com/)
[![AbuseIPDB](https://img.shields.io/badge/AbuseIPDB-Threat%20Intel-FF6C37?style=for-the-badge)](https://www.abuseipdb.com/)
[![Shodan](https://img.shields.io/badge/Shodan-Vulnerability%20Scans-D32F2F?style=for-the-badge&logo=shodan&logoColor=white)](https://www.shodan.io/)
[![Groq AI](https://img.shields.io/badge/Groq-Llama%203.1-F55036?style=for-the-badge&logo=meta&logoColor=white)](https://groq.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)

<br/>

**SentinelFlow cuts through alert fatigue by automating Tier-1 triage, multi-source threat intelligence fusion, AI reasoning, and high-severity containment — accelerating incident response from minutes to sub-10 seconds.**

<br/>

[Key Highlights](#-key-highlights) • [Architecture](#-architecture) • [Workflow Engines](#-two-ways-to-run) • [Getting Started](#-getting-started) • [Configuration](#-configuration) • [Research & Citation](#-research--academic-citation) • [License](#-license)

</div>

---

##  Key Highlights

- **Multi-Source Threat Fusion** — Real-time correlation with **VirusTotal API v3**, **AbuseIPDB**, and **Shodan** to establish a weighted **Composite Threat Score (0–100)**.
- **Guarded LLM Reasoning** — Utilizes **Groq Llama 3.1** / **Google Gemini** / **Claude** with strict JSON schema parsing for deterministic severity classification and playbook recommendations.
- **Automated Containment Actions** — Executes policy-driven incident containment: Firewall IP blocking, EDR host isolation, and active session/token revocation.
- **Full SOC Integration** — Instant notification dispatch to **Discord** and **Slack**, automated ticket creation in **Jira Software**, and audit logging in **Google Sheets**.
- **NIST & MITRE ATT&CK Aligned** — Normalizes alerts against standard taxonomy (Brute Force, C2, Malware, Exfiltration) following the **NIST SP 800-61r2** incident handling lifecycle.
- **Dual Engine Flexibility** — Deploy as a **visual low-code n8n workflow** or run as a **high-speed standalone Python CLI engine**.

---

## Architecture

```mermaid
flowchart TD
    subgraph Ingestion["1. Ingestion & Normalization"]
        A["Alert Source\n(SIEM / EDR / Firewall / Webhook)"] --> B["Normalize Alert\n(Taxonomy Mapping & Sanitization)"]
    end

    subgraph Enrichment["2. Threat Intelligence Fusion"]
        B --> C1["VirusTotal API v3\n(Reputation & Malicious Votes)"]
        B --> C2["AbuseIPDB\n(Abuse Confidence Score)"]
        B --> C3["Shodan API\n(Open Ports & CVEs)"]
        C1 & C2 & C3 --> D["Composite Threat Engine\n(Score: 0 - 100)"]
    end

    subgraph Reasoning["3. Cognitive AI Assessment"]
        D --> E["LLM Assessment (Llama 3.1 / Gemini)\n(Severity, MITRE Technique, Playbook)"]
        E --> F{"Severity Decision\nCritical / High / Med / Low"}
    end

    subgraph Containment["4. Automated Containment (High/Critical)"]
        F -- "Auto-Contain" --> G1["Firewall IP Block"]
        F -- "Auto-Contain" --> G2["EDR Host Isolation"]
        F -- "Auto-Contain" --> G3["Revoke User Sessions"]
    end

    subgraph Distribution["5. Collaboration & Audit Trail"]
        F --> H1["Discord / Slack\n(SOC Incident Embeds)"]
        F --> H2["Jira Software\n(Ticket Generation)"]
        F --> H3["Google Sheets / JSON\n(Audit Logging)"]
    end

    style A fill:#1e293b,stroke:#64748b,color:#e2e8f0
    style B fill:#1e293b,stroke:#3b82f6,color:#e2e8f0
    style C1 fill:#1a1a2e,stroke:#394EFF,color:#818cf8
    style C2 fill:#1a1a2e,stroke:#FF6C37,color:#fdba74
    style C3 fill:#1a1a2e,stroke:#D32F2F,color:#fca5a5
    style D fill:#1a1a2e,stroke:#a855f7,color:#d8b4fe
    style E fill:#1a1a2e,stroke:#F55036,color:#fb923c
    style F fill:#1e293b,stroke:#eab308,color:#fef08a
    style G1 fill:#450a0a,stroke:#ef4444,color:#fca5a5
    style G2 fill:#450a0a,stroke:#ef4444,color:#fca5a5
    style G3 fill:#450a0a,stroke:#ef4444,color:#fca5a5
    style H1 fill:#172554,stroke:#3b82f6,color:#93c5fd
    style H2 fill:#022c22,stroke:#10b981,color:#6ee7b7
    style H3 fill:#1e293b,stroke:#64748b,color:#cbd5e1
```

---

## Project Structure

```
SentinalFlow/
├── .env.example                               # Pre-configured environment template
├── .gitignore                                 # Git ignore filters
├── CODE_OF_CONDUCT.md                         # Community guidelines
├── CONTRIBUTING.md                            # Contribution instructions
├── LICENSE                                    # MIT License
├── README.md                                  # Project documentation
├── SECURITY.md                                # Vulnerability reporting policy
├── requirements.txt                           # Core dependencies
│
├── docs/
│   ├── architecture.md                        # Deep technical specification
│   └── presentation/
│       └── SentinelFlow_PoC_Presentation.pptx # Project defense slides & diagrams
│
├── src/                                       # Python micro-service engine
│   ├── __init__.py                            # Module exports
│   ├── config.py                              # Configuration & environment loader
│   ├── enrichment.py                          # VirusTotal API v3 integration
│   ├── analyzer.py                            # Groq Llama 3.1 analysis & JSON parser
│   ├── notifier.py                            # Discord webhook embed formatter
│   └── sentinel_flow.py                       # CLI orchestrator & pipeline runner
│
├── tests/
│   └── test_sentinel_flow.py                  # Unit and integration test suite
│
└── workflows/                                 # Ready-to-import n8n pipelines
    ├── n8n_incident_response_soar.json        # Full SOAR Pipeline (VT, AbuseIPDB, Jira, Slack, Containment)
    └── sentinel_flow.json                     # Lightweight Rapid-Triage Workflow
```

---

## Two Ways to Run

### Option 1: Full Enterprise SOAR Workflow (n8n)

The complete end-to-end orchestration pipeline is available under `workflows/`:

1. Launch your self-hosted **n8n** instance (`npx n8n` or via Docker).
2. Go to **Workflows → Import from File** and select:
   ```
   workflows/n8n_incident_response_soar.json
   ```
3. Set your environment variables in n8n or link your credentials:
   - `VIRUSTOTAL_API_KEY`
   - Slack, Jira, or Google Sheets credentials as needed.
4. Activate the **Receive Security Alert** Webhook node to begin accepting live security events.

---

### Option 2: Standalone Python Micro-Engine

For lightweight environments, scripts, or serverless functions:

#### 1. Clone & Set Up Environment

```bash
# Clone repository
git clone https://github.com/itold1lie/SentinalFlow.git
cd SentinalFlow

# Create virtual environment
python -m venv venv
source venv/bin/activate       # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### 2. Configure Credentials

```bash
# Create local .env from template
cp .env.example .env
```

Edit `.env` with your API keys:

```ini
VT_API_KEY=your_virustotal_api_key_here
GROQ_API_KEY=your_groq_api_key_here
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/your_webhook_url
```

#### 3. Execute the Engine

```bash
python -m src.sentinel_flow
```

---

## Sample Output

```
============================================================
 SENTINELFLOW — AUTONOMOUS SECURITY TRIAGE PIPELINE
============================================================

--- PROCESSING ALERT #1: google.com ---
 Alert Ingested: ID=ALERT-9281, Target=google.com
  ├─ VirusTotal: 0 malicious, 0 suspicious (Clean)
  ├─ AI Assessment: Severity=Low (Confidence: 98%)
  └─ Decision: Pass (No action needed)

--- PROCESSING ALERT #2: testphp.vulnweb.com ---
 Alert Ingested: ID=ALERT-9282, Target=testphp.vulnweb.com
  ├─ VirusTotal: 3 malicious engines detected
  ├─ AI Assessment: Severity=High
  ├─ MITRE Technique: T1190 (Exploit Public-Facing Application)
  ├─ Containment: Mock IP firewall block triggered
  └─ Dispatch: Discord embed & Jira incident ticket created

============================================================
 TRIAGE COMPLETE: 2 Alerts Processed in 2.34s
============================================================
```

---

## Threat Taxonomy & MITRE ATT&CK Mapping

SentinelFlow standardizes raw incoming events into recognized security categories:

| Alert Category | MITRE Technique | Recommended Playbook | Default Action |
|---|---|---|---|
| **BRUTE_FORCE** | `T1110` (Brute Force) | Identity Lockout Playbook | Revoke Sessions & Flag User |
| **MALWARE_DETECTED** | `T1204` (User Execution) | Endpoint Isolation Playbook | Quarantine Host via EDR |
| **C2_COMMUNICATION** | `T1071` (App Layer Protocol) | Network Egress Filter Playbook | Block IP at Firewall |
| **DATA_EXFILTRATION** | `T1048` (Exfiltration Over Alt Protocol) | DLP Containment Playbook | Emergency Access Cutoff |
| **WEB_ATTACK** | `T1190` (Exploit Public-Facing App) | WAF Rule Enforcement | Rate-Limit & Block Origin IP |

---

## Security Policy & Credential Hygiene

- **Zero Committed Secrets**: This repository strictly rejects hardcoded API keys, bearer tokens, or webhook secrets. All configurations utilize `.env` variables or n8n secret stores.
- **Safe Simulation**: Out-of-the-box containment actions default to mock endpoints to protect production networks during initial testing.
- Please review our [SECURITY.md](SECURITY.md) for vulnerability disclosure procedures.

---

## Research & Academic Citation

This project is built upon the academic research:

> **"SentinelFlow: AI + N8N Workflows for Security Operations"**    
> **Authors:** Lakshan Kumaresh V D, Rithish S, Loga Mummoorthi S  
> **Team:** ZERO TWO  

If you use SentinelFlow in your research or SOC deployment, please cite this repository:

```bibtex
@article{sentinelflow2026,
  title={SentinelFlow: AI + N8N Workflows for Security Operations},
  author={Lakshan Kumaresh V D and Rithish S and Loga Mummoorthi S }
```

---

##  Contributors

- **Lakshan Kumaresh V D** ([@itold1lie](https://github.com/itold1lie)) — *Architecture, Automation & Core Pipeline*

---

## License

This project is licensed under the [MIT License](LICENSE).
