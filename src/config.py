"""
Configuration module for SentinelFlow.
Loads API keys and settings from environment variables or .env file.
"""

import os
from pathlib import Path

# Try importing dotenv, otherwise fallback gracefully
try:
    from dotenv import load_dotenv
    # Load .env from project root if it exists
    env_path = Path(__file__).resolve().parent.parent / ".env"
    load_dotenv(dotenv_path=env_path)
except ImportError:
    pass

VT_API_KEY = os.getenv("VT_API_KEY", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

GROQ_MODEL = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
GROQ_API_URL = os.getenv("GROQ_API_URL", "https://api.groq.com/openai/v1/chat/completions")
VT_API_BASE_URL = os.getenv("VT_API_BASE_URL", "https://www.virustotal.com/api/v3")

def validate_config() -> dict:
    """Check which API keys are configured."""
    return {
        "virustotal": bool(VT_API_KEY and not VT_API_KEY.startswith("YOUR_")),
        "groq": bool(GROQ_API_KEY and not GROQ_API_KEY.startswith("YOUR_")),
        "discord": bool(DISCORD_WEBHOOK_URL and not DISCORD_WEBHOOK_URL.startswith("YOUR_")),
    }
