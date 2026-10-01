# Contributing to SentinelFlow

Thank you for your interest in contributing to SentinelFlow! This guide will help you get started.

## Quick Start

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create a branch** for your feature or fix
4. **Make changes** and test them
5. **Submit a Pull Request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/<your-username>/SentinalFlow.git
cd SentinalFlow

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
# Fill in your API keys in .env
```

## Branch Naming Convention

| Type | Pattern | Example |
|---|---|---|
| Feature | `feature/<description>` | `feature/add-slack-notifier` |
| Bug Fix | `fix/<description>` | `fix/vt-api-timeout` |
| Documentation | `docs/<description>` | `docs/update-architecture` |
| Refactor | `refactor/<description>` | `refactor/enrichment-module` |

## Commit Message Format

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>

[optional body]
```

**Types:** `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

**Examples:**
```
feat: add Slack notification channel
fix: handle VirusTotal API rate limiting
docs: update architecture diagram
```

## Testing

```bash
# Run tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src
```

## Areas for Contribution

- **New Enrichment Sources** — AbuseIPDB, Shodan, OTX, etc.
- **New Notification Channels** — Slack, Teams, PagerDuty, email
- **AI Model Support** — OpenAI, Claude, local models via Ollama
- **Dashboard** — Web-based triage dashboard
- **Tests** — Improve unit and integration test coverage

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
