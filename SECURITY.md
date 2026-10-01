# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | Active support     |

## Reporting a Vulnerability

If you discover a security vulnerability in SentinelFlow, please report it responsibly.

### Do not open a public GitHub issue for security vulnerabilities.

Instead, please send an email to: **lakshanisonwork@gmail.com**

Include the following details:
- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Suggested fix (if any)

### Response Timeline

| Action | Timeframe |
|---|---|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 1 week |
| Fix & disclosure | Within 30 days |

## Security Best Practices

When using SentinelFlow:

1. **Never commit API keys** — Always use `.env` files (excluded via `.gitignore`)
2. **Rotate keys regularly** — Especially if you suspect a leak
3. **Use least-privilege API keys** — Only grant necessary permissions
4. **Secure webhook URLs** — Treat Discord webhook URLs as secrets
5. **Review AI outputs** — Never blindly trust AI severity classifications for critical decisions

## Scope

This security policy covers the SentinelFlow codebase. Third-party services
(VirusTotal, Groq, Discord) have their own security policies.
