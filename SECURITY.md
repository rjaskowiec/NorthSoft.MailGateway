# Security Policy — NorthSoft.MailGateway

## Supported Versions

Security updates are actively maintained for the current production release deployed at `mail.northsoft.is`.

| Version | Supported |
| :--- | :--- |
| 1.0.x | Yes |

---

## Credentials & Secret Policy

NorthSoft.MailGateway operates under a strict **Zero-Secret Storage Policy**:

1. **No Credentials in Version Control**: API keys, bearer tokens, passwords, private keys, and environment secrets must never be committed to repository source code, configuration files, or git history.
2. **Cloudflare Secret Bindings**: Production secrets (`GATEWAY_TOKEN`, `BREVO_API_KEY`) are stored exclusively using Cloudflare Worker secret bindings (`wrangler secret put`).
3. **Local Testing Isolation**: Local test environments utilize `.dev.vars` which is strictly ignored by version control.

---

## Reporting a Vulnerability

If you discover a potential security vulnerability in NorthSoft.MailGateway, please report it responsibly.

### How to Submit a Report

Please send security reports directly to the project maintainer:

- **Maintainer**: Robert Jaśkowiec (rjaskowiec)
- **GitHub**: [https://github.com/rjaskowiec](https://github.com/rjaskowiec)

### Report Guidelines

Please include the following details in your report:

- Type of issue (e.g., authentication bypass, sanitization flaw, header injection, CORS misconfiguration).
- Steps to reproduce or proof-of-concept payload.
- Potential impact of the vulnerability.
- Any suggested remediations or patches.

> [!WARNING]
> Please do **NOT** publicly disclose active credentials, production tokens, or unpatched vulnerabilities in public GitHub issues or discussions.
