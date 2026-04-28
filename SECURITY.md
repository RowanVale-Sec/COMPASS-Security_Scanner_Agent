# Security Policy

## Reporting a vulnerability

If you've found a security issue in COMPASS, please **do not open a public GitHub issue**. Instead:

- Open a private security advisory via GitHub: **Security → Advisories → Report a vulnerability** on this repo, or
- Email the maintainer at `shashi@compass-sec.app` with subject `[SECURITY] COMPASS: <short description>`.

Please include:
- A description of the issue and its impact.
- Steps to reproduce (or a proof-of-concept).
- The COMPASS version / commit SHA you tested against.
- Any suggested mitigation, if you have one.

You can expect an acknowledgement within **5 business days** and a coordinated disclosure timeline depending on severity.

## Supported versions

COMPASS is pre-1.0 with no tagged releases yet. Security fixes are applied to `master`. Once tagged releases exist this section will list which versions receive backports.

## Scope

Issues in scope:
- Credential leakage (LLM API keys, GitHub PATs reaching disk, logs, telemetry, or other tenants' contexts).
- Authentication / authorization bypasses (IAP gating, S2S ID-token validation, WIF attribute conditions).
- Code execution via crafted scan inputs.
- Server-side request forgery, path traversal, command injection in any of the agents.
- Misconfigurations in the Terraform that grant broader access than documented.

Out of scope (see [docs/security.md](docs/security.md) for the full list):
- 0-days in upstream scanner binaries (Trivy, Semgrep, Bandit, Checkov, Syft).
- Issues that require already-compromised Google accounts.
- Sustained DDoS / volumetric attacks.

## Background

For the full threat model, defense-in-depth design, and a rundown of every security control in the codebase, see **[docs/security.md](docs/security.md)**.
