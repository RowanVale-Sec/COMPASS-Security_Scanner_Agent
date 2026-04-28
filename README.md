# COMPASS — Threat Modeling Agent Pipeline

**COMPASS** reads your GitHub repo like a threat modeler would — inferring components, data flows, and trust boundaries from the code itself, then mapping each security finding to the real component it affects and synthesizing STRIDE attack scenarios and MITRE ATT&CK–mapped risk priorities into one CISO-ready report, in minutes.

Multi-agent pipeline. Brings your own LLM key (Anthropic Claude or Azure OpenAI). No persistent storage of your code or your credentials. Runs locally via Docker Compose, or on GCP Cloud Run with scale-to-zero billing and Cloud IAP gating.

---

## Pick your path

| You want to... | Read this |
|---|---|
| **Run a scan and get a threat model** | [docs/use-it.md](docs/use-it.md) — install, scan, interpret the report |
| **Host this for your team** | [docs/deploy-it.md](docs/deploy-it.md) — local Docker or GCP Cloud Run |
| **Understand how it works** | [docs/understand-it.md](docs/understand-it.md) — architecture, data flow, design rationale |
| **Add a feature or fix a bug** | [docs/contribute.md](docs/contribute.md) — dev setup, code map, how to add an agent |
| **Audit the security posture** | [docs/security.md](docs/security.md) — threat model, credential handling, attack surface |

Reference (lookups, not narratives): [env vars](docs/reference/env-vars.md) · [API endpoints](docs/reference/api.md) · [MCP servers](docs/reference/mcp-servers.md).

---

## 5-minute local quickstart

```bash
git clone https://github.com/RowanVale-Sec/COMPASS.git
cd COMPASS
docker compose up --build -d
```

When `docker compose ps` shows everything healthy, open `http://localhost:3000`, paste your Anthropic or Azure OpenAI key, paste a GitHub repo URL, hit Submit. About 5–15 minutes later you have a JSON bundle with scanner findings, an SBOM, an asset inventory, a STRIDE threat model, and an executive summary.

If anything goes wrong: [docs/use-it.md#troubleshooting](docs/use-it.md#troubleshooting).

---

## What's in the box

A request-driven pipeline of 8 services (7 on Cloud Run — frontend bundles into the api-gateway):

- **api-gateway** — FastAPI BFF; receives `POST /api/scan`, clones the repo, streams progress over SSE.
- **orchestrator** — calls scanner → inventory → threat-model in sequence; runs the executive summary in-process.
- **scanner-agent** — Trivy / Checkov / Bandit / Semgrep, deduplicates with embeddings, maps each finding to MITRE ATT&CK.
- **inventory-agent** — Syft SBOM + architecture detection + data-flow analysis + asset registry.
- **threat-model-agent** — STRIDE analysis + attack scenarios + risk scoring.
- **mitre-mcp** — MCP server for the ATT&CK technique catalog.
- **syft-mcp** — HTTP wrapper around the `syft` SBOM binary.
- **frontend** — React + Vite SPA (local Docker only; folded into api-gateway on Cloud Run).

For the data-flow diagram and the why-it-looks-this-way section, see [docs/understand-it.md](docs/understand-it.md).

---

## Project status

Pre-1.0, single-maintainer, no tagged releases yet. Local Docker has been the working deployment; GCP Cloud Run support landed in this iteration. Forward-looking design exploration lives in [docs/future/](docs/future/).

Reporting security issues: [SECURITY.md](SECURITY.md). Contributing: [CONTRIBUTING.md](CONTRIBUTING.md). License: [Apache 2.0](LICENSE).
