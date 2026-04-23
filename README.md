# COMPASS — Multi-Agent Security Pipeline

**COMPASS** (Cloud Operations Management Platform for Application Security Systems) is a modular, multi-agent security pipeline that scans a codebase, builds an inventory of assets, and produces a risk-focused threat model — all orchestrated via containerized microservices.

**Elevator Pitch:** COMPASS reads your GitHub repo like a threat modeler would — inferring components, data flows, and trust boundaries from the code itself, then mapping each security finding to the real component it affects and synthesizing STRIDE attack scenarios and MITRE ATT&CK–mapped risk priorities into one CISO-ready report, in minutes.

---

## 🧩 What This Repository Contains

This repository provides a full **pipeline** of services (agents) that work together:

- **Scanner Agent** (`:8090`) — runs security tools (Checkov, Trivy, Bandit, Semgrep), deduplicates findings using embeddings, and maps findings to MITRE ATT&CK.
- **Inventory Agent** (`:8091`) — generates SBOMs (via Syft), analyzes architecture and data flows, and builds an asset inventory.
- **Threat Model Agent** (`:8092`) — correlates scan findings with the inventory, generates attack scenarios, applies STRIDE analysis, and scores risks.
- **Orchestrator** (`:8093`) — coordinates all agents as a single pipeline and produces an executive report.
- **MITRE MCP Server** (`:8000`) — provides ATT&CK knowledge via an MCP/HTTP endpoint.
- **Syft MCP Server** (`:8080`) — provides SBOM generation via the Syft MCP API.

---

## 🏗️ Architecture Overview

```
                          ┌─────────────────────────────────────────┐
                          │           ORCHESTRATOR  :8093           │
                          │                                         │
                          │  POST /run  →  runs full pipeline       │
                          │  • calls each agent in sequence         │
                          │  • passes S3 URIs between agents        │
                          │  • uploads executive summary to S3      │
                          └────┬──────────┬──────────┬─────────────┘
                               │ step 1   │ step 2   │ step 3
                               ▼          ▼          ▼
                          ┌────────┐ ┌─────────┐ ┌────────────┐
                          │SCANNER │ │INVENTORY│ │THREAT MODEL│
                          │ :8090  │ │  :8091  │ │   :8092    │
                          └────────┘ └─────────┘ └────────────┘
                               │          │            │
                               └──────────┴────────────┘
                                          │
                                    ┌─────▼──────┐
                                    │  AWS  S3   │
                                    │  (results) │
                                    └────────────┘
```

---

## 🚀 Quick Start (Docker Compose)

### 1) Prerequisites

- Docker & Docker Compose (v3.8+)
- An AWS S3 bucket (for storing scan results)
- Azure OpenAI (for AI-powered deduplication & mapping)

### 2) Configure Environment

Create a `.env` file at the repo root with your settings:

```bash
# Azure OpenAI
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_API_KEY=your-api-key
AZURE_OPENAI_CHAT_DEPLOYMENT_NAME=gpt-4o

# AWS S3
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_REGION=us-east-1
S3_BUCKET=your-bucket-name
```

> ⚠️ The pipeline uses `S3_BUCKET` to store all intermediary and final results. Ensure the bucket exists and the credentials have `s3:GetObject`, `s3:PutObject`, and `s3:ListBucket` permissions.

### 3) Start All Services

```bash
docker compose up --build -d
```

### 4) Run the Full Pipeline

The orchestrator coordinates the agents and uploads an executive summary to S3:

```bash
curl -X POST http://localhost:8093/run -H "Content-Type: application/json" -d '{}'
```

> 📌 The orchestrator will wait for each agent to complete. You can also call each agent directly for debugging.

---

## 📌 Agent Endpoints (Direct Calls)

| Agent | Port | Endpoint | Purpose |
|------|------|----------|---------|
| Scanner | 8090 | `POST /run` | Executes scan tools, deduplicates, maps to MITRE |
| Inventory | 8091 | `POST /run` | Generates SBOM, architecture, data flow, assets |
| Threat Model | 8092 | `POST /run` | Correlates findings, generates attack scenarios, scores risk |
| Orchestrator | 8093 | `POST /run` | Runs full pipeline (scanner → inventory → threat model) |

> Each agent exposes a `/health` endpoint for readiness checks.

---

## 🧠 What the Scanner Agent Does

- Runs **multiple scanners in parallel** (Checkov, Trivy, Bandit, Semgrep, etc.)
- Aggregates and normalizes results into a common findings schema
- Deduplicates findings using **Azure OpenAI embeddings + cosine similarity**
- Maps findings to **MITRE ATT&CK** using the built-in MCP server
- Uploads results to **S3**

---

## 🗃️ What the Inventory Agent Does

- Generates an SBOM (via Syft MCP)
- Analyzes codebase architecture, detects services/frameworks/IaC patterns
- Maps data flows and trust boundaries
- Builds an asset inventory with risk classifications
- Uploads inventory output to **S3**

---

## 🎯 What the Threat Model Agent Does

- Loads Scanner + Inventory outputs from **S3**
- Correlates findings to architecture components
- Generates realistic attack scenarios using MITRE techniques
- Applies **STRIDE analysis** and scores risks (CVSS-like)
- Uploads threat model output to **S3**

---

## 📦 Output Storage (S3)

The orchestrator and agents store outputs in well-known prefixes under the configured bucket:

```
s3://<bucket>/mitre-mapped-findings/       # Scanner + MITRE mapping
s3://<bucket>/scan-results/                 # Raw and deduplicated scans
s3://<bucket>/inventory/                    # SBOM, architecture, assets
s3://<bucket>/threat-model/                 # Final threat model report
s3://<bucket>/executive-reports/            # Orchestrator executive summary
```

---

## 🛠️ Configuration Notes

### Change Scan Source Folder

To scan a different codebase, update the volume mount in `docker-compose.yml` for each agent (scanner + inventory):

```yaml
services:
  scanner-agent:
    volumes:
      - /path/to/your/code:/scan:ro
  inventory-agent:
    volumes:
      - /path/to/your/code:/scan:ro
```

### Adjust Agent Timeouts

Each agent has per-request timeouts controlled by env vars exposed in their `Dockerfile` / entrypoint scripts (look in `agents/*/*.py`).

---

## 🧪 Running Locally for Development

If you'd like to run an agent directly without Compose, you can start any agent with Python from its folder (e.g., `agents/scanner`), making sure required dependencies are installed in a virtualenv.

---

## 🛠️ Troubleshooting

### Check Service Health

```bash
docker compose ps
```

### View Logs

```bash
docker compose logs -f orchestrator scanner-agent inventory-agent threat-model-agent
```

### Common Issues

**Azure OpenAI authentication failure**
- Ensure `AZURE_OPENAI_API_KEY` is correct
- Ensure `AZURE_OPENAI_CHAT_DEPLOYMENT_NAME` matches the deployment name in Azure

**S3 permission errors**
- Validate IAM permissions for `s3:GetObject`, `s3:PutObject`, and `s3:ListBucket`

**Agent startup hangs**
- Confirm MCP servers are healthy (port 8000 for MITRE, 8080 for Syft)

---

## 📄 License

MIT License — see [LICENSE](LICENSE)
