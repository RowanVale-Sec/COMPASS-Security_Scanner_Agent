# COMPASS — Multi-Agent Security Pipeline

> **C**loud **O**perations **M**anagement **P**latform for **A**pplication **S**ecurity **S**ystems

---

## Overall Workflow

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

## How the Orchestrator Coordinates the Pipeline

```
 User
  │
  │  POST /run  {"folder_path": "/scan", "s3_bucket": "..."}
  ▼
┌─────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATOR                             │
│                                                                 │
│  1. run_scanner_agent(folder_path, s3_bucket)                   │
│        │                                                        │
│        │  HTTP POST → scanner-agent:8090/run                   │
│        │  waits up to 30 min                                    │
│        ◄─ returns s3://bucket/mitre-mapped-findings/…json       │
│                                                                 │
│  2. run_inventory_agent(folder_path, scanner_s3_uri)            │
│        │                                                        │
│        │  HTTP POST → inventory-agent:8091/run                  │
│        ◄─ returns s3://bucket/inventory/…json                   │
│                                                                 │
│  3. run_threat_model_agent(scanner_s3_uri, inventory_s3_uri)    │
│        │                                                        │
│        │  HTTP POST → threat-model-agent:8092/run               │
│        ◄─ returns s3://bucket/threat-model/…json                │
│                                                                 │
│  4. upload_executive_summary(all S3 results)                    │
│        └─► s3://bucket/executive-reports/…json                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Scanner Agent  `:8090`

Scans the codebase with multiple tools in parallel, then aggregates, deduplicates and maps to MITRE ATT&CK.

```
  /scan  (mounted codebase)
    │
    ├──────────────────────────────────────────────────────┐
    │   PARALLEL SCAN TOOLS                                │
    │                                                      │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
    │  │ Checkov  │  │Trivy IaC │  │  Bandit  │           │
    │  │ (IaC)    │  │ (misconf)│  │  (SAST)  │           │
    │  └──────────┘  └──────────┘  └──────────┘           │
    │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │
    │  │ Semgrep  │  │Trivy SCA │  │  Trivy   │           │
    │  │ (SAST)   │  │ (deps)   │  │ Secrets  │           │
    │  └──────────┘  └──────────┘  └──────────┘           │
    │  ┌──────────┐                                        │
    │  │  Trivy   │  (scans Docker base images found       │
    │  │  Image   │   via find_docker_base_images())       │
    │  └──────────┘                                        │
    └──────────────────────────────────────────────────────┘
            │
            │  ~125 raw findings
            ▼
    ┌───────────────────┐
    │    AGGREGATOR     │  normalises all tool outputs into
    │                   │  a unified findings schema
    │                   │  → s3://…/scan-results/….json
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐
    │   DEDUPLICATOR    │  Azure OpenAI embeddings
    │                   │  cosine similarity clustering
    │                   │  removes duplicate findings
    │                   │  → s3://…/scan-results/…-deduplicated.json
    └─────────┬─────────┘
              │
              ▼
    ┌───────────────────┐          ┌────────────────────┐
    │  MITRE  MAPPER    │◄─────────│  MITRE ATT&CK MCP  │
    │                   │  queries │  Server  :8000      │
    │  maps each finding│  /mcp    │  (FastMCP /         │
    │  to ATT&CK tactic │          │   Streamable HTTP)  │
    │  & technique      │          └────────────────────┘
    │  → s3://…/mitre-mapped-findings/….json
    └───────────────────┘
```

---

## Inventory Agent  `:8091`

Builds a complete picture of what is deployed — packages, architecture, data flows, and assets.

```
  /scan  (mounted codebase)
    │
    ├─────────────────────────────────────────────────────┐
    │                                                     │
    │  ┌─────────────────────┐    ┌───────────────────┐  │
    │  │  generate_enhanced  │    │  Syft MCP  :8080  │  │
    │  │       _sbom()       │◄───│  (Syft SBOM tool) │  │
    │  │                     │    │  /health endpoint  │  │
    │  │  Software Bill of   │    └───────────────────┘  │
    │  │  Materials (SPDX)   │                            │
    │  └──────────┬──────────┘                            │
    │             │                                       │
    │  ┌──────────▼──────────┐                            │
    │  │ analyze_architecture│  detects services,         │
    │  │       ()            │  frameworks, cloud          │
    │  │                     │  resources, IaC patterns   │
    │  └──────────┬──────────┘                            │
    │             │                                       │
    │  ┌──────────▼──────────┐                            │
    │  │  analyze_data_flows │  maps trust boundaries,    │
    │  │       ()            │  entry points, data stores │
    │  └──────────┬──────────┘                            │
    │             │                                       │
    │  ┌──────────▼──────────┐                            │
    │  │ build_asset_inventory│  catalogs all assets      │
    │  │       ()             │  with risk classification │
    │  └──────────┬──────────┘                            │
    └─────────────┼───────────────────────────────────────┘
                  │
                  ▼
    ┌─────────────────────────┐
    │  upload_inventory_to_s3 │
    │  (sbom, arch, dfd,      │
    │   asset_inventory)      │
    │  → s3://…/inventory/…json
    └─────────────────────────┘
```

---

## Threat Model Agent  `:8092`

Loads scanner + inventory results from S3, then runs a 4-stage threat modelling pipeline.

```
  S3 inputs
    │
    ├── s3://…/mitre-mapped-findings/….json  (from Scanner)
    └── s3://…/inventory/….json              (from Inventory)
                  │
                  ▼
    ┌─────────────────────────────────────────────────────┐
    │                                                     │
    │  ┌────────────────────────────────────────────┐     │
    │  │ 1. correlate_vulnerabilities_with_          │     │
    │  │         architecture()                      │     │
    │  │                                             │     │
    │  │  matches findings → architecture components │     │
    │  │  exposure level, data at risk, attack path  │     │
    │  └───────────────────┬────────────────────────┘     │
    │                      │                              │
    │  ┌───────────────────▼────────────────────────┐     │
    │  │ 2. generate_attack_scenarios()              │     │
    │  │                                             │     │
    │  │  builds realistic attack chains from        │     │
    │  │  correlated findings + MITRE techniques     │     │
    │  └───────────────────┬────────────────────────┘     │
    │                      │                              │
    │  ┌───────────────────▼────────────────────────┐     │
    │  │ 3. perform_stride_analysis()                │     │
    │  │                                             │     │
    │  │  Spoofing / Tampering / Repudiation /       │     │
    │  │  Info Disclosure / DoS / Elevation of Priv  │     │
    │  └───────────────────┬────────────────────────┘     │
    │                      │                              │
    │  ┌───────────────────▼────────────────────────┐     │
    │  │ 4. score_and_prioritize_risks()             │     │
    │  │                                             │     │
    │  │  CVSS-style scoring, business impact,       │     │
    │  │  remediation priority ranking               │     │
    │  └───────────────────┬────────────────────────┘     │
    │                      │                              │
    └──────────────────────┼──────────────────────────────┘
                           │
                           ▼
             ┌─────────────────────────┐
             │  upload_threat_model_   │
             │       to_s3()           │
             │  → s3://…/threat-model/…json
             └─────────────────────────┘
```

---

## S3 as the Inter-Agent Message Bus

```
  Scanner ──────► s3://bucket/mitre-mapped-findings/…json ──────────┐
                                                                     │
  Inventory ────► s3://bucket/inventory/…json ───────────────────┐  │
                                                                  │  │
                                                       ┌──────────▼──▼──────┐
                                                       │   Threat Model     │
                                                       │   (reads both)     │
                                                       └──────────┬─────────┘
                                                                  │
                                                                  ▼
                                              s3://bucket/threat-model/…json
                                                                  │
                                                       ┌──────────▼─────────┐
                                                       │    Orchestrator    │
                                                       │  Executive Summary │
                                                       └──────────┬─────────┘
                                                                  │
                                                                  ▼
                                          s3://bucket/executive-reports/…json
```

---

## Services & Ports

| Service | Port | Role |
|---|---|---|
| `orchestrator` | 8093 | Pipeline coordinator — entry point |
| `scanner-agent` | 8090 | Runs all scan tools + MITRE mapping |
| `inventory-agent` | 8091 | SBOM + architecture + data flow analysis |
| `threat-model-agent` | 8092 | STRIDE + attack scenarios + risk scoring |
| `mitre-mcp` | 8000 | MITRE ATT&CK knowledge base (MCP/HTTP) |
| `syft-mcp` | 8080 | Syft SBOM generation tool (MCP/HTTP) |

---

## Docker Health & Startup Order

```
  mitre-mcp  ──healthy──►  scanner-agent  ──healthy──►  orchestrator
  syft-mcp   ──healthy──►  inventory-agent ──healthy──►  orchestrator
                           threat-model-agent ──healthy──► orchestrator

  (orchestrator only starts once all 3 agents are healthy)
```

---

## Trigger the Pipeline

```bash
# Start all services
docker compose up -d

# Run the full pipeline
curl -X POST http://localhost:8093/run \
     -H "Content-Type: application/json" \
     -d "{}"

# Watch logs
docker compose logs -f orchestrator scanner-agent inventory-agent threat-model-agent
```
