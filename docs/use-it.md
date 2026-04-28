# Use COMPASS

You give COMPASS a public Git repo URL and your LLM API key. About 5–15 minutes later it gives you back a JSON bundle containing scanner findings (Trivy, Checkov, Bandit, Semgrep), an asset inventory and SBOM, a STRIDE threat model, and a CISO-ready executive summary.

This doc is the operator's manual: how to install it, how to run a scan, how to read the result, and what to do when something fails.

---

## What you need

| Required | What it's for |
|---|---|
| Docker + Docker Compose | To run the 8-container pipeline locally. |
| An LLM API key | One of: Anthropic Claude (`sk-ant-*`) **or** Azure OpenAI (key + endpoint + chat deployment name). |
| A GitHub repo URL | Public works out of the box. Private repos need a GitHub PAT with `repo` read scope. |

Optional: if you've already got COMPASS deployed to GCP for your team, you don't install anything — you just visit the URL. Skip ahead to [Submit a scan](#submit-a-scan).

---

## Run it locally in 5 minutes

```bash
git clone https://github.com/RowanVale-Sec/COMPASS.git
cd COMPASS
docker compose up --build -d
```

The first build pulls scanner binaries (Trivy, Syft) and pre-warms the embedding model — expect 5–10 minutes on a cold machine, ~30 seconds on rebuilds.

Once `docker compose ps` shows every service `healthy`, open:

```
http://localhost:3000
```

That's the React frontend. There's no setup screen, no login — just the scan form.

> Don't see services going healthy? Skip to [Troubleshooting](#troubleshooting).

---

## Submit a scan

The form takes four things:

| Field | Notes |
|---|---|
| **GitHub URL** | `https://github.com/owner/repo`. HTTPS only; SSH URLs are rejected by [the validator](../api_gateway/app/validators.py). Default 500 MB clone size cap. |
| **GitHub PAT** *(optional)* | Only for private repos. `ghp_*` or `github_pat_*` accepted. Scoped to a single clone, then dropped. |
| **Provider** | `claude` or `azure`. |
| **Credentials** | The API key (and for Azure, the endpoint + chat deployment name). See [provider setup below](#provider-setup). |

Hit **Submit**. The page switches to a live progress view streamed over Server-Sent Events. You'll see the stages tick by:

```
clone           → completed
scanner         → completed (45 findings)
inventory       → completed (32 assets)
threat_model    → completed (overall_risk_score 7.3)
executive_summary → completed
complete        → bundle ready
```

The whole thing typically takes 5–15 minutes depending on repo size and LLM provider latency. Closing the browser tab does **not** cancel the scan — it keeps running on the server, and you can re-open the events URL using the `job_id` to reattach.

---

## Read the report

The bundle is a single JSON file with five top-level sections:

```json
{
  "compass_version": "2.0",
  "report_type": "compass_full_bundle",
  "generated_at": "2026-04-26T12:34:56Z",
  "target": "/workspace/<job_id>/repo",

  "scanner":           { "metadata": {...}, "FND-...": {...} },
  "inventory":         { "sbom": {...}, "architecture": {...},
                         "data_flow": {...}, "asset_inventory": {...} },
  "threat_model":      { "summary": {...}, "risk_analysis": {...},
                         "attack_scenarios": [...], "stride": {...} },
  "executive_summary": { "executive_summary": "...", "key_metrics": {...},
                         "top_3_actions": [...], "risk_posture": "..." }
}
```

Where to start:

- **`executive_summary.top_3_actions`** — the three things to fix first, ranked by the threat-model agent.
- **`executive_summary.risk_posture`** — one-line overall judgment (CRITICAL / HIGH / MEDIUM / LOW).
- **`threat_model.summary.overall_risk_score`** — 0–10 rollup score.
- **`scanner.metadata.tool_distribution`** — how many findings each tool produced (sanity-check that scanners actually ran).
- **`inventory.architecture`** — what services/frameworks/cloud resources COMPASS detected. If this is empty for a repo you know has a Dockerfile or `terraform/` directory, the inventory agent missed something — flag it.

Each scanner finding has a `mitre_analysis` block with the mapped ATT&CK technique, an adjusted severity, and the rationale the LLM used to pick it. Useful for filtering ("show me everything mapped to T1078 — Valid Accounts").

For the full schema of every section, see [docs/reference/api.md](reference/api.md).

---

## Provider setup

### Claude (recommended)

1. Get an API key at [console.anthropic.com](https://console.anthropic.com).
2. In the form: Provider = **Claude**, paste the `sk-ant-*` key, optionally pick a model.

Allowlisted models (validated server-side — see [validators.py:54-60](../api_gateway/app/validators.py#L54-L60)):
- `claude-opus-4-7`, `claude-opus-4-6`, `claude-opus-4-5`
- `claude-sonnet-4-6`, `claude-sonnet-4-5`
- `claude-haiku-4-5`, `claude-haiku-4-5-20251001`

Default if you don't pick: `claude-sonnet-4-6` (fast, cheap, good for the scan workload).

### Azure OpenAI

1. Have an Azure OpenAI resource with a chat deployment (`gpt-4o` or compatible).
2. In the form: Provider = **Azure**, paste the API key, the endpoint URL (`https://<resource>.openai.azure.com/`), and the deployment name.

Optional: `embedding_deployment` if you want server-side embeddings instead of the local sentence-transformer model the scanner uses by default. Most users should leave it blank.

---

## Cost & performance expectations

| Repo size | Time | LLM calls | Approx LLM cost (Claude Sonnet) |
|---|---|---|---|
| Small (<10 files, <1k LOC) | 3–5 min | ~50 | $0.05 |
| Medium (50 files, ~10k LOC) | 7–12 min | ~250 | $0.30 |
| Large (200+ files, ~50k LOC) | 15–25 min | ~800 | $1–2 |

Most of the wall time is scanner tool execution + MITRE mapping (15-way parallel LLM calls, one per finding).

---

## Troubleshooting

### Services don't go healthy

```bash
docker compose ps
docker compose logs -f orchestrator scanner-agent inventory-agent threat-model-agent
```

Common causes:
- **Port already in use.** Something on your machine is on 3000, 8090–8094, 8000, or 8080. Stop it or remap in `docker-compose.yml`.
- **Out of disk.** The scanner image bundles Trivy + Syft + sentence-transformers (~6.5 GB). Free up at least 10 GB.
- **First-build embedding download failed.** Re-run `docker compose build scanner-agent` — the SentenceTransformer pull retries.

### "Scan rejected (HTTP 400): invalid github url"

The URL validator only accepts `https://github.com/...`. SSH URLs (`git@github.com:...`) and HTTP (no S) are rejected.

### "Scan rejected (HTTP 400): invalid api key"

Keys are pattern-validated server-side ([validators.py:47-49](../api_gateway/app/validators.py#L47-L49)):
- Claude: `sk-ant-` followed by 20–300 alphanumeric/underscore/hyphen.
- Azure: 32–64 hex characters.

If your key looks right but is rejected, double-check no leading/trailing whitespace.

### Scan hangs at "scanner: started"

The scanner is the longest stage. Tail its logs:

```bash
docker compose logs -f scanner-agent
```

You should see Trivy / Checkov / Semgrep output rolling. If you see "MITRE" line items but they're not progressing, the LLM provider is rate-limiting you — try a different key or wait a few minutes.

### Scan completes but `inventory.architecture` is empty

The inventory agent's architecture detection relies on the LLM. Failure here usually means:
- The repo has no Dockerfile / `terraform/` / framework manifest the detector recognises (genuinely sparse repo).
- LLM call timed out or was rate-limited mid-stage. Re-run the scan.

### "rate limit exceeded" on `/api/scan`

The gateway rate-limits to **3 scans per minute per IP** ([main.py:106](../api_gateway/app/main.py#L106)). Wait a minute and retry. This limit doesn't carry through to a deployed instance behind a load balancer — talk to your operator.

### Local cleanup

```bash
docker compose down -v        # stops everything + drops the workspace volume
```

The workspace volume (`compass-workspace`) holds per-job clones during scans — the api-gateway deletes them on completion, so `down` is safe to run while idle.

---

## Where to go next

- **Want to host this for your team?** [deploy-it.md](deploy-it.md) — local + GCP options.
- **Curious how it works?** [understand-it.md](understand-it.md) — system architecture.
- **Want to add a feature?** [contribute.md](contribute.md).
- **Reviewing the security model?** [security.md](security.md).
