# Contribute to COMPASS

This is the contributor's manual: how to set up a dev loop, where things live, and how to add a scan tool, an agent, or a Cloud Run service. Aimed at someone who's read [understand-it.md](understand-it.md) once and is now opening their first PR.

---

## Dev setup

### Run the stack

```bash
git clone https://github.com/RowanVale-Sec/COMPASS.git
cd COMPASS
docker compose up --build -d
```

When everything's healthy, hit `http://localhost:3000` and submit a scan against any small public repo (e.g. itself). That's the loop you're iterating on.

### Iterate on a single service

Most services rebuild fast. To rebuild and bounce just one:

```bash
docker compose up -d --build scanner-agent
docker compose logs -f scanner-agent
```

The frontend is the one exception — `npm run dev` outside Docker is much faster than rebuilding the nginx image:

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173, proxies /api to localhost:8094
```

(Vite's dev server proxy is configured to hit the gateway directly so you don't need the nginx container running for frontend work.)

### Python venvs (optional)

Each Python service has its own `requirements.txt`. If you want IDE completion / type-checking outside Docker:

```bash
python -m venv .venv && . .venv/Scripts/activate     # PowerShell: .venv\Scripts\Activate.ps1
pip install -r api_gateway/requirements.txt
pip install -r agents/scanner/requirements.txt       # etc.
```

There's no project-wide `pyproject.toml` or `pytest.ini` — each service is a standalone Python app.

---

## Code map

A 90-second tour of the repo:

```
COMPASS/
├── frontend/                       # React + Vite SPA, served by nginx (local) or
│                                   # bundled into api-gateway (cloud)
│   └── src/
│       ├── App.tsx                 # the scan form + progress view
│       └── api/client.ts           # POST /api/scan, opens SSE stream
│
├── api_gateway/                    # FastAPI BFF — the only public service
│   ├── Dockerfile                  # local build (FastAPI only)
│   ├── Dockerfile.cloud            # cloud build (Node + React + FastAPI)
│   └── app/
│       ├── main.py                 # routes, job lifecycle, repo cleanup
│       ├── jobs.py                 # in-memory JobRegistry (TTL + LRU)
│       ├── github.py               # safe git clone with PAT injection via GIT_ASKPASS
│       ├── orchestrator_client.py  # SSE consumer for the orchestrator
│       ├── validators.py           # GitHub URL, PAT, credential pattern checks
│       ├── security.py             # log scrubbing for secrets
│       └── cloud_auth.py           # ID-token minter for Cloud Run S2S (no-op locally)
│
├── agents/                         # the 4 pipeline stages
│   ├── orchestrator/
│   │   └── orchestrator_agent.py   # pipeline coordinator + SSE emitter
│   ├── scanner/
│   │   ├── scanner_agent.py        # /run + /health
│   │   ├── tools/                  # one file per scan tool (checkov, trivy_*, bandit, semgrep)
│   │   └── pipeline/               # aggregator, deduplicator, mitre_mapper
│   ├── inventory/
│   │   ├── inventory_agent.py
│   │   └── tools/                  # sbom_generator, architecture_analyzer, dataflow_analyzer, asset_builder
│   └── threat_model/
│       ├── threat_model_agent.py
│       └── tools/                  # correlate, generate_attack_scenarios, stride, score_risks
│
├── mcp_servers/
│   ├── mitre/                      # Dockerfile clones Montimage/mitre-mcp at build (no source here)
│   └── syft/syft_mcp_server.py     # Flask wrapper around the syft binary
│
├── shared/                         # used by the 4 agents (NOT api-gateway, which is self-contained)
│   ├── base_agent.py               # tiny: get_scan_folder() env reader
│   ├── cloud_auth.py               # mirror of api-gateway's helper
│   ├── llm_provider.py             # ProviderCredentials + use_credentials() ContextVar scope
│   ├── mcp_utils.py                # mcp_session() context manager
│   ├── local_store.py              # per-run temp dir lifecycle (run_scope)
│   ├── security.py                 # log scrubbing
│   └── schemas.py                  # Pydantic data contracts
│
├── infra/                          # GCP deploy (Terraform + bootstrap + workflow refs)
│   ├── README.md                   # operator's deploy walkthrough
│   ├── bootstrap.{sh,ps1}          # one-time GCS state bucket creator
│   └── terraform/                  # see infra/README.md for module layout
│
├── .github/workflows/
│   ├── deploy.yml                  # build 7 images + terraform apply on push to master
│   └── pr-check.yml                # terraform fmt/validate + hadolint on PRs
│
└── docs/                           # this directory
```

The `api_gateway/app/cloud_auth.py` is intentionally a duplicate of `shared/cloud_auth.py` — the api-gateway is built as a self-contained image and doesn't have access to `shared/`. Keep them in sync if you change the helper.

---

## How to add a scan tool

Concrete example: adding `gitleaks` (secrets detection).

1. **Tool wrapper.** Create `agents/scanner/tools/gitleaks.py`:
   ```python
   import json, subprocess
   from typing import Annotated
   from pydantic import Field
   from shared.local_store import save_findings

   def scan_with_gitleaks(
       folder_path: Annotated[str, Field(description="Path to scan")]
   ) -> dict:
       """Run gitleaks against folder_path. Returns {tool, findings_file, finding_count}."""
       result = subprocess.run(
           ["gitleaks", "detect", "--source", folder_path, "--report-format", "json", "--no-git"],
           capture_output=True, text=True
       )
       findings = json.loads(result.stdout) if result.stdout else []
       path = save_findings(findings, "gitleaks-findings")
       return {"tool": "gitleaks", "findings_file": path, "finding_count": len(findings)}
   ```
   The contract is: returns a metadata dict with `tool`, `findings_file` (path written by `save_findings`), and `finding_count`. The aggregator stage discovers tool runs via this dict.

2. **Wire into the agent.** In [agents/scanner/scanner_agent.py](../agents/scanner/scanner_agent.py):
   - Import `from agents.scanner.tools.gitleaks import scan_with_gitleaks`
   - Add `scan_with_gitleaks` to the `tools=[...]` list passed to `agent.create_agent(...)`
   - Add a corresponding line to the workflow instructions string ("- gitleaks_result = scan_with_gitleaks(...)")

3. **Install the binary.** In [agents/scanner/Dockerfile](../agents/scanner/Dockerfile), add the install step:
   ```dockerfile
   RUN curl -sSfL https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz \
       | tar -xz -C /usr/local/bin gitleaks
   ```

4. **Rebuild and try.** `docker compose up -d --build scanner-agent`, then submit a scan and check the logs for `[Tool] gitleaks` output.

The aggregator + deduplicator + MITRE mapper stages handle the new tool's findings without further changes — they're tool-agnostic.

---

## How to add a new agent

This is more involved because it touches docker-compose, the orchestrator, Terraform, and CI. Concrete example: adding a hypothetical `compliance-agent` that produces SOC 2 control mappings.

1. **Agent skeleton.** Create `agents/compliance/` with:
   - `Dockerfile` — copy [agents/threat_model/Dockerfile](../agents/threat_model/Dockerfile) as a starting point
   - `requirements.txt` — at minimum `flask`, `pydantic`, `requests`, `google-auth`
   - `compliance_agent.py` — implement `POST /run` (returns `{"status": "success", "compliance": {...}}`) and `GET /health`

2. **docker-compose.yml.** Add the service block matching the others' shape (port, env, healthcheck, networks). Update the `orchestrator` block's `depends_on` and `environment` (`COMPLIANCE_URL=http://compliance-agent:8095`).

3. **Orchestrator.** In [agents/orchestrator/orchestrator_agent.py](../agents/orchestrator/orchestrator_agent.py):
   - Add `COMPLIANCE_URL = os.environ.get('COMPLIANCE_URL', 'http://compliance-agent:8095')`
   - Add a `_post_agent(COMPLIANCE_URL, ...)` call inside `run_pipeline()` between threat_model and the executive summary.
   - Add the agent's output to the final `bundle` dict.

4. **Terraform.**
   - [infra/terraform/locals.tf](../infra/terraform/locals.tf): add `"compliance-agent"` to the `services` list. PR 2's modules (AR repo, runtime SA) will provision automatically.
   - [infra/terraform/services.tf](../infra/terraform/services.tf): add a `module "cloud_run_compliance"` block following the `threat-model-agent` pattern + add the port to `local.prod_ports`.
   - Update the `orchestrator` module's `env_vars` to include `COMPLIANCE_URL = module.cloud_run_compliance.uri`.
   - [infra/terraform/runtime_iam.tf](../infra/terraform/runtime_iam.tf): add `google_cloud_run_v2_service_iam_member "orchestrator_invokes_compliance"` granting the orchestrator SA invoker on the new service.

5. **CI.** [.github/workflows/deploy.yml](../.github/workflows/deploy.yml): add a matrix entry under `build.strategy.matrix.include`:
   ```yaml
   - service: compliance-agent
     dockerfile: agents/compliance/Dockerfile
     context: .
   ```
   And add `compliance-agent` to the smoke-test loop in `terraform-apply`.

6. **Docs.** Add the agent to [understand-it.md](understand-it.md)'s component table and the pipeline sequence diagram. Add any new env vars to [reference/env-vars.md](reference/env-vars.md).

That's the full mechanical pass. Follow [docs/security.md](security.md) when picking the new agent's IAM scope — every new internal service should be `--no-allow-unauthenticated` with explicit invoker bindings.

---

## Testing

**There are no automated tests in the repo today.** This is the honest state — `docker compose up` + submitting a scan is the entire test surface. If you want to add tests, that's a high-value contribution; pick a frame (pytest is the obvious choice for the Python services, vitest for the frontend) and start with one service.

Until tests exist, the convention used during the GCP migration was to write a throwaway `_smoke.py` next to the change that imports the modules and exercises a non-network code path:

```python
# _smoke.py — delete after run
import py_compile
for f in ["api_gateway/app/main.py", "shared/cloud_auth.py"]:
    py_compile.compile(f, doraise=True)

import os
os.environ.pop("K_SERVICE", None)
from shared import cloud_auth
assert cloud_auth.get_id_token("https://x.run.app") is None  # local mode

print("ALL CHECKS PASS")
```

The PR-check workflow runs `terraform fmt`, `terraform validate`, and `hadolint` on every PR — that catches formatting drift and Dockerfile mistakes without needing GCP.

---

## PR flow

1. Branch off `master`. The Workload Identity Federation provider is locked to `RowanVale-Sec/COMPASS` on `refs/heads/master`, so feature branches can't accidentally deploy to prod.
2. Make changes. Run the local stack and exercise the path you touched.
3. If you touched Terraform, run `terraform fmt -recursive` from `infra/terraform/`.
4. Push, open a PR. The PR-check workflow validates Terraform + lints Dockerfiles. Failures show up inline.
5. After merge to `master`, the deploy workflow builds the 7 images, runs `terraform apply -var image_tag=<sha>`, and rolls every service. The smoke step asks Cloud Run for each service's deployed image and fails if any didn't pick up the new SHA.
6. End-to-end verification through IAP is a manual browser step — the deployer SA isn't (and shouldn't be) in the IAP allowlist.

If a deploy goes bad, see [deploy-it.md#rollback](deploy-it.md#rollback) for the gcloud one-liner that flips traffic back to the previous revision.

---

## Style and conventions

- Python services follow [shared/llm_provider.py](../shared/llm_provider.py)'s `ProviderCredentials` + `use_credentials()` pattern for any LLM call. **Don't** read API keys from env in agent code; let the per-request flow handle it.
- Inter-service calls go through `shared/cloud_auth.auth_headers()` (or `api_gateway/app/cloud_auth.py` for the gateway). Returns `{}` locally so the same code works in both paths.
- Workspace paths come from env (`SCAN_FOLDER_PATH`, `COMPASS_WORKSPACE_ROOT`), never hardcoded.
- Agent endpoints are uniform: `POST /run` (sync), `POST /run/stream` (orchestrator only), `GET /health`.
- Logging uses [shared/security.py](../shared/security.py)'s scrubbed configuration so secrets don't leak. New agents should call `configure_scrubbed_logging()` at startup.

---

## Where to go next

- [understand-it.md](understand-it.md) — the system architecture (read this before changing structure)
- [security.md](security.md) — credential handling, attack surface, what to be careful about
- [reference/env-vars.md](reference/env-vars.md), [reference/api.md](reference/api.md), [reference/mcp-servers.md](reference/mcp-servers.md) — lookups for the boring details
- [infra/README.md](../infra/README.md) — full GCP deploy mechanics
