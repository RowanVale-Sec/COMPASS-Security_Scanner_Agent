# Environment variables reference

Every env var COMPASS reads, grouped by purpose. **Almost all are optional** — defaults from docker-compose work for local dev and the GCP Terraform sets the cloud equivalents. Override only when you know why.

For LLM credentials specifically: don't set them as env vars in normal use. The browser form forwards them per-request. The fallback env vars at the bottom of this page exist only for running an agent directly (no api-gateway in front).

---

## Workspace & job lifecycle

| Var | Default | Set by | Purpose |
|---|---|---|---|
| `COMPASS_WORKSPACE_ROOT` | `/workspace` | api-gateway env (docker-compose / Cloud Run services.tf) | Root directory the api-gateway clones into. Each job goes to `${ROOT}/${job_id}/repo`. |
| `COMPASS_CLONE_TIMEOUT_S` | `300` | Optional | Hard timeout for `git clone` ([github.py:21](../../api_gateway/app/github.py#L21)). |
| `COMPASS_MAX_REPO_BYTES` | `524288000` (500 MB) | Optional | Reject clones larger than this. Prevents accidental scans of huge monorepos. |
| `SCAN_FOLDER_PATH` | `/scan` (code default) → `/workspace` (docker-compose) | scanner / inventory env | Where the agents look for the cloned repo. Must match the workspace mount point. |
| `COMPASS_STORE_ROOT` | system tempdir | Optional | Where `shared/local_store.py:run_scope()` creates per-run temp directories for intermediate findings JSON. |

---

## Frontend serving

| Var | Default | Set by | Purpose |
|---|---|---|---|
| `COMPASS_STATIC_DIR` | (unset) | `Dockerfile.cloud` sets to `/app/static`; unset locally | When set to an existing directory, the api-gateway mounts it as the SPA at `/`. Cloud build path. Local Docker uses the separate `frontend` nginx container instead. |
| `COMPASS_ALLOWED_ORIGIN` | `http://localhost:3000` | docker-compose env | CORS allowlist for the api-gateway. Comma-separated; multiple origins supported. Not needed when the SPA is bundled (same-origin). |

---

## Agent ports

Each Python service binds to its own port. **Don't change these unless you're remapping for a port collision** — the docker-compose network and Cloud Run `container_port` config both expect the defaults.

| Var | Default | Service |
|---|---|---|
| `SCANNER_PORT` | `8090` | scanner-agent |
| `INVENTORY_PORT` | `8091` | inventory-agent |
| `THREAT_MODEL_PORT` | `8092` | threat-model-agent |
| `ORCHESTRATOR_PORT` | `8093` | orchestrator |

The api-gateway's port (8094) is set in the Dockerfile `CMD` directly (`--port 8094`), not via an env var.

The MCP servers use their own conventions: `mitre-mcp` listens on 8000 via `FASTMCP_PORT`, `syft-mcp` on 8080 hardcoded.

---

## Agent / MCP discovery URLs

How services find each other. Defaults match docker-compose hostnames; Cloud Run overrides them with `module.cloud_run_X.uri` ([infra/terraform/services.tf](../../infra/terraform/services.tf)).

| Var | Default | Set on | Purpose |
|---|---|---|---|
| `ORCHESTRATOR_URL` | `http://orchestrator:8093` | api-gateway | Where the gateway POSTs scan jobs. |
| `SCANNER_URL` | `http://scanner-agent:8090` | orchestrator | Step 1 of the pipeline. |
| `INVENTORY_URL` | `http://inventory-agent:8091` | orchestrator | Step 2. |
| `THREAT_MODEL_URL` | `http://threat-model-agent:8092` | orchestrator | Step 3. |
| `MITRE_MCP_URL` | `http://mitre-mcp:8000/mcp` | scanner-agent | MCP endpoint for the technique catalog. The `/mcp` suffix is required (FastMCP's HTTP transport). |
| `SYFT_MCP_URL` | `http://syft-mcp:8080` | inventory-agent | Plain HTTP; the syft-mcp wrapper exposes `/analyze`. |

---

## Timeouts

All in seconds.

| Var | Default | Service | Purpose |
|---|---|---|---|
| `SCANNER_TIMEOUT_S` | `1800` (30 min) | orchestrator | Max time the orchestrator waits on `scanner-agent`. |
| `INVENTORY_TIMEOUT_S` | `900` (15 min) | orchestrator | Max time on `inventory-agent`. |
| `THREAT_MODEL_TIMEOUT_S` | `900` (15 min) | orchestrator | Max time on `threat-model-agent`. |
| `ORCHESTRATOR_STREAM_TIMEOUT_S` | `3600` (60 min) | api-gateway | Max time the gateway will hold the SSE connection to the orchestrator. Aligned with Cloud Run's max request timeout. |

---

## Tuning

| Var | Default | Purpose |
|---|---|---|
| `DEDUP_SIMILARITY_THRESHOLD` | `0.85` | Cosine similarity threshold for clustering near-duplicate findings ([deduplicator.py:71](../../agents/scanner/pipeline/deduplicator.py#L71)). Higher = stricter dedup; lower = collapses more aggressively. |

---

## Cloud Run runtime

Set automatically by Cloud Run; **don't set these manually**. They're listed here for awareness.

| Var | Set by | Used by | Purpose |
|---|---|---|---|
| `K_SERVICE` | Cloud Run | [shared/cloud_auth.py:45](../../shared/cloud_auth.py#L45), [api_gateway/app/cloud_auth.py:40](../../api_gateway/app/cloud_auth.py#L40) | Presence detection for "am I running on Cloud Run?". When unset, the auth helpers return `None` so docker-compose paths skip ID-token minting. |
| `PORT` | Cloud Run | (unused; we set our own ports) | Cloud Run's default contract. We override per-service via `container_port` in services.tf because each COMPASS service has a hardcoded listen port. |
| `FASTMCP_HOST` | services.tf (mitre-mcp only) | mitre-mcp upstream code | Host bind for the FastMCP server. Set to `0.0.0.0`. |
| `FASTMCP_PORT` | services.tf (mitre-mcp only) | mitre-mcp upstream code | Port bind. Set to `8000`. |
| `COMPASS_MODE` | docker-compose / services.tf | Each agent's `__main__` block | When `server`, the agent runs as a Flask HTTP server. Otherwise it runs the workflow once and exits (CLI mode). |

---

## Fallback LLM credentials (CLI mode only)

These are read by [shared/llm_provider.py](../../shared/llm_provider.py) **only** when an agent is invoked directly without going through the api-gateway — e.g., `python -m agents.scanner.scanner_agent` with `COMPASS_MODE` unset.

In normal operation (browser → api-gateway → orchestrator → agent), credentials come in the request body via `use_credentials()` and these env vars are ignored.

| Var | Default | Purpose |
|---|---|---|
| `LLM_PROVIDER` | `azure` | Selects which provider block below is used. `claude` or `azure`. |
| `CLAUDE_API_KEY` *(or `ANTHROPIC_API_KEY`)* | (none) | Anthropic API key for direct calls. |
| `CLAUDE_MODEL` | `claude-sonnet-4-5` | Claude model id. Allowlist enforced when going through the gateway; not enforced for direct CLI calls. |
| `CLAUDE_MAX_TOKENS` | `4096` | Max output tokens per call. |
| `AZURE_OPENAI_API_KEY` | (none) | Azure OpenAI API key. |
| `AZURE_OPENAI_ENDPOINT` | (none) | Resource URL, e.g. `https://my-resource.openai.azure.com/`. |
| `AZURE_OPENAI_CHAT_DEPLOYMENT_NAME` *(or `AZURE_OPENAI_DEPLOYMENT`)* | (none) | Deployment name for chat. |
| `AZURE_OPENAI_EMBEDDING_DEPLOYMENT` *(or `AZURE_OPENAI_EMBEDDING_DEPLOYMENT_NAME`)* | (none) | Optional embedding deployment for server-side embeddings. The scanner uses local sentence-transformers by default; set this only if you specifically want Azure embeddings. |

---

## Where set in production

For Cloud Run, all the values above (except the fallback creds, which aren't used) are set in [infra/terraform/services.tf](../../infra/terraform/services.tf) as `env_vars` blocks per module call. To change one, edit there and run `terraform apply` — don't `gcloud run services update --update-env-vars`, or terraform will revert it on the next deploy.

For docker-compose, see the `environment:` blocks in [docker-compose.yml](../../docker-compose.yml). The committed values are the ones the agents need to find each other; tuning knobs live in `.env` (copy from [.env.example](../../.env.example)).
