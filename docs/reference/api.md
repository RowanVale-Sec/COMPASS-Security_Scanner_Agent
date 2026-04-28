# API reference

The HTTP surface of COMPASS, by service.

The only **public-facing** endpoints are on the api-gateway. Everything else is internal — agents only accept calls from the orchestrator (locally via the Docker network, on Cloud Run via ID-token-authenticated S2S calls). They're documented here so contributors can call them directly when debugging.

---

## api-gateway (`:8094`)

The BFF. This is what the React SPA calls.

### `GET /health`

Liveness probe. Returns `{"status": "healthy", "service": "api_gateway"}` with HTTP 200. Used by Docker healthcheck and any uptime monitor you point at the deployment.

### `POST /api/scan`

Submit a scan. Rate-limited to **3 requests/minute per IP**.

Request body ([api_gateway/app/models.py](../../api_gateway/app/models.py)):
```json
{
  "github_url": "https://github.com/owner/repo",
  "github_pat": "ghp_...",                  // optional, only for private repos
  "provider": "claude",                      // or "azure"
  "credentials": {
    "api_key": "sk-ant-...",
    "model": "claude-sonnet-4-6"             // optional
  }
}
```

For Azure, `credentials` is:
```json
{
  "api_key": "...",
  "endpoint": "https://my-resource.openai.azure.com/",
  "deployment": "gpt-4o",
  "api_version": "2024-08-01-preview",       // optional
  "embedding_deployment": "text-embedding-3-small"  // optional
}
```

Unknown fields anywhere in the body are **rejected** (`extra="forbid"` on every Pydantic model) so clients can't sneak extras through to internal agents.

Response (HTTP 200):
```json
{
  "job_id": "abc...",                        // 16 url-safe chars
  "events_url": "/api/scan/abc.../events",
  "download_url": "/api/download/abc..."
}
```

Errors:
| Status | Cause |
|---|---|
| 400 | Validation failure (bad URL, malformed key, missing field). Body: `{"error": "..."}`. |
| 422 | Pydantic schema mismatch (wrong types, extra fields). FastAPI's default body. |
| 429 | Rate limit exceeded. Body: `{"error": "rate limit exceeded: 3 per 1 minute"}`. |

The job kicks off **synchronously inside the request handler** (clones the repo, then the orchestrator stream runs as an `asyncio` task), so a 200 means the scan has started.

### `GET /api/scan/{job_id}/events`

Server-Sent Events stream of pipeline progress for the given job. Open with the browser's `EventSource` API or `curl -N`.

Event types:

| `event:` | `data:` shape | When |
|---|---|---|
| `stage` | `{"stage": "...", "status": "started\|completed", "ts": "...", "detail": {...}}` | Each pipeline stage starts and finishes. Stages: `clone`, `scanner`, `inventory`, `threat_model`, `executive_summary`. |
| `complete` | `{"download_url": "/api/download/{job_id}"}` | The scan finished successfully. The full bundle is now available at `download_url`. The connection closes after this. |
| `error` | `{"message": "..."}` | The scan failed. Connection closes. |

Keepalive comments (`: keep-alive\n\n`) are sent every 30 seconds so proxies don't time the connection out. The browser EventSource ignores these.

If the api-gateway instance dies or your client disconnects, you can reconnect with the same `job_id` and resume from where you left off — events are buffered in the in-memory `JobRegistry` ([jobs.py](../../api_gateway/app/jobs.py)) for up to 1 hour.

### `GET /api/download/{job_id}`

Returns the final scan bundle as a JSON file download (`Content-Disposition: attachment; filename="compass-threat-model-{job_id}.json"`).

Returns:
- 200 + the bundle JSON if the scan succeeded.
- 404 if the `job_id` doesn't exist (either never created or evicted from the registry after 1h).
- 409 if the scan exists but isn't complete yet, with body `{"detail": "bundle not ready (status=running)"}`.

The bundle schema is documented in [docs/use-it.md#read-the-report](../use-it.md#read-the-report). Top-level keys: `compass_version`, `report_type`, `generated_at`, `target`, `scanner`, `inventory`, `threat_model`, `executive_summary`.

---

## orchestrator (`:8093`)

Internal. Called only by the api-gateway.

### `GET /health`

`{"status": "healthy", "agent": "orchestrator"}`.

### `POST /run`

Synchronous pipeline run. Blocks until all 4 stages complete, then returns the bundle inline.

Request:
```json
{
  "folder_path": "/workspace/<job_id>/repo",
  "credentials": { "provider": "claude", "api_key": "...", ... }
}
```

Response on success:
```json
{ "status": "success", "bundle": { ... full report ... } }
```

On failure: `{"status": "error", "agent": "orchestrator", "error": "..."}` with HTTP 502 (downstream agent failure) or 500 (internal).

### `POST /run/stream`

Same input as `/run`, but returns a `text/event-stream` response. This is what the api-gateway calls. Emits the same `stage` / `complete` / `error` events that the api-gateway forwards onto the browser.

The orchestrator's worker runs in a thread; the SSE response stays open for the duration of the scan. `concurrency=1` on this service so each scan owns its own instance.

---

## scanner-agent (`:8090`)

Internal. Called only by the orchestrator.

### `GET /health` → `{"status": "healthy", "agent": "security_scanner"}`

### `POST /run`

Request:
```json
{
  "folder_path": "/workspace/<job_id>/repo",   // optional, falls back to SCAN_FOLDER_PATH env
  "credentials": { ... }                        // optional, falls back to env (see env-vars.md)
}
```

Response on success:
```json
{
  "status": "success",
  "agent": "security_scanner",
  "scanner_findings": {
    "metadata": { "total_findings": 45, "tool_distribution": {...} },
    "FND-TI-1": { "finding": {...}, "mitre_analysis": {...} },
    "FND-S-1":  { "finding": {...}, "mitre_analysis": {...} },
    ...
  }
}
```

Each `FND-*` key is one deduplicated finding with its mapped MITRE ATT&CK technique, adjusted severity, and rationale. The prefix encodes the source tool (`TI` = Trivy IaC, `S` = Semgrep, `B` = Bandit, etc.).

Failures return HTTP 400 (bad credentials shape) or 500 (internal). Body always includes `error` and `agent`.

---

## inventory-agent (`:8091`)

Internal. Same shape as scanner.

### `POST /run`

Request:
```json
{
  "folder_path": "/workspace/<job_id>/repo",   // optional
  "scanner_findings": { ... },                  // optional, used to cross-ref SCA vulns into SBOM
  "credentials": { ... }                        // optional
}
```

Response:
```json
{
  "status": "success",
  "agent": "inventory",
  "inventory": {
    "compass_version": "2.0",
    "sbom":            { "format": "spdx-json", "total_packages": 187, "packages": [...] },
    "architecture":    { ... },
    "data_flow":       { ... },
    "asset_inventory": { "total_assets": 32, "by_category": {...} }
  }
}
```

---

## threat-model-agent (`:8092`)

Internal. Reads no filesystem — consumes scanner + inventory JSON in the request body.

### `POST /run`

Request:
```json
{
  "scanner_findings": { ... },
  "inventory": { ... },
  "credentials": { ... }
}
```

Response:
```json
{
  "status": "success",
  "agent": "threat_model",
  "threat_model": {
    "summary": { "total_threats": 23, "critical_risks": 4, "overall_risk_score": 7.3 },
    "risk_analysis":     { "risk_level": "HIGH", "critical_priorities": [...], "quick_wins": [...] },
    "attack_scenarios":  [ { ... } ],
    "stride":            { "spoofing": [...], "tampering": [...], ... }
  }
}
```

---

## mitre-mcp (`:8000`) and syft-mcp (`:8080`)

These are MCP servers, not REST APIs. Their tools are documented in [reference/mcp-servers.md](mcp-servers.md).

---

## Conventions

Some patterns that hold across every endpoint:

- **All agents use `POST /run`** with a JSON body. No path parameters, no query strings — just one entry point per agent.
- **All agents return** `{"status": "success" | "error", "agent": "...", "<result_key>": {...}}`. The orchestrator inspects `status` to decide whether to continue the pipeline.
- **All agents have `GET /health`** returning `{"status": "healthy", "agent": "..."}`. Used by Docker healthchecks and Cloud Run startup probes.
- **Credentials always travel in the request body**, never headers, never query strings, never env vars (in normal operation). See [security.md](../security.md).
- **On Cloud Run**, every internal POST carries `Authorization: Bearer <google_id_token>` via [shared/cloud_auth.py](../../shared/cloud_auth.py). Locally the headers are empty and authentication is "trust the Docker network".
- **Unknown fields are rejected** by every Pydantic model. Don't try to sneak extra keys through; add them properly to the agent's request schema.
