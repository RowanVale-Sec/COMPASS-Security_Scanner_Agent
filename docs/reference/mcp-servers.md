# MCP servers reference

COMPASS depends on two MCP servers for external knowledge:

| Server | Purpose | Protocol | Called by |
|---|---|---|---|
| `mitre-mcp` | MITRE ATT&CK technique catalog | MCP (streamable HTTP) | scanner-agent's MITRE mapper |
| `syft-mcp` | SBOM generation via the `syft` binary | Plain HTTP (Flask, not MCP despite the name) | inventory-agent's SBOM generator |

Both run as their own Cloud Run services (or docker-compose containers locally) and are reached via env-var URLs ([reference/env-vars.md](env-vars.md)).

---

## mitre-mcp

A FastMCP server wrapping the [Montimage/mitre-mcp](https://github.com/Montimage/mitre-mcp) project, which itself wraps the `mitreattack-python` library. The Dockerfile clones the upstream repo at build time and pins `REPO_VERSION`.

### Endpoint

| Setting | Value |
|---|---|
| URL | `http://mitre-mcp:8000/mcp` (local) / `https://compass-mitre-mcp-XXX.run.app/mcp` (cloud) |
| Transport | MCP Streamable HTTP |
| Env var pointing here | `MITRE_MCP_URL` |
| Connection helper | [shared/mcp_utils.py:mcp_session()](../../shared/mcp_utils.py) |

The `/mcp` path suffix is required — that's where FastMCP listens for JSON-RPC requests over the streamable-HTTP protocol.

### Tools COMPASS calls

Only one tool is used in the scan pipeline:

#### `get_techniques`

Returns ATT&CK techniques. Called once per scan to load the entire Enterprise catalog into memory ([mitre_mapper.py:145-185](../../agents/scanner/pipeline/mitre_mapper.py#L145-L185)).

Arguments:
```json
{
  "domain": "enterprise-attack",
  "include_descriptions": true,
  "limit": 500,
  "offset": 0
}
```

The mapper paginates until `pagination.has_more` is false (Montimage's server caps page size at 20 unless overridden). The 500-page-size + pagination-loop pattern works for both their default and our override.

Response shape (one of):
```json
// New servers
{
  "techniques": [
    { "mitre_id": "T1078", "name": "Valid Accounts", "description": "...", ... },
    ...
  ],
  "pagination": { "has_more": true, "offset": 500, "limit": 500 }
}

// Older servers
[ { "mitre_id": "T1078", ... }, ... ]
```

The mapper handles both. After loading, it does Python token-overlap shortlisting per finding to avoid sending the entire 600+ technique catalog into every LLM call.

### Other tools

The upstream Montimage server exposes additional tools (`get_tactics`, `get_groups`, `get_software`, etc.), but COMPASS doesn't currently use them. If you want richer threat-actor or campaign data in scans, those are the entry points to wire in.

### Calling pattern

```python
from shared.mcp_utils import mcp_session, call_tool_json
from shared.cloud_auth import auth_headers

url = "http://mitre-mcp:8000/mcp"
async with mcp_session(url, headers=auth_headers(url)) as session:
    payload = await call_tool_json(
        session,
        "get_techniques",
        {"domain": "enterprise-attack", "include_descriptions": True, "limit": 500, "offset": 0},
    )
```

`auth_headers(url)` returns `{"Authorization": "Bearer ..."}` on Cloud Run (S2S ID token) and `{}` locally. Same code works in both deployments.

---

## syft-mcp

Despite the name, **this is a plain Flask HTTP server**, not an MCP server. The "mcp" naming is historical from when the project was MCP-first; the syft wrapper ended up simpler as straight HTTP because Syft is a CLI tool, not a streaming knowledge source.

### Endpoints

All under `http://syft-mcp:8080/`. The `SYFT_MCP_URL` env var points here.

#### `GET /health`

`{"status": "healthy"}`. Used by Docker healthcheck and Cloud Run startup probe.

#### `GET /capabilities`

```json
{
  "tool": "syft",
  "version": "syft 1.x.x",
  "capabilities": [
    "sbom_generation",
    "dependency_detection",
    "license_detection",
    "purl_extraction",
    "cpe_extraction",
    "relationship_mapping",
    "container_image_sbom"
  ],
  "supported_languages": ["java", "python", "go", "javascript", "ruby", "php", "dotnet", "rust"]
}
```

Useful for self-discovery / debug. COMPASS doesn't currently call this.

#### `POST /analyze`

Generate an SBOM from a directory. The inventory agent's main consumer.

Request:
```json
{
  "repo_path": "/workspace/<job_id>/repo",
  "output_format": "spdx-json"
}
```

Response:
```json
{
  "status": "success",
  "tool": "syft",
  "result": {
    "sbom_file": "/tmp/sbom_<uuid>.spdx-json",
    "findings": [
      {
        "type": "dependency",
        "name": "requests",
        "version": "2.31.0",
        "license": "Apache-2.0",
        "purl": "pkg:pypi/requests@2.31.0",
        "cpe": "cpe:2.3:a:python:requests:2.31.0:...",
        "supplier": "...",
        "spdx_id": "SPDXRef-Package-...",
        "files_analyzed": true
      },
      ...
    ],
    "relationships": [ {"source": "...", "target": "...", "type": "DEPENDS_ON"}, ... ],
    "total_packages": 187,
    "sbom_format": "spdx-json",
    "sbom_raw": { /* full SPDX JSON */ }
  }
}
```

The `findings` array is the enriched view; `sbom_raw` is the raw SPDX document if you need the full schema. The inventory agent uses both — `findings` for the asset registry, `sbom_raw` for cross-referencing with the scanner's SCA results.

Errors: HTTP 500 with `{"status": "error", "message": "Syft analysis failed: ..."}` if the syft binary fails (e.g., unparseable manifest).

#### `POST /analyze-image`

Generate an SBOM from a container image reference (not a local directory).

Request:
```json
{
  "image_ref": "ubuntu:24.04"
}
```

COMPASS doesn't currently use this — the inventory agent works only on source code. It's available if you want to wire image scanning into a future agent.

### Calling pattern

```python
import requests
from shared.cloud_auth import auth_headers

syft_url = "http://syft-mcp:8080"
response = requests.post(
    f"{syft_url}/analyze",
    json={"repo_path": "/workspace/job_xyz/repo", "output_format": "spdx-json"},
    timeout=300,
    headers=auth_headers(syft_url),
)
```

Same `auth_headers()` pattern as MITRE — empty headers locally, Bearer token on Cloud Run.

---

## When you'd add another MCP server

The pattern is straightforward — MCP servers in COMPASS are just stateless HTTP services that any agent can call. To add one:

1. Create `mcp_servers/<name>/` with a Dockerfile + the server code.
2. Add it to [docker-compose.yml](../../docker-compose.yml) and to [infra/terraform/locals.tf](../../infra/terraform/locals.tf)'s services list.
3. Add a `module "cloud_run_<name>_mcp"` block in [services.tf](../../infra/terraform/services.tf), copying the existing MCP shape (Gen1, low resources, max-instances=5).
4. Add an invoker binding in [runtime_iam.tf](../../infra/terraform/runtime_iam.tf) granting the calling agent's runtime SA `roles/run.invoker` on the new service.
5. Add the discovery URL env var to whichever agent calls it ([reference/env-vars.md](env-vars.md)).

If it's a real MCP server (streamable-HTTP transport), use [shared/mcp_utils.mcp_session()](../../shared/mcp_utils.py) to call it. If it's plain HTTP like syft-mcp, just `requests.post()` with `auth_headers()`.

---

## Where to go next

- [understand-it.md](../understand-it.md) — how MITRE mapping fits in the scan pipeline
- [contribute.md](../contribute.md) — full walkthrough of adding a new agent (similar process for a new MCP)
- [shared/mcp_utils.py](../../shared/mcp_utils.py) — the session helper
- [agents/scanner/pipeline/mitre_mapper.py](../../agents/scanner/pipeline/mitre_mapper.py) — reference implementation of an MCP consumer
