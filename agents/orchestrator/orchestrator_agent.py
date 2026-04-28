#!/usr/bin/env python3
"""
COMPASS Orchestrator Agent
Coordinates the full security analysis pipeline:
Scanner Agent -> Inventory Agent -> Threat Model Agent -> Executive Summary.

Each agent is invoked via its HTTP `/run` endpoint and returns its output JSON
inline in the response body. The orchestrator holds intermediate results in
memory (no S3), emits SSE stage events so the API gateway can stream progress
to the browser, and exposes a plain `POST /run` that returns the final bundle
for non-streaming callers.
"""

import os
import sys
import json
import queue
import uuid
import threading
from datetime import datetime
from typing import Any, Dict, Iterator, Optional

import requests
from flask import Flask, Response, request as flask_request, jsonify, stream_with_context

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.base_agent import get_scan_folder
from shared.cloud_auth import auth_headers
from shared.llm_provider import ProviderCredentials, get_provider, use_credentials

try:
    from agent_framework.exceptions import ServiceResponseException
except ImportError:
    ServiceResponseException = Exception


EXECUTIVE_SUMMARY_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {
            "type": "string",
            "description": "2-3 paragraph summary for leadership",
        },
        "key_metrics": {
            "type": "object",
            "description": "Key metrics synthesized from the pipeline outputs",
        },
        "top_3_actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "The top three recommended actions",
        },
        "risk_posture": {
            "type": "string",
            "description": "Overall risk posture assessment",
        },
    },
    "required": ["executive_summary", "key_metrics", "top_3_actions", "risk_posture"],
}


SCANNER_URL = os.environ.get('SCANNER_URL', 'http://scanner-agent:8090')
INVENTORY_URL = os.environ.get('INVENTORY_URL', 'http://inventory-agent:8091')
THREAT_MODEL_URL = os.environ.get('THREAT_MODEL_URL', 'http://threat-model-agent:8092')

SCANNER_TIMEOUT_S = int(os.environ.get('SCANNER_TIMEOUT_S', '1800'))
INVENTORY_TIMEOUT_S = int(os.environ.get('INVENTORY_TIMEOUT_S', '900'))
THREAT_MODEL_TIMEOUT_S = int(os.environ.get('THREAT_MODEL_TIMEOUT_S', '900'))


class PipelineError(RuntimeError):
    """Raised when a downstream agent returns a non-success response."""


def _post_agent(
    url: str,
    payload: Dict[str, Any],
    timeout: int,
    result_key: str,
    agent_label: str,
) -> Dict[str, Any]:
    """POST to an agent's /run, return the inline JSON under `result_key`.

    Raises PipelineError on any failure. Credentials in `payload` are never
    logged — only the non-credential keys are echoed for debugging.
    """
    echo_keys = sorted(k for k in payload.keys() if k != 'credentials')
    print(f"[Orchestrator] -> {agent_label} {url} (keys: {echo_keys})")

    try:
        response = requests.post(
            f"{url}/run",
            json=payload,
            timeout=timeout,
            headers=auth_headers(url),
        )
    except requests.exceptions.ConnectionError as exc:
        raise PipelineError(f"Cannot connect to {agent_label} at {url}: {exc}") from exc
    except requests.exceptions.Timeout as exc:
        raise PipelineError(f"{agent_label} timed out after {timeout}s") from exc

    try:
        body = response.json()
    except ValueError as exc:
        raise PipelineError(
            f"{agent_label} returned non-JSON (HTTP {response.status_code})"
        ) from exc

    if response.status_code >= 400 or body.get('status') != 'success':
        err = body.get('error') or body.get('message') or f"HTTP {response.status_code}"
        raise PipelineError(f"{agent_label} error: {err}")

    payload_out = body.get(result_key)
    if not isinstance(payload_out, dict):
        raise PipelineError(f"{agent_label} response missing '{result_key}' object")
    return payload_out


async def _generate_executive_summary(
    scanner_data: Dict[str, Any],
    inventory_data: Dict[str, Any],
    threat_model_data: Dict[str, Any],
) -> Dict[str, Any]:
    """Generate the executive summary from the three in-memory results.

    Uses whatever provider is currently active (set by the caller via
    `use_credentials`), falling back to env vars if none is active.
    """
    provider = get_provider()

    scanner_meta = scanner_data.get('metadata', {})
    tm_summary = threat_model_data.get('summary', {})
    risk = threat_model_data.get('risk_analysis', {})
    inventory_assets = inventory_data.get('asset_inventory', {})
    sbom = inventory_data.get('sbom', {})

    prompt = f"""Generate a concise executive security summary:

**Scanner Results:**
- Total findings: {scanner_meta.get('total_findings', 'N/A')}
- Tool distribution: {scanner_meta.get('tool_distribution', {})}

**Inventory:**
- Total assets: {inventory_assets.get('total_assets', 'N/A')}
- Asset categories: {inventory_assets.get('by_category', {})}
- SBOM packages: {sbom.get('total_packages', 'N/A')}

**Threat Model:**
- Total threats: {tm_summary.get('total_threats', 'N/A')}
- Attack scenarios: {tm_summary.get('attack_scenarios_count', 'N/A')}
- Critical risks: {tm_summary.get('critical_risks', 'N/A')}
- High risks: {tm_summary.get('high_risks', 'N/A')}
- Overall risk score: {tm_summary.get('overall_risk_score', 'N/A')}/10

**Risk Analysis:**
- Risk level: {risk.get('risk_level', 'N/A')}
- Critical priorities: {len(risk.get('critical_priorities', []))}
- Quick wins: {len(risk.get('quick_wins', []))}

Generate JSON with:
{{
  "executive_summary": "2-3 paragraph summary for leadership",
  "key_metrics": {{...}},
  "top_3_actions": ["action1", "action2", "action3"],
  "risk_posture": "Overall assessment"
}}

Return ONLY valid JSON."""

    try:
        return await provider.structured_output(
            schema=EXECUTIVE_SUMMARY_SCHEMA,
            prompt=prompt,
            system="You are a CISO creating executive security summaries. Return only valid JSON.",
            temperature=0.3,
        )
    except Exception as e:
        return {
            "executive_summary": f"Summary generation failed: {e}",
            "key_metrics": {},
            "top_3_actions": [],
            "risk_posture": "UNKNOWN",
        }


def run_pipeline(
    folder_path: str,
    credentials: Optional[Dict[str, Any]],
    emit: Optional[callable] = None,
) -> Dict[str, Any]:
    """Run the full pipeline in-process. Returns the assembled bundle.

    `emit(stage, status, detail=None)` is called at stage boundaries so callers
    (e.g. the SSE endpoint) can stream progress. It is NEVER called with any
    credential material.
    """
    def e(stage: str, status: str, **detail: Any) -> None:
        if emit:
            try:
                emit(stage, status, detail or None)
            except Exception:
                # Never let a misbehaving emitter break the pipeline.
                pass

    print("=" * 80)
    print("COMPASS ORCHESTRATOR - Full Security Analysis Pipeline")
    print("=" * 80)
    print(f"Target: {folder_path}")
    print(f"Scanner: {SCANNER_URL}")
    print(f"Inventory: {INVENTORY_URL}")
    print(f"Threat Model: {THREAT_MODEL_URL}")
    print("=" * 80)

    # Validate credentials shape up front so we fail before any long-running call.
    creds_obj = None
    if credentials:
        try:
            creds_obj = ProviderCredentials.from_dict(credentials)
        except ValueError as exc:
            raise PipelineError(f"Invalid credentials: {exc}") from exc

    pipeline_started = datetime.utcnow().isoformat() + "Z"

    # ---- Scanner ----------------------------------------------------------
    e("scanner", "started")
    scanner_data = _post_agent(
        SCANNER_URL,
        {"folder_path": folder_path, "credentials": credentials} if credentials
        else {"folder_path": folder_path},
        SCANNER_TIMEOUT_S,
        result_key="scanner_findings",
        agent_label="Scanner",
    )
    scanner_findings_count = scanner_data.get('metadata', {}).get('total_findings', 0)
    e("scanner", "completed", findings=scanner_findings_count)

    # ---- Inventory --------------------------------------------------------
    e("inventory", "started")
    inventory_payload: Dict[str, Any] = {
        "folder_path": folder_path,
        "scanner_findings": scanner_data,
    }
    if credentials:
        inventory_payload["credentials"] = credentials
    inventory_data = _post_agent(
        INVENTORY_URL,
        inventory_payload,
        INVENTORY_TIMEOUT_S,
        result_key="inventory",
        agent_label="Inventory",
    )
    inventory_assets = inventory_data.get('asset_inventory', {}).get('total_assets', 0)
    e("inventory", "completed", total_assets=inventory_assets)

    # ---- Threat model -----------------------------------------------------
    e("threat_model", "started")
    tm_payload: Dict[str, Any] = {
        "scanner_findings": scanner_data,
        "inventory": inventory_data,
    }
    if credentials:
        tm_payload["credentials"] = credentials
    threat_model_data = _post_agent(
        THREAT_MODEL_URL,
        tm_payload,
        THREAT_MODEL_TIMEOUT_S,
        result_key="threat_model",
        agent_label="ThreatModel",
    )
    tm_score = threat_model_data.get('summary', {}).get('overall_risk_score', 'N/A')
    e("threat_model", "completed", overall_risk_score=tm_score)

    # ---- Executive summary (in-process, no HTTP) --------------------------
    import asyncio  # local import keeps top-level startup cheap
    e("executive_summary", "started")
    with use_credentials(creds_obj):
        summary = asyncio.run(
            _generate_executive_summary(scanner_data, inventory_data, threat_model_data)
        )
    e("executive_summary", "completed")

    bundle = {
        "compass_version": "2.0",
        "report_type": "compass_full_bundle",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "pipeline_started_at": pipeline_started,
        "target": folder_path,
        "scanner": scanner_data,
        "inventory": inventory_data,
        "threat_model": threat_model_data,
        "executive_summary": summary,
    }
    return bundle


# ============================================================================
# HTTP API
# ============================================================================

app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "agent": "orchestrator"})


@app.route('/run', methods=['POST'])
def run():
    """Non-streaming pipeline run.

    Request body:
      { "folder_path": "/workspace/<id>", "credentials": { ... } }

    Response body on success:
      { "status": "success", "bundle": { ... full report JSON ... } }
    """
    data = flask_request.json or {}
    folder_path = data.get('folder_path') or get_scan_folder()
    credentials = data.get('credentials')

    try:
        bundle = run_pipeline(folder_path, credentials)
        return jsonify({"status": "success", "bundle": bundle})
    except PipelineError as exc:
        return jsonify({"status": "error", "agent": "orchestrator", "error": str(exc)}), 502
    except Exception as exc:
        return jsonify({"status": "error", "agent": "orchestrator", "error": str(exc)}), 500


@app.route('/run/stream', methods=['POST'])
def run_stream():
    """Streaming pipeline run. Emits SSE stage events and a final `complete`
    event whose data contains the full bundle.
    """
    data = flask_request.json or {}
    folder_path = data.get('folder_path') or get_scan_folder()
    credentials = data.get('credentials')

    events: "queue.Queue[Optional[Dict[str, Any]]]" = queue.Queue(maxsize=128)

    def emit(stage: str, status: str, detail: Optional[Dict[str, Any]] = None) -> None:
        event = {"stage": stage, "status": status, "ts": datetime.utcnow().isoformat() + "Z"}
        if detail:
            event["detail"] = detail
        events.put({"event": "stage", "data": event})

    def worker() -> None:
        try:
            bundle = run_pipeline(folder_path, credentials, emit=emit)
            events.put({"event": "complete", "data": {"bundle": bundle}})
        except PipelineError as exc:
            events.put({"event": "error", "data": {"message": str(exc)}})
        except Exception as exc:
            events.put({"event": "error", "data": {"message": f"Orchestrator failure: {exc}"}})
        finally:
            events.put(None)  # sentinel

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    def sse_stream() -> Iterator[str]:
        while True:
            item = events.get()
            if item is None:
                break
            payload = json.dumps(item["data"])
            yield f"event: {item['event']}\ndata: {payload}\n\n"

    return Response(
        stream_with_context(sse_stream()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
        },
    )


if __name__ == "__main__":
    mode = os.environ.get('COMPASS_MODE', 'agent')

    if mode == 'server':
        port = int(os.environ.get('ORCHESTRATOR_PORT', '8093'))
        print(f"Starting Orchestrator HTTP server on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
    else:
        bundle = run_pipeline(get_scan_folder(), None)
        print(json.dumps(bundle, indent=2))
