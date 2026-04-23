#!/usr/bin/env python3
"""
COMPASS Inventory Agent
Generates detailed SBOM, discovers application architecture, maps data flows,
and builds a consolidated asset inventory.

Outputs: SBOM (with PURL, CPE, vulnerability mapping), architecture model,
data flow diagram, and unified asset registry.
"""

import inspect
import json
import os
import sys
import asyncio
from datetime import datetime
from typing import Annotated, Any, Dict, Optional
from pydantic import Field
from flask import Flask, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.base_agent import get_scan_folder
from shared.llm_provider import ProviderCredentials, use_credentials
from shared.local_store import run_scope, save_input_payload

from agents.inventory.tools.sbom_generator import generate_enhanced_sbom
from agents.inventory.tools.architecture_analyzer import analyze_architecture
from agents.inventory.tools.dataflow_analyzer import analyze_data_flows
from agents.inventory.tools.asset_builder import build_asset_inventory


def consolidate_inventory(
    sbom_json: Annotated[str, Field(description="JSON string returned by generate_enhanced_sbom")],
    architecture_json: Annotated[str, Field(description="JSON string returned by analyze_architecture")],
    dfd_json: Annotated[str, Field(description="JSON string returned by analyze_data_flows")],
    asset_inventory_json: Annotated[str, Field(description="JSON string returned by build_asset_inventory")]
) -> str:
    """
    Consolidate all inventory data into a single structured JSON object.

    Combines SBOM, architecture, data flow, and asset inventory into the unified
    COMPASS Inventory schema and returns it as a JSON string for the caller to
    return to the orchestrator.
    """
    print("[Consolidate] Building consolidated inventory JSON")

    def safe_parse(j):
        try:
            return json.loads(j)
        except (json.JSONDecodeError, TypeError):
            return {}

    inventory_output = {
        "compass_version": "2.0",
        "agent": "inventory",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "scan_folder": get_scan_folder(),
        "sbom": safe_parse(sbom_json),
        "architecture": safe_parse(architecture_json),
        "data_flow": safe_parse(dfd_json),
        "asset_inventory": safe_parse(asset_inventory_json),
    }

    return json.dumps(inventory_output)


async def run_inventory_workflow(
    folder_path: str,
    scanner_findings_path: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute the inventory analysis workflow deterministically.

    Each stage here returns a JSON STRING that the next stage consumes. Previous
    versions asked the LLM to chain these tool calls, but the LLM would not
    echo a multi-kilobyte JSON blob back verbatim (it would truncate it to
    "{}" or summarize), which caused the consolidated inventory to be empty
    even when every individual tool succeeded. The sequencing here is purely
    mechanical — no reasoning needed between steps — so we call the tools
    directly in Python. LLM calls still happen *inside* each tool where they
    genuinely add value (architecture discovery, etc.).
    """
    print("=" * 80)
    print("COMPASS INVENTORY AGENT")
    print("=" * 80)
    print(f"Target Folder: {folder_path}")
    if scanner_findings_path:
        print(f"Scanner findings (local): {scanner_findings_path}")
    print("=" * 80)

    # 1. SBOM (optionally cross-referenced with scanner SCA findings)
    sbom_json = generate_enhanced_sbom(folder_path, scanner_findings_path or "")

    # 2. Architecture
    maybe = analyze_architecture(folder_path)
    architecture_json = await maybe if inspect.iscoroutine(maybe) else maybe

    # 3. Data flow (consumes architecture)
    maybe = analyze_data_flows(folder_path, architecture_json)
    dfd_json = await maybe if inspect.iscoroutine(maybe) else maybe

    # 4. Asset inventory (consumes all three)
    maybe = build_asset_inventory(sbom_json, architecture_json, dfd_json)
    assets_json = await maybe if inspect.iscoroutine(maybe) else maybe

    # 5. Consolidate into the final JSON payload returned to the orchestrator
    consolidated_json = consolidate_inventory(sbom_json, architecture_json, dfd_json, assets_json)

    print("\n" + "=" * 80)
    print("INVENTORY AGENT COMPLETED")
    print("=" * 80)

    try:
        return json.loads(consolidated_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"consolidate_inventory returned invalid JSON: {exc}") from exc


# ============================================================================
# HTTP API for Orchestrator Integration
# ============================================================================

app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "agent": "inventory"})


@app.route('/run', methods=['POST'])
def run():
    """Run the inventory agent.

    Request body:
      {
        "folder_path": "/workspace/<job_id>",             # optional
        "scanner_findings": { ... scanner JSON ... },      # optional, for SCA cross-ref
        "credentials": { "provider": "...", ... }          # optional
      }
    """
    data = request.json or {}
    folder_path = data.get('folder_path') or get_scan_folder()
    scanner_findings = data.get('scanner_findings')
    creds_data = data.get('credentials')

    try:
        creds = ProviderCredentials.from_dict(creds_data) if creds_data else None
    except ValueError as e:
        return jsonify({"status": "error", "agent": "inventory", "error": str(e)}), 400

    try:
        with run_scope() as _root:
            scanner_path = None
            if isinstance(scanner_findings, dict) and scanner_findings:
                scanner_path = save_input_payload("scanner_findings", scanner_findings)
            with use_credentials(creds):
                inventory = asyncio.run(run_inventory_workflow(folder_path, scanner_path))
        return jsonify({
            "status": "success",
            "agent": "inventory",
            "inventory": inventory,
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "agent": "inventory",
            "error": str(e)
        }), 500


if __name__ == "__main__":
    mode = os.environ.get('COMPASS_MODE', 'agent')

    if mode == 'server':
        port = int(os.environ.get('INVENTORY_PORT', '8091'))
        print(f"Starting Inventory Agent HTTP server on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        with run_scope():
            asyncio.run(run_inventory_workflow(get_scan_folder()))
