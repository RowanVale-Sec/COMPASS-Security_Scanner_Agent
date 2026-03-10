#!/usr/bin/env python3
"""
COMPASS Inventory Agent
Generates detailed SBOM, discovers application architecture, maps data flows,
and builds a consolidated asset inventory.

Outputs: SBOM (with PURL, CPE, vulnerability mapping), architecture model,
data flow diagram, and unified asset registry.
"""

import os
import sys
import json
import asyncio
from datetime import datetime
from typing import Annotated
from pydantic import Field
from flask import Flask, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.base_agent import (
    create_chat_client, get_scan_folder, get_s3_bucket,
    get_deployment_name, ServiceResponseException
)
from shared.s3_helpers import upload_json_to_s3

from agents.inventory.tools.sbom_generator import generate_enhanced_sbom
from agents.inventory.tools.architecture_analyzer import analyze_architecture
from agents.inventory.tools.dataflow_analyzer import analyze_data_flows
from agents.inventory.tools.asset_builder import build_asset_inventory


def upload_inventory_to_s3(
    sbom_json: Annotated[str, Field(description="JSON string returned by generate_enhanced_sbom")],
    architecture_json: Annotated[str, Field(description="JSON string returned by analyze_architecture")],
    dfd_json: Annotated[str, Field(description="JSON string returned by analyze_data_flows")],
    asset_inventory_json: Annotated[str, Field(description="JSON string returned by build_asset_inventory")]
) -> str:
    """
    Consolidate all inventory data and upload to S3.

    Combines SBOM, architecture, data flow, and asset inventory into a single
    structured output following the COMPASS Inventory schema.

    Returns: S3 location of the uploaded inventory.
    """
    print("[Upload] Consolidating inventory data for S3 upload")

    try:
        sbom = json.loads(sbom_json)
    except json.JSONDecodeError:
        sbom = {}

    try:
        architecture = json.loads(architecture_json)
    except json.JSONDecodeError:
        architecture = {}

    try:
        dfd = json.loads(dfd_json)
    except json.JSONDecodeError:
        dfd = {}

    try:
        assets = json.loads(asset_inventory_json)
    except json.JSONDecodeError:
        assets = {}

    inventory_output = {
        "compass_version": "2.0",
        "agent": "inventory",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "scan_folder": get_scan_folder(),
        "sbom": sbom,
        "architecture": architecture,
        "data_flow": dfd,
        "asset_inventory": assets
    }

    s3_location = upload_json_to_s3(inventory_output, "inventory")
    print(f"[Upload] Inventory uploaded to {s3_location}")
    return s3_location


async def run_inventory_workflow(
    folder_path: str = None,
    scanner_s3_location: str = None
):
    """Execute the complete inventory analysis workflow."""
    folder_path = folder_path or get_scan_folder()

    print("=" * 80)
    print("COMPASS INVENTORY AGENT")
    print("=" * 80)
    print(f"Target Folder: {folder_path}")
    if scanner_s3_location:
        print(f"Scanner Results: {scanner_s3_location}")
    print("=" * 80)

    chat_client = create_chat_client()

    scanner_context = ""
    if scanner_s3_location:
        scanner_context = f"""
You also have Scanner Agent SCA results available at: {scanner_s3_location}
Pass this to generate_enhanced_sbom as the scanner_s3_location parameter
to cross-reference vulnerability data with the SBOM."""

    agent = chat_client.create_agent(
        instructions=f"""You are an application inventory analyst. Your job is to comprehensively
catalog all assets, understand the architecture, and map data flows for a codebase.

Follow this EXACT workflow:

STEP 1: GENERATE ENHANCED SBOM
Call generate_enhanced_sbom("{folder_path}"{', "' + scanner_s3_location + '"' if scanner_s3_location else ''})
This will generate a Software Bill of Materials with package details including
PURL identifiers, CPE, licenses, and known vulnerabilities.

STEP 2: ANALYZE ARCHITECTURE
Call analyze_architecture("{folder_path}")
This will discover the application architecture: components, services,
databases, communication patterns, and deployment topology.

STEP 3: ANALYZE DATA FLOWS
Call analyze_data_flows("{folder_path}", architecture_json)
Pass the architecture JSON from Step 2. This will generate a Data Flow Diagram
with trust boundaries, data flows, entry points, and data stores.

STEP 4: BUILD ASSET INVENTORY
Call build_asset_inventory(sbom_json, architecture_json, dfd_json)
Pass all three JSON outputs from previous steps. This consolidates everything
into a unified asset registry.

STEP 5: UPLOAD TO S3
Call upload_inventory_to_s3(sbom_json, architecture_json, dfd_json, asset_inventory_json)
Pass all four JSON outputs. This uploads the complete inventory to S3.

Report the S3 location when complete.
{scanner_context}

IMPORTANT: Execute steps in order. Each step depends on previous results.""",
        tools=[
            generate_enhanced_sbom,
            analyze_architecture,
            analyze_data_flows,
            build_asset_inventory,
            upload_inventory_to_s3
        ]
    )

    print("\nAgent analyzing codebase...\n")

    try:
        result = await agent.run(
            f"Analyze the codebase at {folder_path}. Generate SBOM, discover architecture, "
            f"map data flows, build asset inventory, and upload to S3."
        )
    except ServiceResponseException as exc:
        message = str(exc)
        if "DeploymentNotFound" in message:
            raise RuntimeError(
                f"Azure OpenAI deployment '{get_deployment_name()}' not found."
            ) from exc
        raise

    print("\n" + "=" * 80)
    print("INVENTORY AGENT COMPLETED")
    print("=" * 80)
    print(result.text)
    print("=" * 80)

    return result.text


# ============================================================================
# HTTP API for Orchestrator Integration
# ============================================================================

app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "agent": "inventory"})


@app.route('/run', methods=['POST'])
def run():
    data = request.json or {}
    folder_path = data.get('folder_path', get_scan_folder())
    scanner_s3_location = data.get('scanner_s3_location')

    try:
        result = asyncio.run(run_inventory_workflow(folder_path, scanner_s3_location))
        return jsonify({
            "status": "success",
            "agent": "inventory",
            "result": result
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
        scanner_loc = os.environ.get('SCANNER_S3_LOCATION')
        asyncio.run(run_inventory_workflow(scanner_s3_location=scanner_loc))
