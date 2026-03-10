#!/usr/bin/env python3
"""
COMPASS Security Scanner Agent
Enhanced multi-tool security scanning with AI deduplication and MITRE ATT&CK mapping.

Scan types: IaC (Checkov, Trivy), SAST (Bandit, Semgrep), SCA (Trivy),
            Secrets (Trivy), Container Image (Trivy)

Pipeline: Scan -> Aggregate -> Deduplicate -> MITRE Map -> S3
"""

import os
import re as _re
import sys
import json
import asyncio
import threading
from pathlib import Path as _Path
from typing import Annotated
from pydantic import Field
from flask import Flask, request, jsonify

# Add project root to path for shared imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.base_agent import (
    create_chat_client, get_scan_folder, get_s3_bucket,
    get_azure_endpoint, get_deployment_name, get_azure_api_key,
    ServiceResponseException
)

# Import scan tools
from agents.scanner.tools.checkov import scan_with_checkov
from agents.scanner.tools.trivy_iac import scan_iac_with_trivy
from agents.scanner.tools.bandit import scan_python_code_with_bandit
from agents.scanner.tools.semgrep import scan_code_with_semgrep
from agents.scanner.tools.trivy_sca import scan_dependencies_with_trivy
from agents.scanner.tools.trivy_secret import scan_secrets_with_trivy
from agents.scanner.tools.trivy_image import scan_container_image_with_trivy

# Import pipeline stages
from agents.scanner.pipeline.aggregator import aggregate_scan_results
from agents.scanner.pipeline.deduplicator import deduplicate_findings_from_s3
from agents.scanner.pipeline.mitre_mapper import analyze_findings_with_mitre


# ============================================================================
# Helper Tool — Dockerfile Base Image Discovery
# ============================================================================

def find_docker_base_images(
    folder_path: Annotated[str, Field(description="Path to search recursively for Dockerfiles")]
) -> list:
    """
    Find all Dockerfiles in a folder and extract their FROM base image references.

    Returns a list of dicts, each with:
      - dockerfile: path to the Dockerfile
      - base_images: list of image references from FROM lines

    Use this before calling scan_container_image_with_trivy so the image name
    is known rather than guessed.
    """
    results = []
    for df in list(_Path(folder_path).rglob("Dockerfile")) + \
              list(_Path(folder_path).rglob("Dockerfile.*")):
        try:
            images = [
                m.group(1)
                for line in df.read_text(errors='replace').splitlines()
                if (m := _re.match(r'^FROM\s+(\S+)', line.strip(), _re.IGNORECASE))
                and not m.group(1).startswith('$')
                and m.group(1).lower() != 'scratch'
            ]
            if images:
                results.append({"dockerfile": str(df), "base_images": images})
        except OSError:
            pass

    total_images = sum(len(r['base_images']) for r in results)
    print(f"[Tool] Found {total_images} base images across {len(results)} Dockerfiles")
    return results


# ============================================================================
# Agent Setup
# ============================================================================

async def run_scanner_workflow(folder_path: str = None, s3_bucket: str = None):
    """Execute the complete security scanning workflow."""
    folder_path = folder_path or get_scan_folder()
    s3_bucket = s3_bucket or get_s3_bucket()

    print("=" * 80)
    print("COMPASS SECURITY SCANNER AGENT")
    print("=" * 80)
    print(f"Target Folder: {folder_path}")
    print(f"S3 Bucket: {s3_bucket}")
    print("=" * 80)

    chat_client = create_chat_client()

    agent = chat_client.create_agent(
        instructions=f"""You are a security scanning orchestrator with MITRE ATT&CK threat intelligence.
Follow this EXACT workflow:

STEP 1: SCAN PHASE
Run these security tools on {folder_path}:
- checkov_result = scan_with_checkov("{folder_path}")
- trivy_iac_result = scan_iac_with_trivy("{folder_path}")
- bandit_result = scan_python_code_with_bandit("{folder_path}")
- semgrep_result = scan_code_with_semgrep("{folder_path}")
- trivy_sca_result = scan_dependencies_with_trivy("{folder_path}")
- trivy_secret_result = scan_secrets_with_trivy("{folder_path}")

For container image scanning:
- docker_images = find_docker_base_images("{folder_path}")
  For each base_image in the returned list, call:
  - trivy_image_result = scan_container_image_with_trivy("<base_image>")

Each tool saves findings to a file and returns metadata with tool name, findings_file path, and finding_count.

STEP 2: AGGREGATE & CONSOLIDATE
Collect all scan results into a JSON array and call aggregate_scan_results.
Pass the results as a JSON string array of the metadata dicts from all tools that produced findings.
This will load findings, normalize each via LLM, and upload to S3.

STEP 3: DEDUPLICATE
Remove duplicate findings using semantic embeddings:
- deduplicated_location = deduplicate_findings_from_s3(s3_location)

STEP 4: MITRE ATT&CK THREAT INTELLIGENCE
Analyze findings with MITRE ATT&CK framework:
- mitre_location = analyze_findings_with_mitre(deduplicated_location)

STEP 5: REPORT
Report the final S3 locations for all pipeline stages.

IMPORTANT:
- Run ALL scan tools first, then aggregate ALL results together.
- Skip tools that error out but continue with remaining tools.
- Include scan results from tools that found 0 findings in the aggregation (they may still have useful metadata).""",
        tools=[
            scan_with_checkov,
            scan_iac_with_trivy,
            scan_python_code_with_bandit,
            scan_code_with_semgrep,
            scan_dependencies_with_trivy,
            scan_secrets_with_trivy,
            find_docker_base_images,
            scan_container_image_with_trivy,
            aggregate_scan_results,
            deduplicate_findings_from_s3,
            analyze_findings_with_mitre
        ]
    )

    print("\nAgent analyzing repository...\n")

    try:
        result = await agent.run(
            f"Scan {folder_path} for security issues. Run all available scan tools, "
            f"aggregate results, deduplicate, and map to MITRE ATT&CK. "
            f"Upload all results to S3 bucket {s3_bucket}."
        )
    except ServiceResponseException as exc:
        message = str(exc)
        if "DeploymentNotFound" in message:
            raise RuntimeError(
                f"Azure OpenAI deployment '{get_deployment_name()}' not found. "
                "Verify AZURE_OPENAI_CHAT_DEPLOYMENT_NAME is set correctly."
            ) from exc
        raise

    print("\n" + "=" * 80)
    print("SCANNER AGENT COMPLETED")
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
    return jsonify({"status": "healthy", "agent": "security_scanner"})


@app.route('/run', methods=['POST'])
def run():
    """Run the scanner agent. Accepts optional folder_path and s3_bucket in request body."""
    data = request.json or {}
    folder_path = data.get('folder_path', get_scan_folder())
    s3_bucket = data.get('s3_bucket', get_s3_bucket())

    try:
        result = asyncio.run(run_scanner_workflow(folder_path, s3_bucket))
        return jsonify({
            "status": "success",
            "agent": "security_scanner",
            "result": result
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "agent": "security_scanner",
            "error": str(e)
        }), 500


# ============================================================================
# Entry Point
# ============================================================================

if __name__ == "__main__":
    mode = os.environ.get('COMPASS_MODE', 'agent')

    if mode == 'server':
        port = int(os.environ.get('SCANNER_PORT', '8090'))
        print(f"Starting Scanner Agent HTTP server on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        asyncio.run(run_scanner_workflow())
