#!/usr/bin/env python3
"""
COMPASS Security Scanner Agent
Enhanced multi-tool security scanning with AI deduplication and MITRE ATT&CK mapping.

Scan types: IaC (Checkov, Trivy), SAST (Bandit, Semgrep), SCA (Trivy),
            Secrets (Trivy), Container Image (Trivy)

Pipeline: Scan -> Aggregate -> Deduplicate -> MITRE Map -> return JSON inline.
"""

import os
import re as _re
import sys
import asyncio
import traceback
from pathlib import Path as _Path
from typing import Annotated
from pydantic import Field
from flask import Flask, request, jsonify

# Add project root to path for shared imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.base_agent import get_scan_folder
from shared.llm_provider import ProviderCredentials, get_provider, use_credentials
from shared.local_store import load_json, run_scope

try:
    from agent_framework.exceptions import ServiceResponseException
except ImportError:
    ServiceResponseException = Exception

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
from agents.scanner.pipeline.deduplicator import deduplicate_findings
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

_PATH_RE = _re.compile(r"(?:[A-Za-z]:[\\/]|/)[^\s'\"<>|]+mitre-mapped-findings[^\s'\"<>|]+\.json")


def _extract_final_path(agent_output: str) -> str:
    """Pull the mitre-mapped JSON path out of the agent's free-form final message."""
    match = _PATH_RE.search(agent_output or "")
    if not match:
        raise RuntimeError(
            "Agent finished without reporting a mitre-mapped findings path"
        )
    return match.group(0).rstrip('.,`*|')


async def run_scanner_workflow(folder_path: str) -> dict:
    """Execute the complete security scanning workflow and return the MITRE-mapped
    findings as a dict. Caller is responsible for `use_credentials` and `run_scope`.
    """
    print("=" * 80)
    print("COMPASS SECURITY SCANNER AGENT")
    print("=" * 80)
    print(f"Target Folder: {folder_path}")
    print("=" * 80)

    provider = get_provider()

    agent = provider.create_agent(
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
This will load findings, normalize each via LLM, and write the aggregated JSON to a local file.

STEP 3: DEDUPLICATE
Remove duplicate findings using semantic embeddings:
- deduplicated_path = deduplicate_findings(aggregated_path)

STEP 4: MITRE ATT&CK THREAT INTELLIGENCE
Analyze findings with MITRE ATT&CK framework:
- mitre_path = analyze_findings_with_mitre(deduplicated_path)

STEP 5: REPORT
Report the final local file path to the MITRE-mapped findings. The path will
contain 'mitre-mapped-findings' — include it verbatim in your final message.

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
            deduplicate_findings,
            analyze_findings_with_mitre
        ]
    )

    print("\nAgent analyzing repository...\n")

    try:
        result = await agent.run(
            f"Scan {folder_path} for security issues. Run all available scan tools, "
            f"aggregate results, deduplicate, and map to MITRE ATT&CK. "
            f"Report the local file path of the final MITRE-mapped findings."
        )
    except ServiceResponseException as exc:
        message = str(exc)
        if "DeploymentNotFound" in message:
            raise RuntimeError(
                "Azure OpenAI deployment not found. "
                "Verify AZURE_OPENAI_CHAT_DEPLOYMENT_NAME is set correctly."
            ) from exc
        raise

    print("\n" + "=" * 80)
    print("SCANNER AGENT COMPLETED")
    print("=" * 80)
    print(result.text)
    print("=" * 80)

    final_path = _extract_final_path(result.text)
    return load_json(final_path)


# ============================================================================
# HTTP API for Orchestrator Integration
# ============================================================================

app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "agent": "security_scanner"})


@app.route('/run', methods=['POST'])
def run():
    """Run the scanner agent.

    Request body:
      {
        "folder_path": "/workspace/<job_id>",  # optional, defaults to SCAN_FOLDER_PATH
        "credentials": { "provider": "...", "api_key": "...", ... }  # optional
      }

    Response body on success:
      {
        "status": "success",
        "agent": "security_scanner",
        "scanner_findings": { ... MITRE-mapped findings JSON ... }
      }
    """
    data = request.json or {}
    folder_path = data.get('folder_path') or get_scan_folder()
    creds_data = data.get('credentials')

    try:
        creds = ProviderCredentials.from_dict(creds_data) if creds_data else None
    except ValueError as e:
        return jsonify({"status": "error", "agent": "security_scanner", "error": str(e)}), 400

    print(f"[Scanner] /run creds_provider={creds.provider if creds else 'NONE'} folder={folder_path}", flush=True)
    try:
        with run_scope():
            with use_credentials(creds):
                findings = asyncio.run(run_scanner_workflow(folder_path))
        return jsonify({
            "status": "success",
            "agent": "security_scanner",
            "scanner_findings": findings,
        })
    except Exception as e:
        print("[Scanner] /run failed:", file=sys.stderr, flush=True)
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "agent": "security_scanner",
            "error": f"{type(e).__name__}: {e}",
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
        with run_scope():
            asyncio.run(run_scanner_workflow(get_scan_folder()))
