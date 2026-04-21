#!/usr/bin/env python3
"""
COMPASS Orchestrator Agent
Coordinates the full security analysis pipeline:
Scanner Agent -> Inventory Agent -> Threat Model Agent -> Executive Summary

Each agent is invoked via HTTP API. The orchestrator manages data flow
between agents using S3 locations as the inter-agent communication mechanism.
"""

import os
import re
import sys
import json
import asyncio
import requests
from datetime import datetime
from typing import Annotated
from pydantic import Field
from flask import Flask, request as flask_request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.base_agent import get_scan_folder, get_s3_bucket
from shared.llm_provider import get_provider
from shared.s3_helpers import upload_json_to_s3, download_json_from_s3

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


# Agent endpoint URLs (configurable via environment)
SCANNER_URL = os.environ.get('SCANNER_URL', 'http://scanner-agent:8090')
INVENTORY_URL = os.environ.get('INVENTORY_URL', 'http://inventory-agent:8091')
THREAT_MODEL_URL = os.environ.get('THREAT_MODEL_URL', 'http://threat-model-agent:8092')


def _extract_s3_uri(text: str, prefer_keyword: str = None) -> str:
    """Extract an s3:// URI from an agent response string.

    If prefer_keyword is given, returns the first URI whose path contains
    that keyword (e.g. "mitre" to get the MITRE-mapped file rather than
    the intermediate aggregated file).  Falls back to the last URI found,
    then to the original text if no URI exists at all.

    Trailing markdown/punctuation characters (|, *, `, ., ,) are stripped.
    """
    uris = [m.group(0).rstrip('|*`.,') for m in re.finditer(r's3://[^\s\'"<>\]|*`]+', text)]
    if not uris:
        return text
    if prefer_keyword:
        for uri in uris:
            if prefer_keyword in uri:
                return uri
    return uris[-1]  # last URI is typically the final pipeline output


def run_scanner_agent(
    folder_path: Annotated[str, Field(description="Path to the codebase to scan")],
    s3_bucket: Annotated[str, Field(description="S3 bucket for results")]
) -> str:
    """
    Invoke the Security Scanner Agent via HTTP API.

    Runs all security scans (IaC, SAST, SCA, Secrets, Container Image),
    aggregates results, deduplicates, and maps to MITRE ATT&CK.

    Returns: S3 location of MITRE-mapped scan results, or error message.
    """
    print(f"[Orchestrator] Invoking Scanner Agent at {SCANNER_URL}")
    print(f"  Scan folder: {folder_path}")

    try:
        response = requests.post(
            f"{SCANNER_URL}/run",
            json={"folder_path": folder_path, "s3_bucket": s3_bucket},
            timeout=1800  # 30 min timeout for full scan pipeline
        )
        response.raise_for_status()
        result = response.json()

        if result.get('status') == 'success':
            agent_result = result.get('result', '')
            print(f"[Orchestrator] Scanner Agent completed successfully")
            return _extract_s3_uri(agent_result, prefer_keyword='mitre')
        else:
            error = result.get('error', 'Unknown error')
            print(f"[Orchestrator] Scanner Agent error: {error}")
            return f"Scanner error: {error}"

    except requests.exceptions.ConnectionError:
        return f"Error: Cannot connect to Scanner Agent at {SCANNER_URL}. Is it running?"
    except requests.exceptions.Timeout:
        return "Error: Scanner Agent timed out after 30 minutes"
    except Exception as e:
        return f"Error invoking Scanner Agent: {str(e)}"


def run_inventory_agent(
    folder_path: Annotated[str, Field(description="Path to the codebase to analyze")],
    scanner_s3_location: Annotated[str, Field(description="S3 location of Scanner Agent results for vulnerability cross-referencing")] = ""
) -> str:
    """
    Invoke the Inventory Agent via HTTP API.

    Generates SBOM, discovers architecture, maps data flows, and builds asset inventory.
    Optionally cross-references with Scanner SCA results.

    Returns: S3 location of inventory results, or error message.
    """
    print(f"[Orchestrator] Invoking Inventory Agent at {INVENTORY_URL}")

    payload = {"folder_path": folder_path}
    if scanner_s3_location:
        payload["scanner_s3_location"] = scanner_s3_location

    try:
        response = requests.post(
            f"{INVENTORY_URL}/run",
            json=payload,
            timeout=900  # 15 min timeout
        )
        response.raise_for_status()
        result = response.json()

        if result.get('status') == 'success':
            print(f"[Orchestrator] Inventory Agent completed successfully")
            return _extract_s3_uri(result.get('result', ''))
        else:
            error = result.get('error', 'Unknown error')
            print(f"[Orchestrator] Inventory Agent error: {error}")
            return f"Inventory error: {error}"

    except requests.exceptions.ConnectionError:
        return f"Error: Cannot connect to Inventory Agent at {INVENTORY_URL}. Is it running?"
    except Exception as e:
        return f"Error invoking Inventory Agent: {str(e)}"


def run_threat_model_agent(
    scanner_s3_location: Annotated[str, Field(description="S3 location of Scanner Agent MITRE-mapped results")],
    inventory_s3_location: Annotated[str, Field(description="S3 location of Inventory Agent results")]
) -> str:
    """
    Invoke the Threat Model Agent via HTTP API.

    Creates threat model by correlating scanner findings with architecture,
    generating attack scenarios, performing STRIDE analysis, and scoring risks.

    Returns: S3 location of threat model, or error message.
    """
    print(f"[Orchestrator] Invoking Threat Model Agent at {THREAT_MODEL_URL}")

    try:
        response = requests.post(
            f"{THREAT_MODEL_URL}/run",
            json={
                "scanner_s3_location": scanner_s3_location,
                "inventory_s3_location": inventory_s3_location
            },
            timeout=900
        )
        response.raise_for_status()
        result = response.json()

        if result.get('status') == 'success':
            print(f"[Orchestrator] Threat Model Agent completed successfully")
            return _extract_s3_uri(result.get('result', ''))
        else:
            error = result.get('error', 'Unknown error')
            print(f"[Orchestrator] Threat Model Agent error: {error}")
            return f"Threat model error: {error}"

    except requests.exceptions.ConnectionError:
        return f"Error: Cannot connect to Threat Model Agent at {THREAT_MODEL_URL}. Is it running?"
    except Exception as e:
        return f"Error invoking Threat Model Agent: {str(e)}"


async def generate_executive_summary(
    scanner_s3_location: Annotated[str, Field(description="S3 location of Scanner results")],
    inventory_s3_location: Annotated[str, Field(description="S3 location of Inventory results")],
    threat_model_s3_location: Annotated[str, Field(description="S3 location of Threat Model results")]
) -> str:
    """
    Generate a unified executive summary from all three agent outputs.

    Downloads all results from S3, synthesizes key findings via LLM,
    and uploads the executive summary to S3.

    Returns: S3 location of the executive summary.
    """
    print("[Orchestrator] Generating executive summary")

    try:
        scanner_data = download_json_from_s3(scanner_s3_location)
    except Exception as e:
        scanner_data = {"error": str(e)}

    try:
        inventory_data = download_json_from_s3(inventory_s3_location)
    except Exception as e:
        inventory_data = {"error": str(e)}

    try:
        threat_model_data = download_json_from_s3(threat_model_s3_location)
    except Exception as e:
        threat_model_data = {"error": str(e)}

    provider = get_provider()

    # Extract key metrics for summary
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
        summary_content = await provider.structured_output(
            schema=EXECUTIVE_SUMMARY_SCHEMA,
            prompt=prompt,
            system="You are a CISO creating executive security summaries. Return only valid JSON.",
            temperature=0.3,
        )
    except Exception as e:
        summary_content = {"executive_summary": f"Summary generation failed: {e}"}

    full_report = {
        "compass_version": "2.0",
        "report_type": "executive_summary",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "sources": {
            "scanner": scanner_s3_location,
            "inventory": inventory_s3_location,
            "threat_model": threat_model_s3_location
        },
        "summary": summary_content,
        "pipeline_status": {
            "scanner": "success" if "error" not in scanner_data else "error",
            "inventory": "success" if "error" not in inventory_data else "error",
            "threat_model": "success" if "error" not in threat_model_data else "error"
        }
    }

    s3_location = upload_json_to_s3(full_report, "executive-reports")
    print(f"[Orchestrator] Executive summary uploaded to {s3_location}")
    return s3_location


async def run_orchestrator_workflow(folder_path: str = None):
    """Execute the full COMPASS pipeline."""
    folder_path = folder_path or get_scan_folder()
    s3_bucket = get_s3_bucket()

    print("=" * 80)
    print("COMPASS ORCHESTRATOR - Full Security Analysis Pipeline")
    print("=" * 80)
    print(f"Target: {folder_path}")
    print(f"S3 Bucket: {s3_bucket}")
    print(f"Scanner: {SCANNER_URL}")
    print(f"Inventory: {INVENTORY_URL}")
    print(f"Threat Model: {THREAT_MODEL_URL}")
    print("=" * 80)

    provider = get_provider()

    agent = provider.create_agent(
        instructions=f"""You are the COMPASS pipeline orchestrator. Coordinate three agents
in sequence to perform a complete security analysis.

Pipeline: Scanner -> Inventory -> Threat Model -> Executive Summary

STEP 1: RUN SCANNER AGENT
Call run_scanner_agent("{folder_path}", "{s3_bucket}")
This runs all security scans and produces MITRE-mapped findings.
Extract the S3 location of the final MITRE-mapped results from the output.

STEP 2: RUN INVENTORY AGENT
Call run_inventory_agent("{folder_path}", scanner_s3_location)
Pass the scanner S3 location for vulnerability cross-referencing in SBOM.
Extract the S3 location from the output.

STEP 3: RUN THREAT MODEL AGENT
Call run_threat_model_agent(scanner_s3_location, inventory_s3_location)
This creates the threat model from real scan + inventory data.
Extract the S3 location from the output.

STEP 4: GENERATE EXECUTIVE SUMMARY
Call generate_executive_summary(scanner_s3_location, inventory_s3_location, threat_model_s3_location)
This produces the final unified executive report.

Report all S3 locations when complete.

IMPORTANT:
- If a step fails, log the error and continue with the next step where possible.
- The Threat Model Agent REQUIRES both Scanner and Inventory results.
- Extract S3 locations (s3://...) from each agent's response to pass to the next.""",
        tools=[
            run_scanner_agent,
            run_inventory_agent,
            run_threat_model_agent,
            generate_executive_summary
        ]
    )

    print("\nOrchestrator starting pipeline...\n")

    try:
        result = await agent.run(
            f"Run the complete COMPASS security analysis pipeline on {folder_path}."
        )
    except ServiceResponseException as exc:
        if "DeploymentNotFound" in str(exc):
            raise RuntimeError(
                f"Azure OpenAI deployment not found: {exc}"
            ) from exc
        raise

    print("\n" + "=" * 80)
    print("COMPASS PIPELINE COMPLETED")
    print("=" * 80)
    print(result.text)
    print("=" * 80)

    return result.text


# ============================================================================
# HTTP API (for external invocation)
# ============================================================================

app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "agent": "orchestrator"})


@app.route('/run', methods=['POST'])
def run():
    data = flask_request.json or {}
    folder_path = data.get('folder_path', get_scan_folder())

    try:
        result = asyncio.run(run_orchestrator_workflow(folder_path))
        return jsonify({
            "status": "success",
            "agent": "orchestrator",
            "result": result
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "agent": "orchestrator",
            "error": str(e)
        }), 500


if __name__ == "__main__":
    mode = os.environ.get('COMPASS_MODE', 'agent')

    if mode == 'server':
        port = int(os.environ.get('ORCHESTRATOR_PORT', '8093'))
        print(f"Starting Orchestrator HTTP server on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        asyncio.run(run_orchestrator_workflow())
