#!/usr/bin/env python3
"""
COMPASS Threat Model Agent
Consumes Scanner Agent and Inventory Agent outputs to generate a comprehensive
threat model with attack scenarios, STRIDE analysis, and risk prioritization.

All threat analysis is grounded in REAL scan data and REAL architecture.
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

from shared.base_agent import get_s3_bucket
from shared.llm_provider import get_provider
from shared.s3_helpers import upload_json_to_s3

try:
    from agent_framework.exceptions import ServiceResponseException
except ImportError:
    ServiceResponseException = Exception

from agents.threat_model.tools.data_loader import load_scanner_results, load_inventory_results
from agents.threat_model.tools.vuln_correlator import correlate_vulnerabilities_with_architecture
from agents.threat_model.tools.scenario_generator import generate_attack_scenarios
from agents.threat_model.tools.stride_analyzer import perform_stride_analysis
from agents.threat_model.tools.risk_scorer import score_and_prioritize_risks


def upload_threat_model_to_s3(
    scanner_s3_location: Annotated[str, Field(description="S3 location of the scanner agent results (s3://bucket/key)")],
    inventory_s3_location: Annotated[str, Field(description="S3 location of the inventory agent results (s3://bucket/key)")],
    correlations_json: Annotated[str, Field(description="JSON string returned by correlate_vulnerabilities_with_architecture")],
    scenarios_json: Annotated[str, Field(description="JSON string returned by generate_attack_scenarios")],
    stride_json: Annotated[str, Field(description="JSON string returned by perform_stride_analysis")],
    risk_json: Annotated[str, Field(description="JSON string returned by score_and_prioritize_risks")]
) -> str:
    """
    Consolidate threat model data and upload to S3.

    Combines all threat analysis components into a single structured output
    following the COMPASS Threat Model schema.

    Returns: S3 location of the uploaded threat model.
    """
    print("[Upload] Consolidating threat model for S3 upload")

    def safe_parse(j):
        try:
            return json.loads(j)
        except (json.JSONDecodeError, TypeError):
            return {}

    correlations = safe_parse(correlations_json)
    scenarios = safe_parse(scenarios_json)
    stride = safe_parse(stride_json)
    risk = safe_parse(risk_json)

    threat_model = {
        "compass_version": "2.0",
        "agent": "threat_model",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "inputs": {
            "scanner_s3_location": scanner_s3_location,
            "inventory_s3_location": inventory_s3_location
        },
        "vulnerability_correlation": correlations.get('correlations', []),
        "correlation_summary": correlations.get('summary', {}),
        "attack_scenarios": scenarios.get('scenarios', []),
        "stride_analysis": {
            "threats": stride.get('threats', []),
            "by_category": stride.get('by_category', {}),
            "critical_threats": stride.get('critical_threats', []),
            "component_threat_map": stride.get('component_threat_map', {})
        },
        "risk_analysis": {
            "overall_risk_score": risk.get('overall_risk_score', 0),
            "risk_level": risk.get('risk_level', 'UNKNOWN'),
            "risk_justification": risk.get('risk_justification', ''),
            "critical_priorities": risk.get('critical_priorities', []),
            "quick_wins": risk.get('quick_wins', []),
            "strategic_improvements": risk.get('strategic_improvements', []),
            "compliance_gaps": risk.get('compliance_gaps', []),
            "risk_matrix": risk.get('risk_matrix', {})
        },
        "summary": {
            "total_threats": len(stride.get('threats', [])),
            "attack_scenarios_count": len(scenarios.get('scenarios', [])),
            "critical_risks": len([t for t in stride.get('threats', []) if t.get('severity') == 'CRITICAL']),
            "high_risks": len([t for t in stride.get('threats', []) if t.get('severity') == 'HIGH']),
            "overall_risk_score": risk.get('overall_risk_score', 0)
        }
    }

    s3_location = upload_json_to_s3(threat_model, "threat-models")
    print(f"[Upload] Threat model uploaded to {s3_location}")
    return s3_location


async def run_threat_model_workflow(
    scanner_s3_location: str,
    inventory_s3_location: str
):
    """Execute the threat modeling workflow using Scanner + Inventory outputs."""

    print("=" * 80)
    print("COMPASS THREAT MODEL AGENT")
    print("=" * 80)
    print(f"Scanner Results: {scanner_s3_location}")
    print(f"Inventory Results: {inventory_s3_location}")
    print("=" * 80)

    provider = get_provider()

    agent = provider.create_agent(
        instructions=f"""You are a threat modeling expert. Your job is to create a comprehensive
threat model by combining REAL security scan results with REAL application architecture.

You have two data sources:
1. Scanner Agent results at: {scanner_s3_location}
2. Inventory Agent results at: {inventory_s3_location}

Follow this EXACT workflow:

STEP 1: LOAD DATA
- scanner_data = load_scanner_results("{scanner_s3_location}")
- inventory_data = load_inventory_results("{inventory_s3_location}")

STEP 2: CORRELATE VULNERABILITIES WITH ARCHITECTURE
- correlations = correlate_vulnerabilities_with_architecture(scanner_data, inventory_data)
This maps each vulnerability to the architecture component it affects.

STEP 3: GENERATE ATTACK SCENARIOS
- scenarios = generate_attack_scenarios(correlations, inventory_data)
Generate 5-10 realistic attack scenarios grounded in REAL findings and architecture.

STEP 4: STRIDE ANALYSIS
- stride = perform_stride_analysis(scenarios, correlations, inventory_data)
Categorize all threats using STRIDE methodology.

STEP 5: RISK SCORING
- risk = score_and_prioritize_risks(stride, correlations, scenarios)
Score overall risk, identify priorities and quick wins.

STEP 6: UPLOAD TO S3
- upload_threat_model_to_s3("{scanner_s3_location}", "{inventory_s3_location}",
    correlations, scenarios, stride, risk)

Report the final threat model S3 location and key metrics.

CRITICAL: Every threat and scenario MUST reference real finding IDs and real components.
Do NOT generate generic threats disconnected from actual scan data.""",
        tools=[
            load_scanner_results,
            load_inventory_results,
            correlate_vulnerabilities_with_architecture,
            generate_attack_scenarios,
            perform_stride_analysis,
            score_and_prioritize_risks,
            upload_threat_model_to_s3
        ]
    )

    print("\nAgent generating threat model...\n")

    try:
        result = await agent.run(
            f"Create a comprehensive threat model using scanner results from "
            f"{scanner_s3_location} and inventory data from {inventory_s3_location}."
        )
    except ServiceResponseException as exc:
        if "DeploymentNotFound" in str(exc):
            raise RuntimeError(
                f"Azure OpenAI deployment not found: {exc}"
            ) from exc
        raise

    print("\n" + "=" * 80)
    print("THREAT MODEL AGENT COMPLETED")
    print("=" * 80)
    print(result.text)
    print("=" * 80)

    return result.text


# ============================================================================
# HTTP API
# ============================================================================

app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "agent": "threat_model"})


@app.route('/run', methods=['POST'])
def run():
    data = request.json or {}
    scanner_loc = data.get('scanner_s3_location')
    inventory_loc = data.get('inventory_s3_location')

    if not scanner_loc or not inventory_loc:
        return jsonify({
            "status": "error",
            "message": "Both scanner_s3_location and inventory_s3_location are required"
        }), 400

    try:
        result = asyncio.run(run_threat_model_workflow(scanner_loc, inventory_loc))
        return jsonify({
            "status": "success",
            "agent": "threat_model",
            "result": result
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "agent": "threat_model",
            "error": str(e)
        }), 500


if __name__ == "__main__":
    mode = os.environ.get('COMPASS_MODE', 'agent')

    if mode == 'server':
        port = int(os.environ.get('THREAT_MODEL_PORT', '8092'))
        print(f"Starting Threat Model Agent HTTP server on port {port}")
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        scanner_loc = os.environ.get('SCANNER_S3_LOCATION')
        inventory_loc = os.environ.get('INVENTORY_S3_LOCATION')
        if not scanner_loc or not inventory_loc:
            print("ERROR: Set SCANNER_S3_LOCATION and INVENTORY_S3_LOCATION environment variables")
            sys.exit(1)
        asyncio.run(run_threat_model_workflow(scanner_loc, inventory_loc))
