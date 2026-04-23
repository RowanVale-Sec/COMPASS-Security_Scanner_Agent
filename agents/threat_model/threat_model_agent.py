#!/usr/bin/env python3
"""
COMPASS Threat Model Agent
Consumes Scanner Agent and Inventory Agent outputs to generate a comprehensive
threat model with attack scenarios, STRIDE analysis, and risk prioritization.

All threat analysis is grounded in REAL scan data and REAL architecture.
"""

import inspect
import json
import os
import sys
import asyncio
from datetime import datetime
from typing import Annotated, Any, Dict
from pydantic import Field
from flask import Flask, request, jsonify

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from shared.llm_provider import ProviderCredentials, use_credentials
from shared.local_store import run_scope, save_input_payload

from agents.threat_model.tools.data_loader import load_scanner_results, load_inventory_results
from agents.threat_model.tools.vuln_correlator import correlate_vulnerabilities_with_architecture
from agents.threat_model.tools.scenario_generator import generate_attack_scenarios
from agents.threat_model.tools.stride_analyzer import perform_stride_analysis
from agents.threat_model.tools.risk_scorer import score_and_prioritize_risks


def assemble_threat_model(
    scanner_source: Annotated[str, Field(description="Human-readable label for the scanner source (e.g. a local path or 'inline')")],
    inventory_source: Annotated[str, Field(description="Human-readable label for the inventory source")],
    correlations_json: Annotated[str, Field(description="JSON string returned by correlate_vulnerabilities_with_architecture")],
    scenarios_json: Annotated[str, Field(description="JSON string returned by generate_attack_scenarios")],
    stride_json: Annotated[str, Field(description="JSON string returned by perform_stride_analysis")],
    risk_json: Annotated[str, Field(description="JSON string returned by score_and_prioritize_risks")]
) -> str:
    """
    Assemble the final threat model JSON and return it as a JSON string.

    The agent's final message should include this exact JSON inside a
    ```threat-model-json ... ``` fenced block so the calling process can extract
    it without parsing prose.
    """
    print("[Assemble] Building consolidated threat model")

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
            "scanner_source": scanner_source,
            "inventory_source": inventory_source,
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

    return json.dumps(threat_model)


async def run_threat_model_workflow(
    scanner_findings_path: str,
    inventory_path: str,
) -> Dict[str, Any]:
    """Execute the threat modeling workflow deterministically.

    Same shape as the inventory pipeline: each stage returns a JSON string
    that the next stage consumes. Asking the LLM to chain these tool calls
    failed because it will not echo a multi-kilobyte JSON blob back verbatim
    (the symptom is an empty correlation summary + zero attack scenarios even
    when the scanner produced hundreds of findings). The sequencing here has
    no reasoning gain from the LLM, so we drive it in Python. LLM calls still
    happen *inside* each tool (scenario generation, STRIDE analysis, risk
    scoring) where they genuinely add value.
    """
    print("=" * 80)
    print("COMPASS THREAT MODEL AGENT")
    print("=" * 80)
    print(f"Scanner findings: {scanner_findings_path}")
    print(f"Inventory: {inventory_path}")
    print("=" * 80)

    async def _await_if_needed(value):
        return await value if inspect.iscoroutine(value) else value

    # 1. Load inputs (these return JSON strings consumed by later stages)
    scanner_data_json = load_scanner_results(scanner_findings_path)
    inventory_data_json = load_inventory_results(inventory_path)

    # 2. Correlate vulns with architecture
    correlations_json = await _await_if_needed(
        correlate_vulnerabilities_with_architecture(scanner_data_json, inventory_data_json)
    )

    # 3. Attack scenarios (needs correlations + inventory)
    scenarios_json = await _await_if_needed(
        generate_attack_scenarios(correlations_json, inventory_data_json)
    )

    # 4. STRIDE categorization
    stride_json = await _await_if_needed(
        perform_stride_analysis(scenarios_json, correlations_json, inventory_data_json)
    )

    # 5. Risk scoring
    risk_json = await _await_if_needed(
        score_and_prioritize_risks(stride_json, correlations_json, scenarios_json)
    )

    # 6. Assemble
    assembled_json = assemble_threat_model(
        scanner_findings_path,
        inventory_path,
        correlations_json,
        scenarios_json,
        stride_json,
        risk_json,
    )

    print("\n" + "=" * 80)
    print("THREAT MODEL AGENT COMPLETED")
    print("=" * 80)

    try:
        return json.loads(assembled_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"assemble_threat_model returned invalid JSON: {exc}") from exc


# ============================================================================
# HTTP API
# ============================================================================

app = Flask(__name__)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({"status": "healthy", "agent": "threat_model"})


@app.route('/run', methods=['POST'])
def run():
    """Run the threat model agent.

    Request body:
      {
        "scanner_findings": { ... scanner JSON ... },
        "inventory":        { ... inventory JSON ... },
        "credentials":      { "provider": "...", ... }  # optional
      }
    """
    data = request.json or {}
    scanner_findings = data.get('scanner_findings')
    inventory = data.get('inventory')
    creds_data = data.get('credentials')

    if not isinstance(scanner_findings, dict) or not scanner_findings:
        return jsonify({
            "status": "error",
            "message": "scanner_findings (object) is required"
        }), 400
    if not isinstance(inventory, dict) or not inventory:
        return jsonify({
            "status": "error",
            "message": "inventory (object) is required"
        }), 400

    try:
        creds = ProviderCredentials.from_dict(creds_data) if creds_data else None
    except ValueError as e:
        return jsonify({"status": "error", "agent": "threat_model", "error": str(e)}), 400

    try:
        with run_scope():
            scanner_path = save_input_payload("scanner_findings", scanner_findings)
            inventory_path = save_input_payload("inventory", inventory)
            with use_credentials(creds):
                model = asyncio.run(run_threat_model_workflow(scanner_path, inventory_path))
        return jsonify({
            "status": "success",
            "agent": "threat_model",
            "threat_model": model,
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
        print("ERROR: threat_model_agent CLI mode requires scanner+inventory JSON inputs; "
              "run it as an HTTP server (COMPASS_MODE=server) and POST to /run.")
        sys.exit(1)
