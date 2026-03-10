"""
Threat Model Tool - STRIDE Analyzer
Performs STRIDE threat categorization based on attack scenarios and architecture.
"""

import json
from typing import Annotated
from pydantic import Field

from shared.base_agent import get_openai_client, get_deployment_name


def perform_stride_analysis(
    scenarios_json: Annotated[str, Field(description="JSON string of attack scenarios from generate_attack_scenarios")],
    correlations_json: Annotated[str, Field(description="JSON string of vulnerability correlations")],
    inventory_json: Annotated[str, Field(description="JSON string of inventory results")]
) -> str:
    """
    Perform STRIDE threat categorization using real attack scenarios and architecture.

    Maps attack scenarios to STRIDE categories:
    - Spoofing: Identity-related threats
    - Tampering: Data integrity threats
    - Repudiation: Audit/logging issues
    - Information Disclosure: Confidentiality breaches
    - Denial of Service: Availability threats
    - Elevation of Privilege: Authorization bypasses

    Returns: JSON string with STRIDE analysis.
    """
    print("[STRIDE] Performing STRIDE threat categorization")

    try:
        scenarios = json.loads(scenarios_json)
    except json.JSONDecodeError:
        scenarios = {"scenarios": []}

    try:
        correlations = json.loads(correlations_json)
    except json.JSONDecodeError:
        correlations = {"correlations": []}

    try:
        inventory = json.loads(inventory_json)
    except json.JSONDecodeError:
        inventory = {}

    openai_client = get_openai_client()
    deployment = get_deployment_name()

    arch = inventory.get('architecture', {})
    scenario_list = scenarios.get('scenarios', [])
    corr_list = correlations.get('correlations', [])

    prompt = f"""Perform comprehensive STRIDE analysis based on:

**Attack Scenarios ({len(scenario_list)}):**
{json.dumps(scenario_list, indent=2)}

**Vulnerability Correlations ({len(corr_list)}):**
{json.dumps(corr_list[:20], indent=2)}

**Architecture Type:** {arch.get('type', 'unknown')}
**Components:** {json.dumps(arch.get('components', []), indent=2)}

For each attack scenario AND for each architecture component, categorize threats
using STRIDE. Generate specific, actionable threats.

Return JSON:
{{
  "threats": [
    {{
      "threat_id": "THR-001",
      "stride_category": "Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege",
      "description": "Specific threat description",
      "affected_component": "Component name from architecture",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW",
      "related_scenarios": ["Scenario name"],
      "related_findings": ["FND-C-1"],
      "mitigation": "Specific mitigation recommendation",
      "detection": "How to detect this threat"
    }}
  ],
  "by_category": {{
    "Spoofing": N,
    "Tampering": N,
    "Repudiation": N,
    "Information Disclosure": N,
    "Denial of Service": N,
    "Elevation of Privilege": N
  }},
  "critical_threats": ["THR-001", "THR-003"],
  "component_threat_map": {{
    "web-service": ["THR-001", "THR-002"],
    "database": ["THR-005"]
  }}
}}

Return ONLY valid JSON. Generate at least 10-15 threats covering all STRIDE categories."""

    try:
        response = openai_client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": "You are a threat modeling expert using STRIDE methodology. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            response_format={"type": "json_object"}
        )

        stride = json.loads(response.choices[0].message.content)
        threat_count = len(stride.get('threats', []))
        print(f"[STRIDE] Categorized {threat_count} threats")
        print(f"  By category: {stride.get('by_category', {})}")

        return json.dumps(stride, indent=2)

    except Exception as e:
        print(f"[STRIDE] Analysis failed: {e}")
        return json.dumps({"threats": [], "by_category": {}, "error": str(e)})
