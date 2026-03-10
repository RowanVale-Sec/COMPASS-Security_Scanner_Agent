"""
Threat Model Tool - Attack Scenario Generator
Generates realistic attack scenarios grounded in actual scan data and architecture.
"""

import json
from typing import Annotated
from pydantic import Field

from shared.base_agent import get_openai_client, get_deployment_name


def generate_attack_scenarios(
    correlations_json: Annotated[str, Field(description="JSON string of vulnerability-architecture correlations")],
    inventory_json: Annotated[str, Field(description="JSON string of inventory results")]
) -> str:
    """
    Generate realistic attack scenarios based on REAL vulnerabilities and architecture.

    Uses correlated vulnerability data and architecture knowledge to create
    attack scenarios that:
    - Start from real entry points identified in the DFD
    - Exploit real vulnerabilities found by the scanner
    - Target real high-value assets identified in the inventory
    - Follow realistic attack chains through the architecture

    Returns: JSON string with 5-10 attack scenarios.
    """
    print("[Scenarios] Generating attack scenarios from real data")

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

    corr_list = correlations.get('correlations', [])
    arch = inventory.get('architecture', {})
    dfd = inventory.get('data_flow', {})

    # Slim correlations to fields needed for scenario generation so all entries fit
    _SCEN_FIELDS = {'finding_id', 'finding_title', 'severity', 'affected_component',
                    'exposure', 'data_at_risk', 'mitre_tactic', 'mitre_technique',
                    'attack_path'}
    slim_corr = [{k: v for k, v in c.items() if k in _SCEN_FIELDS} for c in corr_list]

    prompt = f"""Based on the following REAL vulnerability-architecture correlations and application data,
generate realistic attack scenarios.

**Vulnerability-Architecture Correlations ({len(corr_list)} total):**
{json.dumps(slim_corr, indent=2)}

**Architecture:**
{json.dumps(arch, indent=2)}

**Data Flow Diagram (Entry Points & Trust Boundaries):**
{json.dumps(dfd, indent=2)}

Generate 5-10 realistic attack scenarios. Each scenario MUST:
1. Reference specific real finding IDs (e.g., FND-C-1, FND-B-3)
2. Use actual entry points from the DFD
3. Target actual components from the architecture
4. Follow a realistic attack chain through the architecture

Return JSON:
{{
  "scenarios": [
    {{
      "name": "Short attack scenario name",
      "description": "Detailed attack narrative",
      "entry_point": "Specific entry point from DFD",
      "target_asset": "What the attacker aims to compromise",
      "attack_steps": ["Step 1", "Step 2", "Step 3"],
      "exploited_vulnerabilities": ["FND-C-1", "FND-B-3"],
      "prerequisites": "What attacker needs",
      "impact": "Business impact description",
      "likelihood": "LOW|MEDIUM|HIGH",
      "severity": "LOW|MEDIUM|HIGH|CRITICAL",
      "affected_data": ["PII", "credentials"],
      "mitre_tactics": ["Initial Access", "Privilege Escalation"]
    }}
  ]
}}

Return ONLY valid JSON."""

    try:
        response = openai_client.chat.completions.create(
            model=deployment,
            messages=[
                {"role": "system", "content": "You are a red team expert creating attack scenarios grounded in real vulnerability data. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.4,
            response_format={"type": "json_object"}
        )

        scenarios = json.loads(response.choices[0].message.content)
        count = len(scenarios.get('scenarios', []))
        print(f"[Scenarios] Generated {count} attack scenarios")

        return json.dumps(scenarios, indent=2)

    except Exception as e:
        print(f"[Scenarios] Generation failed: {e}")
        return json.dumps({"scenarios": [], "error": str(e)})
