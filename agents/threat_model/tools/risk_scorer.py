"""
Threat Model Tool - Risk Scorer
Performs risk scoring and prioritization combining MITRE, CVSS, and architecture context.
"""

import json
from typing import Annotated
from pydantic import Field

from shared.llm_provider import get_provider


async def score_and_prioritize_risks(
    stride_json: Annotated[str, Field(description="JSON string of STRIDE analysis from perform_stride_analysis")],
    correlations_json: Annotated[str, Field(description="JSON string of vulnerability correlations")],
    scenarios_json: Annotated[str, Field(description="JSON string of attack scenarios")]
) -> str:
    """
    Score and prioritize risks using MITRE ATT&CK severity, architecture exposure,
    and data sensitivity.

    Produces:
    - Overall risk score (0-10)
    - Critical priorities (must-fix items)
    - Quick wins (high impact, low effort)
    - Strategic improvements (long-term)
    - Compliance gap analysis (OWASP Top 10, CWE)

    Returns: JSON string with risk analysis.
    """
    print("[Risk] Scoring and prioritizing risks")

    try:
        stride = json.loads(stride_json)
    except json.JSONDecodeError:
        stride = {"threats": []}

    try:
        correlations = json.loads(correlations_json)
    except json.JSONDecodeError:
        correlations = {"correlations": []}

    try:
        scenarios = json.loads(scenarios_json)
    except json.JSONDecodeError:
        scenarios = {"scenarios": []}

    provider = get_provider()

    threats = stride.get('threats', [])
    corr_list = correlations.get('correlations', [])
    scenario_list = scenarios.get('scenarios', [])

    # Slim correlations to essential fields so all entries fit in context
    _RISK_FIELDS = {'finding_id', 'finding_title', 'severity', 'affected_component',
                    'exposure', 'mitre_tactic', 'mitre_technique'}
    slim_corr = [{k: v for k, v in c.items() if k in _RISK_FIELDS} for c in corr_list]

    prompt = f"""Perform comprehensive risk analysis and prioritization:

**STRIDE Threats ({len(threats)}):**
{json.dumps(threats, indent=2)}

**Vulnerability Correlations ({len(corr_list)}):**
{json.dumps(slim_corr, indent=2)}

**Attack Scenarios ({len(scenario_list)}):**
{json.dumps(scenario_list, indent=2)}

Generate a risk analysis with:

{{
  "overall_risk_score": 0.0-10.0,
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "risk_justification": "Brief explanation of the overall risk score",

  "critical_priorities": [
    {{
      "rank": 1,
      "title": "Fix title",
      "description": "What to fix and why",
      "related_threats": ["THR-001"],
      "related_findings": ["FND-C-1"],
      "effort": "LOW|MEDIUM|HIGH",
      "impact": "What impact fixing this has",
      "timeline": "Immediate|Short-term|Medium-term"
    }}
  ],

  "quick_wins": [
    {{
      "title": "Quick win title",
      "description": "What to do",
      "effort": "LOW",
      "impact": "HIGH",
      "related_threats": ["THR-005"]
    }}
  ],

  "strategic_improvements": [
    {{
      "title": "Strategic improvement",
      "description": "Long-term security improvement",
      "timeline": "Medium-term|Long-term",
      "effort": "HIGH",
      "impact": "HIGH"
    }}
  ],

  "compliance_gaps": [
    {{
      "standard": "OWASP Top 10|CWE|NIST|PCI-DSS",
      "requirement": "Specific requirement",
      "gap_description": "What's missing",
      "related_threats": ["THR-002"],
      "remediation": "How to address"
    }}
  ],

  "risk_matrix": {{
    "critical_high_likelihood": N,
    "critical_medium_likelihood": N,
    "high_high_likelihood": N,
    "high_medium_likelihood": N,
    "medium_any_likelihood": N,
    "low_any_likelihood": N
  }}
}}

Return ONLY valid JSON. Be specific - reference actual threat IDs and finding IDs."""

    try:
        risk = await provider.structured_output(
            schema={"type": "object"},
            prompt=prompt,
            system="You are a CISO prioritizing security risks. Return only valid JSON.",
            temperature=0.3,
            max_tokens=4096,
        )

        score = risk.get('overall_risk_score', 0)
        priorities = len(risk.get('critical_priorities', []))
        wins = len(risk.get('quick_wins', []))
        print(f"[Risk] Overall risk: {score}/10, {priorities} critical priorities, {wins} quick wins")

        return json.dumps(risk, indent=2)

    except Exception as e:
        print(f"[Risk] Analysis failed: {e}")
        return json.dumps({
            "overall_risk_score": 0,
            "critical_priorities": [],
            "quick_wins": [],
            "error": str(e)
        })
