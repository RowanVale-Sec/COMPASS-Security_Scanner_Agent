"""
Threat Model Tool - Vulnerability-Architecture Correlator
Maps scanner findings to architecture components and data flows.
"""

import json
from typing import Annotated
from pydantic import Field

from shared.llm_provider import get_provider


async def correlate_vulnerabilities_with_architecture(
    scanner_json: Annotated[str, Field(description="JSON string of scanner results from load_scanner_results")],
    inventory_json: Annotated[str, Field(description="JSON string of inventory results from load_inventory_results")]
) -> str:
    """
    Map scanner findings to architecture components using AI.

    For each vulnerability, determines:
    - Which architecture component is affected
    - What attack surface exposure it has (internet-facing, internal)
    - What data is at risk based on data flow analysis
    - The MITRE ATT&CK tactic context

    Returns: JSON string with vulnerability-architecture correlations.
    """
    print("[Correlator] Mapping vulnerabilities to architecture components")

    try:
        scanner = json.loads(scanner_json)
    except json.JSONDecodeError:
        scanner = {"findings": []}

    try:
        inventory = json.loads(inventory_json)
    except json.JSONDecodeError:
        inventory = {}

    findings = scanner.get('findings', [])
    architecture = inventory.get('architecture', {})
    dfd = inventory.get('data_flow', {})
    sbom = inventory.get('sbom', {})

    if not findings:
        print("[Correlator] No findings to correlate")
        return json.dumps({"correlations": [], "summary": "No findings to correlate"})

    provider = get_provider()

    # Slim each finding to fields needed for correlation so all findings fit in context
    _CORR_FIELDS = {'finding_id', 'finding_title', 'description', 'severity',
                    'file_path', 'resource_type', 'scan_type', 'tool_name',
                    'mitre_analysis'}
    slim_findings = [{k: v for k, v in f.items() if k in _CORR_FIELDS} for f in findings]
    findings_summary = json.dumps(slim_findings, indent=2)
    arch_summary = json.dumps(architecture, indent=2)
    dfd_summary = json.dumps(dfd, indent=2)

    prompt = f"""You are a security analyst correlating vulnerability findings with application architecture.

**Scanner Findings ({len(findings)} total):**
{findings_summary}

**Application Architecture:**
{arch_summary}

**Data Flow Diagram:**
{dfd_summary}

For each vulnerability finding, determine which architecture component it affects and what
data is at risk. Return JSON with:

{{
  "correlations": [
    {{
      "finding_id": "FND-C-1",
      "finding_title": "...",
      "severity": "HIGH",
      "affected_component": "web-service",
      "component_type": "service",
      "exposure": "internet-facing" or "internal",
      "data_at_risk": ["PII", "credentials"],
      "mitre_tactic": "Initial Access",
      "mitre_technique": "T1190",
      "attack_path": "Brief description of how this vulnerability could be exploited given the architecture",
      "blast_radius": "How far an attacker could reach from this vulnerability"
    }}
  ],
  "summary": {{
    "total_correlated": N,
    "internet_facing_vulns": N,
    "components_affected": ["list of affected component names"],
    "critical_data_exposed": ["list of data types at risk"]
  }}
}}

Return ONLY valid JSON. Correlate ALL findings, not just the first few."""

    try:
        correlations = await provider.structured_output(
            schema={"type": "object"},
            prompt=prompt,
            system="You are a security analyst mapping vulnerabilities to architecture. Return only valid JSON.",
            temperature=0.2,
            max_tokens=4096,
        )
        count = len(correlations.get('correlations', []))
        print(f"[Correlator] Correlated {count} findings to architecture components")

        return json.dumps(correlations, indent=2)

    except Exception as e:
        print(f"[Correlator] Correlation failed: {e}")
        return json.dumps({"correlations": [], "error": str(e)})
