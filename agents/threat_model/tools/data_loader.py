"""
Threat Model Tool - Data Loader
Loads Scanner Agent and Inventory Agent outputs from local files materialized
from HTTP request bodies.
"""

import json
from typing import Annotated
from pydantic import Field

from shared.local_store import load_json


def load_scanner_results(
    findings_path: Annotated[str, Field(description="Local file path of scanner MITRE-mapped results")]
) -> str:
    """
    Load Scanner Agent results from a local file path.

    Loads the MITRE-mapped, deduplicated security findings including:
    - Vulnerability findings with severity and MITRE ATT&CK mapping
    - Scan types: IaC, SAST, SCA, Secrets, Container
    - Tool distribution and finding counts

    Returns: JSON string of scanner results (flattened findings list).
    """
    print(f"[Loader] Loading scanner results from {findings_path}")

    try:
        data = load_json(findings_path)

        findings = []
        for key, value in data.items():
            if key.startswith('FND-') and isinstance(value, dict):
                finding = value.get('finding', {})
                mitre = value.get('mitre_analysis', {})
                finding['mitre_analysis'] = mitre
                finding['finding_id'] = key
                findings.append(finding)

        metadata = data.get('metadata', {})
        total = metadata.get('total_findings', len(findings))

        result = {
            "source": findings_path,
            "total_findings": total,
            "tool_distribution": metadata.get('tool_distribution', {}),
            "findings": findings
        }

        print(f"[Loader] Loaded {len(findings)} scanner findings")
        return json.dumps(result, indent=2)

    except Exception as e:
        print(f"[Loader] Failed to load scanner results: {e}")
        return json.dumps({"error": str(e), "findings": []})


def load_inventory_results(
    inventory_path: Annotated[str, Field(description="Local file path of inventory JSON")]
) -> str:
    """
    Load Inventory Agent results from a local file path.

    Loads the complete inventory including:
    - SBOM with package details, PURL, CPE, and vulnerability mapping
    - Architecture model with components and communication patterns
    - Data Flow Diagram with trust boundaries and data flows
    - Asset inventory with categorized assets

    Returns: JSON string of inventory results.
    """
    print(f"[Loader] Loading inventory results from {inventory_path}")

    try:
        data = load_json(inventory_path)

        sbom = data.get('sbom', {})
        arch = data.get('architecture', {})
        dfd = data.get('data_flow', {})
        assets = data.get('asset_inventory', {})

        print(f"[Loader] Loaded inventory: {sbom.get('total_packages', 0)} packages, "
              f"{len(arch.get('components', []))} components, "
              f"{len(dfd.get('flows', []))} data flows, "
              f"{assets.get('total_assets', 0)} total assets")

        return json.dumps(data, indent=2)

    except Exception as e:
        print(f"[Loader] Failed to load inventory results: {e}")
        return json.dumps({"error": str(e)})
