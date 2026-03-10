"""
Threat Model Tool - Data Loader
Loads Scanner Agent and Inventory Agent outputs from S3 for threat analysis.
"""

import json
from typing import Annotated
from pydantic import Field

from shared.s3_helpers import download_json_from_s3


def load_scanner_results(
    s3_location: Annotated[str, Field(description="S3 location of Scanner Agent MITRE-mapped results")]
) -> str:
    """
    Download and parse Scanner Agent results from S3.

    Loads the MITRE-mapped, deduplicated security findings including:
    - Vulnerability findings with severity and MITRE ATT&CK mapping
    - Scan types: IaC, SAST, SCA, Secrets, Container
    - Tool distribution and finding counts

    Returns: JSON string of scanner results.
    """
    print(f"[Loader] Loading scanner results from {s3_location}")

    try:
        data = download_json_from_s3(s3_location)

        # Extract key metrics
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
            "source": s3_location,
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
    s3_location: Annotated[str, Field(description="S3 location of Inventory Agent results")]
) -> str:
    """
    Download and parse Inventory Agent results from S3.

    Loads the complete inventory including:
    - SBOM with package details, PURL, CPE, and vulnerability mapping
    - Architecture model with components and communication patterns
    - Data Flow Diagram with trust boundaries and data flows
    - Asset inventory with categorized assets

    Returns: JSON string of inventory results.
    """
    print(f"[Loader] Loading inventory results from {s3_location}")

    try:
        data = download_json_from_s3(s3_location)

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
