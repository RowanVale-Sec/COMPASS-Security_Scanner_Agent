"""
Inventory Tool - Enhanced SBOM Generator
Calls Syft MCP server for SBOM generation, then enriches with vulnerability
cross-referencing from Scanner Agent SCA results.
"""

import os
import json
import requests
from typing import Annotated, Optional
from pydantic import Field


def generate_enhanced_sbom(
    folder_path: Annotated[str, Field(description="Path to the codebase to generate SBOM for")],
    scanner_s3_location: Annotated[str, Field(description="Optional S3 location of Scanner Agent SCA results for vulnerability cross-referencing")] = ""
) -> str:
    """
    Generate an enhanced SBOM using the Syft MCP server.

    Steps:
    1. Call Syft MCP server to generate SPDX-JSON SBOM
    2. Extract rich metadata (PURL, CPE, licenses, relationships)
    3. Optionally cross-reference with Scanner Agent SCA results for CVE mapping
    4. Return structured SBOM data as JSON string

    Returns: JSON string with SBOM data including packages with PURL, CPE, licenses, and known vulnerabilities.
    """
    print(f"[SBOM] Generating enhanced SBOM for {folder_path}")

    syft_url = os.environ.get('SYFT_MCP_URL', 'http://syft-mcp:8080')

    try:
        response = requests.post(
            f"{syft_url}/analyze",
            json={"repo_path": folder_path, "output_format": "spdx-json"},
            timeout=300
        )
        response.raise_for_status()
        result = response.json()

        if result.get('status') != 'success':
            raise Exception(f"Syft returned error: {result.get('message', 'unknown error')}")

        findings = result.get('result', {}).get('findings', [])
        relationships = result.get('result', {}).get('relationships', [])
        total_packages = result.get('result', {}).get('total_packages', 0)

        print(f"[SBOM] Syft found {total_packages} packages")

    except Exception as e:
        print(f"[SBOM] Syft MCP call failed: {e}")
        findings = []
        relationships = []
        total_packages = 0

    # Cross-reference with Scanner SCA results for vulnerability mapping
    known_vulns = {}
    if scanner_s3_location:
        try:
            from shared.s3_helpers import download_json_from_s3
            scanner_data = download_json_from_s3(scanner_s3_location)
            for finding in scanner_data.get('findings', []):
                if finding.get('scan_type') == 'SCA' or finding.get('tool_name', '').startswith('trivy-sca'):
                    pkg_name = finding.get('resource_name', '')
                    if pkg_name:
                        if pkg_name not in known_vulns:
                            known_vulns[pkg_name] = []
                        known_vulns[pkg_name].append({
                            'finding_id': finding.get('finding_id', ''),
                            'title': finding.get('finding_title', ''),
                            'severity': finding.get('severity', 'UNKNOWN')
                        })
            print(f"[SBOM] Cross-referenced {len(known_vulns)} packages with SCA vulnerabilities")
        except Exception as e:
            print(f"[SBOM] Could not cross-reference SCA results: {e}")

    # Enrich findings with vulnerability data
    for finding in findings:
        pkg_name = finding.get('name', '')
        if pkg_name in known_vulns:
            finding['known_vulnerabilities'] = known_vulns[pkg_name]
            finding['risk_level'] = _calculate_risk_level(known_vulns[pkg_name])
        else:
            finding['known_vulnerabilities'] = []
            finding['risk_level'] = 'NONE'

    sbom_data = {
        "format": "spdx-json",
        "total_packages": total_packages,
        "packages": findings,
        "relationships": relationships,
        "packages_with_vulnerabilities": len(known_vulns)
    }

    print(f"[SBOM] Enhanced SBOM complete: {total_packages} packages, {len(known_vulns)} with known vulns")
    return json.dumps(sbom_data, indent=2)


def _calculate_risk_level(vulns: list) -> str:
    """Calculate risk level from list of vulnerabilities."""
    severities = [v.get('severity', 'UNKNOWN') for v in vulns]
    if any(s in ('CRITICAL', 'HIGH') for s in severities):
        return 'HIGH'
    elif any(s == 'MEDIUM' for s in severities):
        return 'MEDIUM'
    elif any(s == 'LOW' for s in severities):
        return 'LOW'
    return 'NONE'
