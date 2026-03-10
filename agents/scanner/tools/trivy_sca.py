"""Trivy SCA Tool - Software Composition Analysis for dependency vulnerabilities."""

import json
import uuid
import subprocess
from typing import Annotated
from pydantic import Field


def scan_dependencies_with_trivy(
    folder_path: Annotated[str, Field(description="Path to scan for dependency vulnerabilities")]
) -> dict:
    """Scan dependencies for known CVEs with Trivy SCA. Saves raw findings to file.

    Unlike the IaC scanner (trivy config), this uses 'trivy fs --scanners vuln' to
    identify known vulnerabilities in project dependencies (pip, npm, maven, go, etc).
    """
    print(f"[Tool] Running Trivy SCA (dependency vulnerability) scan on {folder_path}")

    try:
        result = subprocess.run(
            ['trivy', 'fs', folder_path, '--scanners', 'vuln', '--format', 'json'],
            capture_output=True,
            text=True,
            timeout=300
        )
    except FileNotFoundError:
        return {"tool": "trivy-sca", "error": "Trivy not installed", "findings_file": None, "finding_count": 0}
    except Exception as e:
        return {"tool": "trivy-sca", "error": str(e), "findings_file": None, "finding_count": 0}

    if not result.stdout:
        return {"tool": "trivy-sca", "findings_file": None, "finding_count": 0,
                "note": f"Trivy SCA completed but no output. Return code: {result.returncode}"}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "trivy-sca", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}

    raw_findings = []
    for scan_result in data.get('Results', []):
        target = scan_result.get('Target', '')
        for vuln in scan_result.get('Vulnerabilities', []):
            vuln['_trivy_target'] = target
            raw_findings.append(vuln)

    output_file = f"/tmp/trivy_sca_{uuid.uuid4().hex}.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "trivy-sca", "raw_findings": raw_findings}, f)

    return {
        "tool": "trivy-sca",
        "findings_file": output_file,
        "finding_count": len(raw_findings)
    }
