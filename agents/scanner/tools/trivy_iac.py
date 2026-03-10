"""Trivy IaC Scanner Tool - Scans for Infrastructure as Code misconfigurations."""

import json
import uuid
import subprocess
from typing import Annotated
from pydantic import Field


def scan_iac_with_trivy(
    folder_path: Annotated[str, Field(description="Path to scan for IaC misconfigurations")]
) -> dict:
    """Scan for IaC misconfigurations with Trivy. Saves raw findings to file."""
    print(f"[Tool] Running Trivy IaC scan on {folder_path}")

    try:
        result = subprocess.run(
            ['trivy', 'config', folder_path, '--format', 'json'],
            capture_output=True,
            text=True,
            timeout=300
        )
    except FileNotFoundError:
        return {"tool": "trivy-iac", "error": "Trivy not installed", "findings_file": None, "finding_count": 0}
    except Exception as e:
        return {"tool": "trivy-iac", "error": str(e), "findings_file": None, "finding_count": 0}

    if not result.stdout:
        return {"tool": "trivy-iac", "findings_file": None, "finding_count": 0,
                "note": f"Trivy completed but no output. Return code: {result.returncode}"}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "trivy-iac", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}

    raw_findings = []
    for scan_result in data.get('Results', []):
        for misconf in scan_result.get('Misconfigurations', []):
            misconf['_trivy_target'] = scan_result.get('Target', '')
            raw_findings.append(misconf)

    output_file = f"/tmp/trivy_iac_{uuid.uuid4().hex}.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "trivy-iac", "raw_findings": raw_findings}, f)

    return {
        "tool": "trivy-iac",
        "findings_file": output_file,
        "finding_count": len(raw_findings)
    }
