"""Checkov IaC Scanner Tool - Scans Terraform, CloudFormation, Kubernetes files."""

import json
import uuid
import subprocess
from typing import Annotated
from pydantic import Field


def scan_with_checkov(
    folder_path: Annotated[str, Field(description="Path to folder with IaC files")]
) -> dict:
    """Scan Infrastructure as Code files with Checkov. Saves raw findings to file."""
    print(f"[Tool] Running Checkov on {folder_path}")

    try:
        result = subprocess.run(
            ['checkov', '-d', folder_path, '-o', 'json', '--compact'],
            capture_output=True,
            text=True,
            timeout=300
        )
    except FileNotFoundError:
        return {"tool": "checkov", "error": "Checkov not installed", "findings_file": None, "finding_count": 0}
    except Exception as e:
        return {"tool": "checkov", "error": str(e), "findings_file": None, "finding_count": 0}

    if not result.stdout:
        return {"tool": "checkov", "findings_file": None, "finding_count": 0,
                "note": f"Checkov completed but no output. Return code: {result.returncode}"}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "checkov", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}

    raw_findings = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                raw_findings.extend(item.get('results', {}).get('failed_checks', []))
    elif isinstance(data, dict):
        raw_findings = data.get('results', {}).get('failed_checks', [])

    output_file = f"/tmp/checkov_{uuid.uuid4().hex}.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "checkov", "raw_findings": raw_findings}, f)

    return {
        "tool": "checkov",
        "findings_file": output_file,
        "finding_count": len(raw_findings)
    }
