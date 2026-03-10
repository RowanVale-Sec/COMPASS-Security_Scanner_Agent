"""Trivy Container Image Scanner Tool - Scans Docker images for vulnerabilities."""

import json
import uuid
import subprocess
from typing import Annotated
from pydantic import Field


def scan_container_image_with_trivy(
    image_ref: Annotated[str, Field(description="Docker image reference to scan (e.g., 'python:3.11-slim')")]
) -> dict:
    """Scan a container image for vulnerabilities with Trivy. Saves raw findings to file.

    Analyzes OS packages and application dependencies within a Docker image
    for known CVEs and security issues.
    """
    print(f"[Tool] Running Trivy container image scan on {image_ref}")

    try:
        result = subprocess.run(
            ['trivy', 'image', image_ref, '--format', 'json'],
            capture_output=True,
            text=True,
            timeout=600  # Image scanning can take longer
        )
    except FileNotFoundError:
        return {"tool": "trivy-image", "error": "Trivy not installed", "findings_file": None, "finding_count": 0}
    except Exception as e:
        return {"tool": "trivy-image", "error": str(e), "findings_file": None, "finding_count": 0}

    if not result.stdout:
        return {"tool": "trivy-image", "findings_file": None, "finding_count": 0,
                "note": f"Trivy image scan completed but no output. Return code: {result.returncode}"}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "trivy-image", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}

    raw_findings = []
    for scan_result in data.get('Results', []):
        target = scan_result.get('Target', '')
        result_class = scan_result.get('Class', '')
        for vuln in scan_result.get('Vulnerabilities', []):
            vuln['_trivy_target'] = target
            vuln['_trivy_class'] = result_class
            raw_findings.append(vuln)

    output_file = f"/tmp/trivy_image_{uuid.uuid4().hex}.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "trivy-image", "raw_findings": raw_findings}, f)

    return {
        "tool": "trivy-image",
        "findings_file": output_file,
        "finding_count": len(raw_findings),
        "image_ref": image_ref
    }
