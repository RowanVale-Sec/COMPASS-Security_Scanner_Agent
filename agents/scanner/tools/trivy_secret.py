"""Trivy Secrets Scanner Tool - Detects hardcoded secrets, API keys, and credentials."""

import json
import uuid
import subprocess
from typing import Annotated
from pydantic import Field


def scan_secrets_with_trivy(
    folder_path: Annotated[str, Field(description="Path to scan for hardcoded secrets")]
) -> dict:
    """Scan for hardcoded secrets and credentials with Trivy. Saves raw findings to file.

    Detects API keys, passwords, tokens, private keys, and other sensitive data
    accidentally committed to source code or configuration files.
    """
    print(f"[Tool] Running Trivy Secrets scan on {folder_path}")

    try:
        result = subprocess.run(
            ['trivy', 'fs', folder_path, '--scanners', 'secret', '--format', 'json'],
            capture_output=True,
            text=True,
            timeout=300
        )
    except FileNotFoundError:
        return {"tool": "trivy-secret", "error": "Trivy not installed", "findings_file": None, "finding_count": 0}
    except Exception as e:
        return {"tool": "trivy-secret", "error": str(e), "findings_file": None, "finding_count": 0}

    if not result.stdout:
        return {"tool": "trivy-secret", "findings_file": None, "finding_count": 0,
                "note": f"Trivy Secrets completed but no output. Return code: {result.returncode}"}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "trivy-secret", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}

    raw_findings = []
    for scan_result in data.get('Results', []):
        target = scan_result.get('Target', '')
        for secret in scan_result.get('Secrets', []):
            secret['_trivy_target'] = target
            raw_findings.append(secret)

    output_file = f"/tmp/trivy_secret_{uuid.uuid4().hex}.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "trivy-secret", "raw_findings": raw_findings}, f)

    return {
        "tool": "trivy-secret",
        "findings_file": output_file,
        "finding_count": len(raw_findings)
    }
