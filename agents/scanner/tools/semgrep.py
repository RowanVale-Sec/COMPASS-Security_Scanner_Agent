"""Semgrep SAST Tool - Multi-language static analysis with pattern matching."""

import json
import uuid
import subprocess
from typing import Annotated
from pydantic import Field


def scan_code_with_semgrep(
    folder_path: Annotated[str, Field(description="Path to scan source code")]
) -> dict:
    """Scan multi-language source code with Semgrep. Saves raw findings to file."""
    print(f"[Tool] Running Semgrep on {folder_path}")

    try:
        result = subprocess.run(
            ['semgrep', 'scan', '--config', 'auto', '--json', folder_path],
            capture_output=True,
            text=True,
            timeout=300
        )
    except FileNotFoundError:
        return {"tool": "semgrep", "error": "Semgrep not installed", "findings_file": None, "finding_count": 0}
    except Exception as e:
        return {"tool": "semgrep", "error": str(e), "findings_file": None, "finding_count": 0}

    if not result.stdout:
        return {"tool": "semgrep", "findings_file": None, "finding_count": 0,
                "note": f"Semgrep completed but no output. Return code: {result.returncode}"}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "semgrep", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}

    raw_findings = data.get('results', [])

    output_file = f"/tmp/semgrep_{uuid.uuid4().hex}.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "semgrep", "raw_findings": raw_findings}, f)

    return {
        "tool": "semgrep",
        "findings_file": output_file,
        "finding_count": len(raw_findings)
    }
