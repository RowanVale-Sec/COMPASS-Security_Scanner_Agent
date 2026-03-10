"""Bandit SAST Tool - Scans Python source code for security issues."""

import json
import uuid
import subprocess
from pathlib import Path
from typing import Annotated
from pydantic import Field


def scan_python_code_with_bandit(
    folder_path: Annotated[str, Field(description="Path to scan Python code")]
) -> dict:
    """Scan Python source code with Bandit. Saves raw findings to file."""
    print(f"[Tool] Running Bandit on {folder_path}")

    py_files = list(Path(folder_path).rglob("*.py"))
    if not py_files:
        return {"tool": "bandit", "findings_file": None, "finding_count": 0, "note": "No Python files found"}

    try:
        result = subprocess.run(
            ['bandit', '-r', folder_path, '-f', 'json', '-q'],
            capture_output=True,
            text=True,
            timeout=300
        )
    except FileNotFoundError:
        return {"tool": "bandit", "error": "Bandit not installed", "findings_file": None, "finding_count": 0}
    except Exception as e:
        return {"tool": "bandit", "error": str(e), "findings_file": None, "finding_count": 0}

    if not result.stdout:
        return {"tool": "bandit", "findings_file": None, "finding_count": 0,
                "note": f"Bandit completed but no output. Return code: {result.returncode}"}

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "bandit", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}

    raw_findings = data.get('results', [])

    output_file = f"/tmp/bandit_{uuid.uuid4().hex}.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "bandit", "raw_findings": raw_findings}, f)

    return {
        "tool": "bandit",
        "findings_file": output_file,
        "finding_count": len(raw_findings)
    }
