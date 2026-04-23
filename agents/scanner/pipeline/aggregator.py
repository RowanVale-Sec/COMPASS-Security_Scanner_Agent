"""
Scanner Pipeline - Aggregator
Loads raw findings from all scan tools, normalizes each finding via LLM,
and writes the consolidated result to the local run store.
"""

import os
import json
from datetime import datetime
from typing import Annotated
from pydantic import Field

from shared.llm_provider import LLMProvider, get_provider
from shared.local_store import save_json


FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "tool_name": {"type": "string", "description": "Name of the security tool"},
        "file_path": {"type": "string", "description": "Path to the file with the issue"},
        "finding_title": {"type": "string", "description": "Short title/summary"},
        "description": {"type": "string", "description": "Detailed description"},
        "recommendation": {"type": "string", "description": "How to fix"},
        "resource_type": {"type": "string", "description": "Type of resource (e.g., aws_s3_bucket, Docker, Python function)"},
        "resource_name": {"type": "string", "description": "Name/ID of the resource"},
        "severity": {
            "type": "string",
            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        },
        "scan_type": {
            "type": "string",
            "enum": ["SAST", "IaC", "SCA", "Container", "Secrets", "N/A"],
        },
    },
    "required": [
        "tool_name", "file_path", "finding_title", "description",
        "recommendation", "resource_type", "resource_name", "severity", "scan_type",
    ],
}


async def aggregate_scan_results(
    scan_results_json: Annotated[str, Field(
        description="JSON string: array of metadata dicts from all scan tools, "
                    "each with 'tool', 'findings_file', and 'finding_count' keys"
    )]
) -> str:
    """
    Aggregate and normalize findings from all scan tools.

    Accepts a variable number of tool results (not limited to 4).
    For each raw finding, calls the configured LLM provider to extract 9
    standardized fields. Writes the consolidated result to the run's local
    store and returns its absolute file path.
    """
    print("[Aggregation] Loading findings from all tools...")

    try:
        scan_results = json.loads(scan_results_json)
    except json.JSONDecodeError as e:
        return f"Error: Failed to parse scan results JSON: {e}"

    all_tool_results = []
    for metadata in scan_results:
        tool_name = metadata.get('tool', 'unknown')
        findings_file = metadata.get('findings_file')

        if findings_file and os.path.exists(findings_file):
            with open(findings_file, 'r') as f:
                tool_data = json.load(f)
                all_tool_results.append(tool_data)
                count = len(tool_data.get('raw_findings', []))
                print(f"  [Aggregation] Loaded {count} findings from {tool_name}")
        else:
            print(f"  [Aggregation] Warning: No findings file for {tool_name}")

    total_raw = sum(len(r.get('raw_findings', [])) for r in all_tool_results)
    print(f"[Aggregation] Total raw findings from all tools: {total_raw}")

    provider = get_provider()
    consolidated = []

    for tool_result in all_tool_results:
        tool_name = tool_result.get('tool', 'unknown')
        raw_findings = tool_result.get('raw_findings', [])

        print(f"[Consolidation] Processing {len(raw_findings)} findings from {tool_name}...")

        for idx, raw_finding in enumerate(raw_findings, 1):
            print(f"  [{tool_name}] Extracting fields from finding {idx}/{len(raw_findings)}...")
            extracted = await _extract_fields(provider, tool_name, raw_finding)
            consolidated.append(extracted)

    print(f"[Consolidation] Extracted {len(consolidated)} total findings")

    data = {
        'scan_timestamp': datetime.utcnow().isoformat(),
        'total_findings': len(consolidated),
        'findings': consolidated
    }
    path = save_json(data, "scan-results")

    print(f"[Aggregation] Wrote aggregated findings to {path}")
    return path


async def _extract_fields(provider: LLMProvider, tool_name: str, raw_finding: dict) -> dict:
    """Use the configured LLM provider to extract 9 standardized fields from a raw finding."""
    prompt = f"""You are a security findings parser. Extract the following fields from this {tool_name} finding:

Required fields:
1. tool_name: Name of the security tool
2. file_path: Path to the file with the issue
3. finding_title: Short title/summary
4. description: Detailed description
5. recommendation: How to fix
6. resource_type: Type of resource (e.g., aws_s3_bucket, Docker, Python function)
7. resource_name: Name/ID of the resource
8. severity: CRITICAL, HIGH, MEDIUM, LOW, or INFO
9. scan_type: SAST, IaC, SCA, Container, or Secrets

Raw finding:
{json.dumps(raw_finding, indent=2)}

Return ONLY valid JSON with these exact field names. If a field is not available, use "N/A"."""

    try:
        return await provider.structured_output(
            schema=FINDING_SCHEMA,
            prompt=prompt,
            temperature=0.0,
            max_tokens=800,
        )
    except Exception as e:
        print(f"    [ERROR] Failed to extract fields: {e}")
        return {
            "tool_name": tool_name,
            "file_path": "N/A",
            "finding_title": "Extraction Error",
            "description": f"Failed to parse: {e}",
            "recommendation": "Manual review required",
            "resource_type": "N/A",
            "resource_name": "N/A",
            "severity": "INFO",
            "scan_type": "N/A",
            "raw_finding": raw_finding
        }
