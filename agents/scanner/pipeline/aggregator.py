"""
Scanner Pipeline - Aggregator
Loads raw findings from all scan tools, normalizes each finding via LLM,
and uploads consolidated results to S3.
"""

import os
import json
from datetime import datetime
from typing import Annotated, List
from pydantic import Field

from shared.base_agent import get_openai_client, get_deployment_name
from shared.s3_helpers import upload_json_to_s3


def aggregate_scan_results(
    scan_results_json: Annotated[str, Field(
        description="JSON string: array of metadata dicts from all scan tools, "
                    "each with 'tool', 'findings_file', and 'finding_count' keys"
    )]
) -> str:
    """
    Aggregate and normalize findings from all scan tools.

    Accepts a variable number of tool results (not limited to 4).
    For each raw finding, calls Azure OpenAI to extract 9 standardized fields.
    Uploads consolidated results to S3 and returns the S3 location.
    """
    print("[Aggregation] Loading findings from all tools...")

    try:
        scan_results = json.loads(scan_results_json)
    except json.JSONDecodeError as e:
        return f"Error: Failed to parse scan results JSON: {e}"

    # Load raw findings from each tool's output file
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

    # Normalize each finding using LLM
    openai_client = get_openai_client()
    deployment = get_deployment_name()
    consolidated = []

    for tool_result in all_tool_results:
        tool_name = tool_result.get('tool', 'unknown')
        raw_findings = tool_result.get('raw_findings', [])

        print(f"[Consolidation] Processing {len(raw_findings)} findings from {tool_name}...")

        for idx, raw_finding in enumerate(raw_findings, 1):
            print(f"  [{tool_name}] Extracting fields from finding {idx}/{len(raw_findings)}...")
            extracted = _extract_fields_sync(openai_client, deployment, tool_name, raw_finding)
            consolidated.append(extracted)

    print(f"[Consolidation] Extracted {len(consolidated)} total findings")

    # Upload to S3
    data = {
        'scan_timestamp': datetime.utcnow().isoformat(),
        'total_findings': len(consolidated),
        'findings': consolidated
    }
    s3_location = upload_json_to_s3(data, "scan-results")

    print(f"[Aggregation] Uploaded to {s3_location}")
    return s3_location


def _extract_fields_sync(openai_client, deployment_name: str, tool_name: str, raw_finding: dict) -> dict:
    """Use Azure OpenAI synchronously to extract 9 standardized fields from a raw finding."""
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
        response = openai_client.chat.completions.create(
            model=deployment_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=800,
            response_format={"type": "json_object"}
        )

        content = response.choices[0].message.content.strip()
        return json.loads(content)

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
