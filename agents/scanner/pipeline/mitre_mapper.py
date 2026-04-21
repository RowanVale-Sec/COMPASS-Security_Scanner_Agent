"""
Scanner Pipeline - MITRE ATT&CK Mapper
Analyzes findings using MITRE ATT&CK framework with multi-agent concurrent approach.
Creates one agent per finding to map to MITRE techniques and adjust severity.

NOTE: This module is currently Azure-only. It uses `AzureOpenAIChatClient`
directly because the MITRE lookup runs through `MCPStreamableHTTPTool`
(agent_framework's MCP client), which is not wired through the
provider-agnostic `LLMProvider` interface yet. Claude MCP support is tracked
separately (see Issue #4: Scanner Revamp with Claude CLI / specialized tools).
If `LLM_PROVIDER=claude`, callers should skip MITRE mapping or use a fallback.
"""

import os
import re
import json
import asyncio
from datetime import datetime
from typing import Annotated
from pydantic import Field

from agent_framework.azure import AzureOpenAIChatClient
from agent_framework._mcp import MCPStreamableHTTPTool

from shared.base_agent import get_azure_api_key, get_azure_endpoint, get_deployment_name
from shared.s3_helpers import download_json_from_s3, upload_json_to_s3


async def analyze_findings_with_mitre(
    s3_location: Annotated[str, Field(description="S3 location (s3://bucket/key) of deduplicated findings")],
) -> str:
    """
    Analyze security findings using MITRE ATT&CK framework with multi-agent approach.

    Creates one agent per finding to map to MITRE techniques and adjust severity.
    Uses concurrent execution with rate limiting (max 15 parallel agents).

    The MITRE MCP server URL is read from the MITRE_MCP_URL env var. Not exposed
    as a tool argument because LLMs tend to hallucinate plausible-looking URLs
    (e.g. `https://mitre-mcp.example.com`) when they see an optional parameter.
    """
    mitre_mcp_url = os.environ.get("MITRE_MCP_URL", "http://mitre-mcp:8000/mcp")
    print(f"[MITRE] Starting multi-agent analysis for findings from {s3_location}")

    try:
        findings_data = download_json_from_s3(s3_location)
    except Exception as e:
        return f"Error downloading findings from S3: {e}"

    findings = findings_data.get('findings', [])
    total_findings = len(findings)

    print(f"[MITRE] Downloaded {total_findings} findings for analysis")
    if total_findings == 0:
        return "No findings to analyze"

    chat_client = AzureOpenAIChatClient(
        endpoint=get_azure_endpoint(),
        api_key=get_azure_api_key(),
        model=get_deployment_name()
    )

    print(f"[MITRE] Connecting to MCP server at {mitre_mcp_url}")

    async with MCPStreamableHTTPTool(name="mitre_attack", url=mitre_mcp_url) as mcp_tool:
        print(f"[MITRE] MCP connected. Creating {total_findings} agents...")

        semaphore = asyncio.Semaphore(15)

        tool_prefixes = {
            'trivy-iac': 'TI', 'trivy-sca': 'TS', 'trivy-secret': 'TX',
            'trivy-image': 'TG', 'checkov': 'C', 'bandit': 'B',
            'semgrep': 'S', 'unknown': 'U'
        }
        tool_counts = {}

        async def analyze_single_finding(finding: dict, index: int) -> dict:
            async with semaphore:
                try:
                    tool_name = finding.get('tool_name', finding.get('tool', 'unknown')).lower()
                    prefix = tool_prefixes.get(tool_name, 'U')

                    if prefix not in tool_counts:
                        tool_counts[prefix] = 0
                    tool_counts[prefix] += 1

                    finding_id = f"FND-{prefix}-{tool_counts[prefix]}"

                    title = finding.get('finding_title', finding.get('title', 'N/A'))
                    description = finding.get('description', 'N/A')
                    severity = finding.get('severity', 'UNKNOWN')
                    file_path = finding.get('file_path', 'N/A')
                    resource_type = finding.get('resource_type', 'N/A')
                    scan_type = finding.get('scan_type', 'N/A')

                    print(f"[MITRE] Agent {index + 1}/{total_findings}: Analyzing {finding_id}")

                    instructions = f"""You are an expert security analyst specializing in MITRE ATT&CK framework.

**Finding to Analyze:**
- Finding ID: {finding_id}
- Tool: {tool_name}
- File: {file_path}
- Resource Type: {resource_type}
- Title: {title}
- Description: {description}
- Scan Type: {scan_type}
- Original Severity: {severity}

**Steps:**
1. Extract the threat behavior from this finding
2. USE MITRE ATT&CK tools to search for matching techniques
3. Map to a MITRE technique (T#### format)
4. Adjust severity based on MITRE tactic context:
   - CRITICAL: Privilege Escalation, Credential Access, Initial Access, Execution
   - HIGH: Lateral Movement, Persistence, Impact, Defense Evasion
   - MEDIUM: Discovery, Collection, Command and Control
   - LOW: Informational findings

Return ONLY valid JSON:
{{"technique_id": "T####", "technique_name": "...", "tactic": "...", "adjusted_severity": "CRITICAL|HIGH|MEDIUM|LOW", "confidence": "HIGH|MEDIUM|LOW", "rationale": "..."}}"""

                    agent = chat_client.create_agent(
                        name=f"ThreatAnalyst_{finding_id}",
                        instructions=instructions,
                        tools=[mcp_tool]
                    )
                    result = await agent.run(f"Analyze finding {finding_id} and map to MITRE ATT&CK")

                    analysis_text = str(result.text) if hasattr(result, 'text') else str(result)

                    mitre_data = {
                        "technique_id": "UNMAPPED",
                        "technique_name": "Unable to map",
                        "tactic": "Unknown",
                        "adjusted_severity": severity,
                        "confidence": "LOW",
                        "rationale": analysis_text[:500]
                    }

                    # Strategy 1: parse full text as JSON directly
                    _parsed = None
                    try:
                        _parsed = json.loads(analysis_text)
                    except (json.JSONDecodeError, ValueError):
                        pass

                    # Strategy 2: find outermost balanced {...} block containing technique_id
                    if _parsed is None and '"technique_id"' in analysis_text:
                        for _start in range(len(analysis_text)):
                            if analysis_text[_start] != '{':
                                continue
                            _depth = 0
                            for _end in range(_start, len(analysis_text)):
                                if analysis_text[_end] == '{':
                                    _depth += 1
                                elif analysis_text[_end] == '}':
                                    _depth -= 1
                                    if _depth == 0:
                                        try:
                                            candidate = json.loads(analysis_text[_start:_end + 1])
                                            if 'technique_id' in candidate:
                                                _parsed = candidate
                                        except (json.JSONDecodeError, ValueError):
                                            pass
                                        break
                            if _parsed is not None:
                                break

                    if _parsed is not None:
                        mitre_data.update(_parsed)
                    else:
                        # Strategy 3: regex fallback — recover bare technique ID only
                        tid_match = re.search(r'T\d{4}(?:\.\d{3})?', analysis_text)
                        if tid_match:
                            mitre_data['technique_id'] = tid_match.group(0)

                    print(f"[MITRE] Agent {index + 1}/{total_findings}: {finding_id} -> {mitre_data['technique_id']}")

                    return {
                        finding_id: {
                            "finding": finding,
                            "mitre_analysis": mitre_data
                        }
                    }

                except Exception as e:
                    print(f"[MITRE] Agent {index + 1}/{total_findings}: Error: {e}")
                    return {
                        f"FND-ERR-{index}": {
                            "finding": finding,
                            "mitre_analysis": {
                                "technique_id": "ERROR",
                                "technique_name": "Analysis Failed",
                                "tactic": "N/A",
                                "adjusted_severity": "UNKNOWN",
                                "confidence": "NONE",
                                "rationale": f"Error: {str(e)}"
                            }
                        }
                    }

        print(f"[MITRE] Starting concurrent analysis (max 15 parallel)...")
        results = await asyncio.gather(*(
            analyze_single_finding(finding, idx)
            for idx, finding in enumerate(findings)
        ))

        print(f"[MITRE] All agents completed. Processing results...")

        mitre_mapped = {
            "metadata": {
                "analysis_date": datetime.utcnow().isoformat(),
                "total_findings": total_findings,
                "mitre_mcp_url": mitre_mcp_url,
                "source_file": s3_location,
                "tool_distribution": dict(tool_counts)
            }
        }

        for result in results:
            mitre_mapped.update(result)

        s3_loc = upload_json_to_s3(mitre_mapped, "mitre-mapped-findings")

        mapped_count = sum(1 for r in results if not any('ERR' in k for k in r.keys()))
        error_count = sum(1 for r in results if any('ERR' in k for k in r.keys()))
        print(f"[MITRE] Complete: {mapped_count} mapped, {error_count} errors")
        print(f"[MITRE] Uploaded to {s3_loc}")

        return s3_loc
