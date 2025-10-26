#!/usr/bin/env python3
"""Intelligent Security Scanning Agent - API Key Authentication"""

import asyncio
import os
import subprocess
import json
import boto3
from pathlib import Path
from datetime import datetime
from typing import Annotated
from pydantic import Field
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

from agent_framework.azure import AzureOpenAIChatClient
from agent_framework._mcp import MCPStreamableHTTPTool

try:
    from agent_framework.exceptions import ServiceResponseException  # type: ignore[import]
except ImportError:  # pragma: no cover - fallback for local tooling without agent-framework installed
    ServiceResponseException = Exception  # type: ignore

# ============================================================================
# CREDENTIAL CONFIGURATION - API KEY BASED
# ============================================================================

def get_azure_api_key() -> str:
    """Get Azure OpenAI API key for agent authentication."""
    api_key = os.environ.get('AZURE_OPENAI_API_KEY')
    if not api_key:
        raise ValueError("AZURE_OPENAI_API_KEY environment variable is required")
    return api_key


def get_s3_client():
    """Get S3 client using API keys"""
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_region = os.environ.get('AWS_REGION', 'us-east-1')
    
    if not aws_access_key or not aws_secret_key:
        raise ValueError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are required")
    
    return boto3.client(
        's3',
        aws_access_key_id=aws_access_key,
        aws_secret_access_key=aws_secret_key,
        region_name=aws_region
    )


# ============================================================================
# TOOL DEFINITIONS
# ============================================================================

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
        return {"tool": "checkov", "findings_file": None, "finding_count": 0, "note": f"Checkov completed but no output. Return code: {result.returncode}"}
    
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "checkov", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}
    
    # Extract raw findings
    raw_findings = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                raw_findings.extend(item.get('results', {}).get('failed_checks', []))
    elif isinstance(data, dict):
        raw_findings = data.get('results', {}).get('failed_checks', [])
    
    # Save to file instead of returning all findings
    output_file = "/tmp/checkov_findings.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "checkov", "raw_findings": raw_findings}, f)
    
    return {
        "tool": "checkov",
        "findings_file": output_file,
        "finding_count": len(raw_findings)
    }


def scan_with_trivy(
    folder_path: Annotated[str, Field(description="Path to scan for misconfigurations")]
) -> dict:
    """Scan for IaC misconfigurations with Trivy. Saves raw findings to file."""
    print(f"[Tool] Running Trivy on {folder_path}")
    
    try:
        result = subprocess.run(
            ['trivy', 'config', folder_path, '--format', 'json'],
            capture_output=True,
            text=True,
            timeout=300
        )
    except FileNotFoundError:
        return {"tool": "trivy", "error": "Trivy not installed", "findings_file": None, "finding_count": 0}
    except Exception as e:
        return {"tool": "trivy", "error": str(e), "findings_file": None, "finding_count": 0}
    
    if not result.stdout:
        return {"tool": "trivy", "findings_file": None, "finding_count": 0, "note": f"Trivy completed but no output. Return code: {result.returncode}"}
    
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "trivy", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}
    
    # Extract raw findings
    raw_findings = []
    for scan_result in data.get('Results', []):
        for misconf in scan_result.get('Misconfigurations', []):
            # Add parent context to each finding
            misconf['_trivy_target'] = scan_result.get('Target', '')
            raw_findings.append(misconf)
    
    # Save to file instead of returning all findings
    output_file = "/tmp/trivy_findings.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "trivy", "raw_findings": raw_findings}, f)
    
    return {
        "tool": "trivy",
        "findings_file": output_file,
        "finding_count": len(raw_findings)
    }


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
        return {"tool": "bandit", "findings_file": None, "finding_count": 0, "note": f"Bandit completed but no output. Return code: {result.returncode}"}
    
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "bandit", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}
    
    raw_findings = data.get('results', [])
    
    # Save to file instead of returning all findings
    output_file = "/tmp/bandit_findings.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "bandit", "raw_findings": raw_findings}, f)
    
    return {
        "tool": "bandit",
        "findings_file": output_file,
        "finding_count": len(raw_findings)
    }


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
        return {"tool": "semgrep", "findings_file": None, "finding_count": 0, "note": f"Semgrep completed but no output. Return code: {result.returncode}"}
    
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return {"tool": "semgrep", "error": f"Failed to parse JSON: {e}", "findings_file": None, "finding_count": 0}
    
    raw_findings = data.get('results', [])
    
    # Save to file instead of returning all findings
    output_file = "/tmp/semgrep_findings.json"
    with open(output_file, 'w') as f:
        json.dump({"tool": "semgrep", "raw_findings": raw_findings}, f)
    
    return {
        "tool": "semgrep",
        "findings_file": output_file,
        "finding_count": len(raw_findings)
    }


def upload_results_to_s3(
    findings_json: Annotated[str, Field(description="JSON string with scan findings")],
    bucket_name: Annotated[str, Field(description="S3 bucket name")]
) -> str:
    """Upload scan results to S3 using API keys."""
    print(f"[Tool] Uploading results to S3 bucket: {bucket_name}")
    
    s3_client = get_s3_client()
    
    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    key = f"scan-results/agent-scan-{timestamp}.json"
    
    s3_client.put_object(
        Bucket=bucket_name,
        Key=key,
        Body=findings_json,
        ContentType='application/json'
    )
    
    return f"s3://{bucket_name}/{key}"


def deduplicate_findings_from_s3(
    s3_location: Annotated[str, Field(description="S3 location (s3://bucket/key) of findings to deduplicate")]
) -> str:
    """
    Download findings from S3, deduplicate using embeddings, and re-upload.
    
    This function:
    1. Downloads findings from S3
    2. Generates embeddings for semantic similarity
    3. Clusters similar findings
    4. Uploads deduplicated results to S3
    
    Args:
        s3_location: S3 URI (e.g., s3://bucket/scan-results/file.json)
        
    Returns:
        S3 location of deduplicated findings
    """
    print(f"[Dedup] Downloading findings from {s3_location}")
    
    # Parse S3 location
    if not s3_location.startswith('s3://'):
        return f"Error: Invalid S3 location format: {s3_location}"
    
    parts = s3_location[5:].split('/', 1)
    if len(parts) != 2:
        return f"Error: Invalid S3 location format: {s3_location}"
    
    bucket_name, key = parts
    
    # Download from S3
    s3_client = get_s3_client()
    
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=key)
        findings_data = json.loads(response['Body'].read().decode('utf-8'))
    except Exception as e:
        return f"Error downloading from S3: {e}"
    
    original_findings = findings_data.get('findings', [])
    original_count = len(original_findings)
    
    print(f"[Dedup] Downloaded {original_count} findings")
    
    if original_count == 0:
        return f"Error: No findings found in {s3_location}"
    
    # Deduplicate using embeddings
    try:
        from openai import AzureOpenAI
        import numpy as np
        from sklearn.metrics.pairwise import cosine_similarity
        
        api_key = get_azure_api_key()
        azure_endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
        api_version = os.environ.get('AZURE_OPENAI_API_VERSION', '2024-08-01-preview')
        
        openai_client = AzureOpenAI(
            api_key=api_key,
            azure_endpoint=azure_endpoint,
            api_version=api_version
        )
        
        print("[Dedup] Generating embeddings for semantic similarity...")
        
        # Generate embeddings
        embeddings = []
        for idx, finding in enumerate(original_findings):
            # Create text representation
            text = f"""
            Title: {finding.get('finding_title', '')}
            Description: {finding.get('description', '')}
            File: {finding.get('file_path', '')}
            Resource: {finding.get('resource_name', '')}
            Severity: {finding.get('severity', '')}
            """.strip()
            
            response = openai_client.embeddings.create(
                model="text-embedding-ada-002",
                input=text
            )
            embeddings.append(response.data[0].embedding)
            
            if (idx + 1) % 10 == 0:
                print(f"  Generated {idx + 1}/{original_count} embeddings")
        
        print(f"[Dedup] Generated {len(embeddings)} embeddings")
        
        # Cluster similar findings
        embeddings_array = np.array(embeddings)
        similarity_matrix = cosine_similarity(embeddings_array)
        
        threshold = 0.85  # 85% similarity threshold
        clusters = []
        processed = set()
        
        for i in range(len(original_findings)):
            if i in processed:
                continue
            
            cluster = [original_findings[i]]
            cluster_indices = [i]
            processed.add(i)
            
            # Find similar findings
            for j in range(i + 1, len(original_findings)):
                if j not in processed and similarity_matrix[i][j] >= threshold:
                    cluster.append(original_findings[j])
                    cluster_indices.append(j)
                    processed.add(j)
            
            clusters.append((cluster, cluster_indices))
        
        print(f"[Dedup] Found {len(clusters)} clusters")
        
        # Build deduplicated findings
        unique_findings = []
        duplicates_removed = 0
        
        for cluster, indices in clusters:
            if len(cluster) == 1:
                # Single finding, keep as is
                unique_findings.append(cluster[0])
            else:
                # Multiple similar findings - merge
                print(f"  Merging {len(cluster)} similar findings:")
                for idx, finding in enumerate(cluster):
                    print(f"    - [{finding.get('tool_name')}] {finding.get('finding_title', 'N/A')}")
                
                # Use the first finding as primary, add metadata
                primary = cluster[0].copy()
                primary['detected_by_tools'] = list(set([f.get('tool_name', 'unknown') for f in cluster]))
                primary['duplicate_count'] = len(cluster)
                primary['merged_from_indices'] = indices
                
                # Combine recommendations if different
                recommendations = set()
                for f in cluster:
                    rec = f.get('recommendation', '')
                    if rec and rec != 'N/A':
                        recommendations.add(rec)
                
                if len(recommendations) > 1:
                    primary['combined_recommendations'] = list(recommendations)
                
                unique_findings.append(primary)
                duplicates_removed += len(cluster) - 1
        
        print(f"[Dedup] Deduplicated: {original_count} → {len(unique_findings)} findings")
        print(f"[Dedup] Removed {duplicates_removed} duplicates ({100*duplicates_removed/original_count:.1f}% reduction)")
        
        # Build deduplicated JSON
        deduplicated_data = {
            'scan_timestamp': findings_data.get('scan_timestamp'),
            'deduplication_timestamp': datetime.utcnow().isoformat(),
            'original_finding_count': original_count,
            'deduplicated_finding_count': len(unique_findings),
            'duplicates_removed': duplicates_removed,
            'reduction_percentage': round(100 * duplicates_removed / original_count, 1),
            'similarity_threshold': threshold,
            'findings': unique_findings
        }
        
        deduplicated_json = json.dumps(deduplicated_data, indent=2)
        
        # Upload deduplicated results to S3
        timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        dedup_key = f"scan-results/agent-scan-{timestamp}-deduplicated.json"
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key=dedup_key,
            Body=deduplicated_json,
            ContentType='application/json'
        )
        
        dedup_location = f"s3://{bucket_name}/{dedup_key}"
        print(f"[Dedup] Uploaded deduplicated results to {dedup_location}")
        
        return dedup_location
        
    except Exception as e:
        import traceback
        error_msg = f"Error during deduplication: {e}\n{traceback.format_exc()}"
        print(f"[Dedup] {error_msg}")
        return f"Error: {error_msg}"


async def analyze_findings_with_mitre(
    s3_location: Annotated[str, Field(description="S3 location (s3://bucket/key) of deduplicated findings")],
    mitre_mcp_url: Annotated[str, Field(description="MITRE MCP server URL")] = "http://mitre-mcp:8000/mcp"
) -> str:
    """
    Analyze security findings using MITRE ATT&CK framework with multi-agent approach.
    
    Creates one agent per finding to map to MITRE techniques and adjust severity.
    Uses concurrent execution with rate limiting to handle multiple findings efficiently.
    
    Args:
        s3_location: S3 URI of deduplicated findings (e.g., s3://bucket/dedup-results/file.json)
        mitre_mcp_url: URL of MITRE MCP server (default: http://mitre-mcp:8000/mcp)
        
    Returns:
        S3 location of MITRE-mapped findings with adjusted severity
    """
    print(f"[MITRE] Starting multi-agent analysis for findings from {s3_location}")
    
    # Parse S3 location
    if not s3_location.startswith('s3://'):
        return f"Error: Invalid S3 location format: {s3_location}"
    
    parts = s3_location[5:].split('/', 1)
    if len(parts) != 2:
        return f"Error: Invalid S3 path format: {s3_location}"
    
    bucket_name, key = parts
    
    # Download findings from S3
    s3_client = get_s3_client()
    
    try:
        response = s3_client.get_object(Bucket=bucket_name, Key=key)
        findings_json = response['Body'].read().decode('utf-8')
        findings_data = json.loads(findings_json)
    except Exception as e:
        return f"Error downloading findings from S3: {e}"
    
    findings = findings_data.get('findings', [])
    total_findings = len(findings)
    
    print(f"[MITRE] Downloaded {total_findings} findings for analysis")
    
    if total_findings == 0:
        return "No findings to analyze"
    
    # Get Azure OpenAI credentials
    api_key = get_azure_api_key()
    endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
    deployment = os.environ.get('AZURE_OPENAI_CHAT_DEPLOYMENT_NAME', 'gpt-4o')
    
    # Create chat client
    chat_client = AzureOpenAIChatClient(
        endpoint=endpoint,
        api_key=api_key,
        model=deployment
    )
    
    # Connect to MITRE MCP server
    print(f"[MITRE] Connecting to MCP server at {mitre_mcp_url}")
    
    async with MCPStreamableHTTPTool(
        name="mitre_attack",
        url=mitre_mcp_url,
    ) as mcp_tool:
        
        print(f"[MITRE] MCP connected. Creating {total_findings} agents...")
        
        # Semaphore for rate limiting (max 15 concurrent agents)
        semaphore = asyncio.Semaphore(15)
        
        # Tool name prefixes for unique IDs
        tool_prefixes = {
            'trivy': 'T',
            'checkov': 'C',
            'bandit': 'B',
            'semgrep': 'S',
            'unknown': 'U'
        }
        
        # Track counts per tool
        tool_counts = {}
        
        async def analyze_single_finding(finding: dict, index: int) -> dict:
            """Analyze a single finding with a dedicated agent"""
            async with semaphore:
                try:
                    # Generate unique finding ID based on tool
                    tool_name = finding.get('tool_name', finding.get('tool', 'unknown')).lower()
                    tool_prefix = tool_prefixes.get(tool_name, 'U')
                    
                    # Increment count for this tool
                    if tool_prefix not in tool_counts:
                        tool_counts[tool_prefix] = 0
                    tool_counts[tool_prefix] += 1
                    
                    unique_finding_id = f"FND-{tool_prefix}-{tool_counts[tool_prefix]}"
                    
                    # Extract finding details
                    file_path = finding.get('file_path', 'N/A')
                    title = finding.get('finding_title', finding.get('title', 'N/A'))
                    description = finding.get('description', 'N/A')
                    recommendation = finding.get('recommendation', 'N/A')
                    resource_type = finding.get('resource_type', 'N/A')
                    resource_name = finding.get('resource_name', 'N/A')
                    severity = finding.get('severity', 'UNKNOWN')
                    scan_type = finding.get('scan_type', 'N/A')
                    
                    print(f"[MITRE] Agent {index+1}/{total_findings}: Analyzing {unique_finding_id}")
                    
                    # Create agent with enhanced MITRE tool
                    agent = chat_client.create_agent(
                        name=f"ThreatAnalyst_{unique_finding_id}",
                        instructions=f"""You are an expert security analyst specializing in MITRE ATT&CK framework threat intelligence.

**CRITICAL: You MUST use the MITRE ATT&CK tools to search for techniques. Do NOT say "insufficient information".**

**Finding to Analyze:**
- Finding ID: {unique_finding_id}
- Security Tool: {tool_name}
- File/Resource: {file_path}
- Resource Type: {resource_type}
- Resource Name: {resource_name}
- Issue Title: {title}
- Description: {description}
- Recommendation: {recommendation}
- Scan Type: {scan_type}
- Original Severity: {severity}

**Your Analysis Steps:**

1. **EXTRACT THE THREAT BEHAVIOR** from the finding:
   - What is the security risk? (e.g., "privilege escalation", "credential exposure", "network access", "encryption missing")
   - What attack vector does this enable? (e.g., "container escape", "data exfiltration", "unauthorized access")
   - What resource is vulnerable? (e.g., "IAM policy", "container", "database", "network interface")

2. **USE MITRE ATT&CK TOOLS** - You MUST call one or more of these:
   - `get_techniques` - Search for techniques matching the threat behavior
   - `get_tactics` - List all tactics to understand categories
   - `get_technique_by_id` - Get details if you know a technique ID
   - Search keywords: Use terms like "privilege", "escape", "credential", "access", "execution", "persistence"

3. **MAP TO MITRE TECHNIQUE**:
   - Identify the PRIMARY technique that matches this vulnerability
   - Get the technique ID (format: T####)
   - Get the tactic category (e.g., "Privilege Escalation", "Defense Evasion")

4. **ADJUST SEVERITY** based on MITRE context:
   - **CRITICAL**: Privilege Escalation, Credential Access, Initial Access, Execution with high impact
   - **HIGH**: Lateral Movement, Persistence, Impact, Defense Evasion
   - **MEDIUM**: Discovery, Collection, Command and Control
   - **LOW**: Informational findings with minimal exploit potential

5. **RETURN STRUCTURED JSON** (EXACTLY this format):
```json
{{
  "technique_id": "T####",
  "technique_name": "Name of MITRE Technique",
  "tactic": "MITRE Tactic Category",
  "adjusted_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "rationale": "2-3 sentence explanation of why this technique matches and severity adjustment"
}}
```

**EXAMPLE for Container Privilege Escalation:**
Finding: "Container allows privilege escalation"
→ Search: get_techniques with "privilege escalation container"
→ Result: T1611 - Escape to Host
→ Adjusted Severity: CRITICAL (enables host compromise)

**NOW ANALYZE {unique_finding_id} - USE THE TOOLS!**
""",
                        tools=[mcp_tool]
                    )
                    
                    # Run agent analysis
                    result = await agent.run(f"Analyze security finding {unique_finding_id} and map to MITRE ATT&CK technique")
                    
                    # Extract response and parse JSON
                    analysis_text = str(result.text) if hasattr(result, 'text') else str(result)
                    
                    # Try to extract structured data from response
                    import re
                    mitre_data = {
                        "technique_id": "UNMAPPED",
                        "technique_name": "Unable to map",
                        "tactic": "Unknown",
                        "adjusted_severity": severity,
                        "confidence": "LOW",
                        "rationale": analysis_text[:500]  # Truncate long responses
                    }
                    
                    # Try to parse JSON from response
                    try:
                        json_match = re.search(r'\{[^{}]*"technique_id"[^{}]*\}', analysis_text, re.DOTALL)
                        if json_match:
                            parsed = json.loads(json_match.group(0))
                            mitre_data.update(parsed)
                    except:
                        # Fallback: extract fields using regex
                        tid_match = re.search(r'[Tt]echnique[_\s]*[Ii][Dd].*?(T\d{4}(?:\.\d{3})?)', analysis_text)
                        if tid_match:
                            mitre_data['technique_id'] = tid_match.group(1)
                        
                        tname_match = re.search(r'[Tt]echnique[_\s]*[Nn]ame.*?:[\s]*([\w\s]+?)(?:\n|$)', analysis_text)
                        if tname_match:
                            mitre_data['technique_name'] = tname_match.group(1).strip()
                        
                        tactic_match = re.search(r'[Tt]actic.*?:[\s]*([\w\s]+?)(?:\n|$)', analysis_text)
                        if tactic_match:
                            mitre_data['tactic'] = tactic_match.group(1).strip()
                        
                        sev_match = re.search(r'[Aa]djusted[_\s]*[Ss]everity.*?:[\s]*(CRITICAL|HIGH|MEDIUM|LOW)', analysis_text, re.IGNORECASE)
                        if sev_match:
                            mitre_data['adjusted_severity'] = sev_match.group(1).upper()
                    
                    print(f"[MITRE] Agent {index+1}/{total_findings}: Completed {unique_finding_id} → {mitre_data['technique_id']}")
                    
                    return {
                        unique_finding_id: {
                            "finding": finding,
                            "mitre_analysis": mitre_data
                        }
                    }
                    
                except Exception as e:
                    print(f"[MITRE] Agent {index+1}/{total_findings}: Error analyzing {unique_finding_id}: {e}")
                    return {
                        f"FND-ERR-{index}": {
                            "finding": finding,
                            "mitre_analysis": {
                                "technique_id": "ERROR",
                                "technique_name": "Analysis Failed",
                                "tactic": "N/A",
                                "adjusted_severity": "UNKNOWN",
                                "confidence": "NONE",
                                "rationale": f"Error during analysis: {str(e)}"
                            }
                        }
                    }
        
        # Run all agents concurrently with rate limiting
        print(f"[MITRE] Starting concurrent analysis (max 15 parallel agents)...")
        
        results = await asyncio.gather(*[
            analyze_single_finding(finding, idx)
            for idx, finding in enumerate(findings)
        ])
        
        print(f"[MITRE] All agents completed. Processing results...")
        
        # Consolidate results into single dict
        mitre_mapped_findings = {
            "metadata": {
                "analysis_date": datetime.utcnow().isoformat(),
                "total_findings": total_findings,
                "mitre_mcp_url": mitre_mcp_url,
                "source_file": s3_location,
                "tool_distribution": dict(tool_counts)
            }
        }
        
        # Merge all finding dicts
        for result in results:
            mitre_mapped_findings.update(result)
        
        # Upload to S3
        timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        mitre_key = f"mitre-mapped-findings/mitre-analysis-{timestamp}.json"
        
        s3_client.put_object(
            Bucket=bucket_name,
            Key=mitre_key,
            Body=json.dumps(mitre_mapped_findings, indent=2),
            ContentType='application/json'
        )
        
        mitre_location = f"s3://{bucket_name}/{mitre_key}"
        print(f"[MITRE] Uploaded MITRE-mapped findings to {mitre_location}")
        
        # Summary stats
        mapped_count = sum(1 for r in results if 'FND-' in list(r.keys())[0] and 'ERR' not in list(r.keys())[0])
        error_count = sum(1 for r in results if 'ERR' in list(r.keys())[0])
        
        print(f"[MITRE] Analysis complete: {mapped_count} mapped, {error_count} errors")
        
        return mitre_location


def aggregate_scan_results(
    checkov_result: Annotated[dict, Field(description="Metadata dict from scan_with_checkov")],
    trivy_result: Annotated[dict, Field(description="Metadata dict from scan_with_trivy")],
    bandit_result: Annotated[dict, Field(description="Metadata dict from scan_python_code_with_bandit")],
    semgrep_result: Annotated[dict, Field(description="Metadata dict from scan_code_with_semgrep")]
) -> str:
    """
    Aggregate, consolidate, and upload scan results in ONE synchronous function.
    
    This tool:
    1. Loads all findings from files
    2. Extracts fields from each finding using LLM (synchronously)
    3. Uploads consolidated results to S3
    4. Returns S3 location
    
    Args:
        checkov_result: Metadata dict from Checkov scan
        trivy_result: Metadata dict from Trivy scan
        bandit_result: Metadata dict from Bandit scan
        semgrep_result: Metadata dict from Semgrep scan
        
    Returns:
        S3 location of uploaded consolidated findings
    """
    print("[Aggregation] Loading findings from all tools...")
    
    all_results = []
    
    # Parse metadata and load findings from files
    for tool_name, metadata in [
        ("checkov", checkov_result),
        ("trivy", trivy_result),
        ("bandit", bandit_result),
        ("semgrep", semgrep_result)
    ]:
        if metadata:
            try:
                findings_file = metadata.get('findings_file')
                
                if findings_file and os.path.exists(findings_file):
                    with open(findings_file, 'r') as f:
                        tool_data = json.load(f)
                        all_results.append(tool_data)
                        finding_count = len(tool_data.get('raw_findings', []))
                        print(f"  [Aggregation] Loaded {finding_count} findings from {tool_name}")
                else:
                    print(f"  [Aggregation] Warning: No findings file for {tool_name}")
            except Exception as e:
                print(f"  [Aggregation] Warning: Failed to load {tool_name} findings: {e}")
    
    total_findings = sum(len(r.get('raw_findings', [])) for r in all_results)
    print(f"[Aggregation] Total raw findings from all tools: {total_findings}")
    
    # CONSOLIDATE: Extract fields from each finding synchronously
    print("[Consolidation] Starting field extraction from raw findings...")
    
    try:
        from openai import AzureOpenAI  # Use SYNC client
        
        api_key = get_azure_api_key()
        azure_endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
        deployment_name = os.environ.get('AZURE_OPENAI_CHAT_DEPLOYMENT_NAME') or os.environ.get('AZURE_OPENAI_DEPLOYMENT')
        api_version = os.environ.get('AZURE_OPENAI_API_VERSION', '2024-08-01-preview')
        
        openai_client = AzureOpenAI(
            api_key=api_key,
            azure_endpoint=azure_endpoint,
            api_version=api_version
        )
    except Exception as e:
        return f"Error: Failed to create Azure OpenAI client: {e}"
    
    # Process findings from each tool
    consolidated_findings = []
    
    for tool_result in all_results:
        tool_name = tool_result.get('tool', 'unknown')
        raw_findings = tool_result.get('raw_findings', [])
        
        print(f"[Consolidation] Processing {len(raw_findings)} findings from {tool_name}...")
        
        # Loop through EACH finding individually
        for idx, raw_finding in enumerate(raw_findings, 1):
            print(f"  [{tool_name}] Extracting fields from finding {idx}/{len(raw_findings)}...")
            
            # Call LLM for THIS single finding (SYNC)
            extracted_finding = _extract_fields_sync(
                openai_client, 
                deployment_name, 
                tool_name, 
                raw_finding
            )
            consolidated_findings.append(extracted_finding)
    
    print(f"[Consolidation] Extracted {len(consolidated_findings)} total findings")
    
    # Build final JSON
    final_json = json.dumps({
        'scan_timestamp': datetime.utcnow().isoformat(),
        'total_findings': len(consolidated_findings),
        'findings': consolidated_findings
    }, indent=2)
    
    # Upload to S3
    bucket = os.environ.get('S3_BUCKET', 'my-security-scans')
    print(f"[Tool] Uploading results to S3 bucket: {bucket}")
    
    s3_client = get_s3_client()
    timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
    key = f"scan-results/agent-scan-{timestamp}.json"
    
    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=final_json,
        ContentType='application/json'
    )
    
    return f"s3://{bucket}/{key}"


def _extract_fields_sync(openai_client, deployment_name: str, tool_name: str, raw_finding: dict) -> dict:
    """
    Use Azure OpenAI SYNCHRONOUSLY to extract standardized fields from a single raw finding.
    """
    prompt = f"""You are a security findings parser. Extract the following fields from this {tool_name} finding:

Required fields:
1. tool_name: Name of the security tool
2. file_path: Path to the file with the issue
3. finding_title: Short title/summary
4. description: Detailed description
5. recommendation: How to fix
6. resource_type: Type of resource (e.g., aws_s3_bucket, Docker, Python function)
7. resource_name: Name/ID of the resource
8. severity: HIGH, MEDIUM, LOW, or INFO
9. scan_type: SAST, IaC, Container, or Secrets

Raw finding:
{json.dumps(raw_finding, indent=2)}

Return ONLY valid JSON with these exact field names. If a field is not available, use "N/A"."""

    try:
        response = openai_client.chat.completions.create(
            model=deployment_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=800
        )
        
        content = response.choices[0].message.content.strip()
        
        # Parse LLM response
        if content.startswith('```json'):
            content = content[7:]
        if content.startswith('```'):
            content = content[3:]
        if content.endswith('```'):
            content = content[:-3]
        content = content.strip()
        
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


# ============================================================================
# LLM-BASED FIELD EXTRACTION
# ============================================================================

async def extract_fields_from_raw_finding(openai_client, deployment_name: str, tool_name: str, raw_finding: dict) -> dict:
    """
    Use Azure OpenAI to extract standardized fields from a single raw finding.
    
    Args:
        openai_client: AsyncAzureOpenAI client instance
        deployment_name: Azure OpenAI deployment name
        tool_name: Name of the security tool (checkov, trivy, bandit, semgrep)
        raw_finding: Single raw finding dict from the tool
        
    Returns:
        Dict with 9 standardized fields
    """
    prompt = f"""Extract security finding fields from this {tool_name} raw output.

Raw Finding JSON:
{json.dumps(raw_finding, indent=2)}

Extract these EXACT 9 fields:
1. tool_name: "{tool_name}"
2. file_path: Path to the file with the security issue
3. finding_title: Clear, concise title of the security issue
4. description: Detailed description of what's wrong
5. recommendation: How to fix the issue
6. resource_type: Type of resource (e.g., aws_eks_cluster, Python Code, Terraform, etc.)
7. resource_name: Specific resource identifier or location
8. severity: CRITICAL, HIGH, MEDIUM, LOW, or UNKNOWN
9. scan_type: IaC, SAST, Secret, Container, or other category

Return ONLY a valid JSON object with these 9 keys. No markdown, no explanation."""

    try:
        # Direct completion call for single finding
        response = await openai_client.chat.completions.create(
            model=deployment_name,
            messages=[
                {"role": "system", "content": "You extract structured data from security scan results. Return only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0,
            max_tokens=500
        )
        
        response_text = response.choices[0].message.content.strip()
        
        # Remove markdown code blocks if present
        if response_text.startswith('```'):
            response_text = response_text.split('```')[1]
            if response_text.startswith('json'):
                response_text = response_text[4:]
            response_text = response_text.strip()
        
        extracted = json.loads(response_text)
        
        # Ensure all 9 fields are present
        required_fields = ['tool_name', 'file_path', 'finding_title', 'description', 
                          'recommendation', 'resource_type', 'resource_name', 'severity', 'scan_type']
        for field in required_fields:
            if field not in extracted:
                extracted[field] = ''
        
        return extracted
        
    except Exception as e:
        print(f"[ERROR] Failed to extract fields: {e}")
        return {
            'tool_name': tool_name,
            'file_path': '',
            'finding_title': 'EXTRACTION_FAILED',
            'description': f'LLM extraction failed: {str(e)}',
            'recommendation': 'Review raw finding manually',
            'resource_type': '',
            'resource_name': '',
            'severity': 'UNKNOWN',
            'scan_type': 'Unknown',
            'raw_finding': raw_finding  # Include for manual review
        }


async def consolidate_and_upload_findings(
    scan_results: Annotated[str, Field(description="JSON string containing all scan results from all tools")],
    bucket_name: Annotated[str, Field(description="S3 bucket name")]
) -> str:
    """
    Process all raw findings through LLM extraction, consolidate, and upload to S3.
    
    This function:
    1. Parses scan results from all tools
    2. Loops through each raw finding ONE BY ONE
    3. Calls Azure OpenAI to extract standardized fields for EACH finding
    4. Builds consolidated JSON with all findings
    5. Uploads to S3
    
    Returns S3 location of uploaded results.
    """
    print("[Consolidation] Starting field extraction from raw findings...")
    
    # Parse scan results
    try:
        all_scan_results = json.loads(scan_results)
    except json.JSONDecodeError as e:
        return f"Error: Failed to parse scan results JSON: {e}"
    
    # Create single Azure OpenAI client for all extractions
    try:
        from openai import AsyncAzureOpenAI
        
        api_key = get_azure_api_key()
        azure_endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
        deployment_name = os.environ.get('AZURE_OPENAI_CHAT_DEPLOYMENT_NAME') or os.environ.get('AZURE_OPENAI_DEPLOYMENT')
        api_version = os.environ.get('AZURE_OPENAI_API_VERSION', '2024-08-01-preview')
        
        openai_client = AsyncAzureOpenAI(
            api_key=api_key,
            azure_endpoint=azure_endpoint,
            api_version=api_version
        )
    except Exception as e:
        return f"Error: Failed to create Azure OpenAI client: {e}"
    
    # Process findings from each tool
    consolidated_findings = []
    
    for tool_result in all_scan_results:
        tool_name = tool_result.get('tool', 'unknown')
        raw_findings = tool_result.get('raw_findings', [])
        
        print(f"[Consolidation] Processing {len(raw_findings)} findings from {tool_name}...")
        
        # Loop through EACH finding individually
        for idx, raw_finding in enumerate(raw_findings, 1):
            print(f"  [{tool_name}] Extracting fields from finding {idx}/{len(raw_findings)}...")
            
            # Call LLM for THIS single finding
            extracted_finding = await extract_fields_from_raw_finding(
                openai_client, 
                deployment_name, 
                tool_name, 
                raw_finding  # Single finding, not the entire array
            )
            consolidated_findings.append(extracted_finding)
    
    # Build final JSON
    final_json = json.dumps({
        'scan_timestamp': datetime.utcnow().isoformat(),
        'total_findings': len(consolidated_findings),
        'findings': consolidated_findings
    }, indent=2)
    
    print(f"[Consolidation] Extracted {len(consolidated_findings)} total findings")
    
    # Upload to S3
    s3_location = upload_results_to_s3(final_json, bucket_name)
    
    return f"Successfully processed {len(consolidated_findings)} findings and uploaded to {s3_location}"


# ============================================================================
# AGENT SETUP
# ============================================================================

async def main():
    # Get configuration from environment
    folder_path = os.environ.get('SCAN_FOLDER_PATH', '/scan')
    s3_bucket = os.environ.get('S3_BUCKET')
    azure_endpoint = os.environ.get('AZURE_OPENAI_ENDPOINT')
    deployment_name = os.environ.get('AZURE_OPENAI_CHAT_DEPLOYMENT_NAME')
    if not deployment_name:
        deployment_name = os.environ.get('AZURE_OPENAI_DEPLOYMENT')
    
    # Validate required environment variables
    if not azure_endpoint:
        raise ValueError("AZURE_OPENAI_ENDPOINT is required")
    if not deployment_name:
        raise ValueError("Set AZURE_OPENAI_CHAT_DEPLOYMENT_NAME (or legacy AZURE_OPENAI_DEPLOYMENT) to the chat deployment name")
    if not s3_bucket:
        raise ValueError("S3_BUCKET is required")
    
    print("=" * 80)
    print("🤖 INTELLIGENT SECURITY SCANNING AGENT")
    print("=" * 80)
    print(f"Target Folder: {folder_path}")
    print(f"S3 Bucket: {s3_bucket}")
    print(f"Azure OpenAI: {azure_endpoint}")
    print("=" * 80)
    
    # Get Azure credential using API key
    api_key = get_azure_api_key()
    
    # Create agent
    agent = AzureOpenAIChatClient(
        endpoint=azure_endpoint,
        deployment_name=deployment_name,
        api_key=api_key,
    ).create_agent(
        instructions=f"""You are a security scanning orchestrator with MITRE ATT&CK threat intelligence. Follow this EXACT 4-step workflow:

STEP 1: SCAN PHASE
Run these 4 security tools on {folder_path}:
- checkov_result = scan_with_checkov("{folder_path}")
- trivy_result = scan_with_trivy("{folder_path}")
- bandit_result = scan_python_code_with_bandit("{folder_path}")
- semgrep_result = scan_code_with_semgrep("{folder_path}")

Each tool saves findings to a file and returns metadata: {{"tool": "name", "findings_file": "/tmp/...", "finding_count": N}}

STEP 2: AGGREGATE & CONSOLIDATE
Call aggregate_scan_results which will automatically:
1. Load all findings from files
2. Extract fields from EVERY finding using LLM
3. Upload consolidated results to S3
4. Return S3 location

- s3_location = aggregate_scan_results(checkov_result, trivy_result, bandit_result, semgrep_result)

STEP 3: DEDUPLICATE
Remove duplicate findings using semantic embeddings:
- deduplicated_location = deduplicate_findings_from_s3(s3_location)

This will:
- Download findings from S3
- Generate embeddings to find semantically similar findings
- Merge duplicates (e.g., same issue found by Checkov AND Trivy)
- Re-upload deduplicated results to S3

STEP 4: MITRE ATT&CK THREAT INTELLIGENCE (NEW!)
Analyze findings with MITRE ATT&CK framework using multi-agent approach:
- mitre_mapped_location = analyze_findings_with_mitre(deduplicated_location)

This will:
- Download deduplicated findings from S3
- Create one AI agent per finding (concurrent execution with rate limiting)
- Each agent maps the finding to MITRE ATT&CK techniques
- Adjust severity based on MITRE threat context
- Consolidate all MITRE-enriched findings
- Upload final results to S3

STEP 5: REPORT
Report the final S3 locations:
- Original findings: s3_location
- Deduplicated findings: deduplicated_location
- MITRE-mapped findings: mitre_mapped_location

IMPORTANT: 
- Do NOT call consolidate_and_upload_findings directly - it's called internally by aggregate_scan_results.
- ALWAYS run all 4 steps in sequence for complete threat intelligence analysis.""",
        tools=[
            scan_with_checkov,
            scan_with_trivy,
            scan_python_code_with_bandit,
            scan_code_with_semgrep,
            aggregate_scan_results,
            deduplicate_findings_from_s3,
            analyze_findings_with_mitre
        ]
    )
    
    print("\n🔍 Agent analyzing repository...\n")

    try:
        result = await agent.run(
            f"Scan {folder_path} for security issues and upload to S3 bucket {s3_bucket}"
        )
    except ServiceResponseException as exc:
        message = str(exc)
        if "DeploymentNotFound" in message:
            raise RuntimeError(
                "Azure OpenAI returned DeploymentNotFound. Verify that"
                f" '{deployment_name}' exists under your Azure OpenAI resource and that"
                " AZURE_OPENAI_CHAT_DEPLOYMENT_NAME (or AZURE_OPENAI_DEPLOYMENT) is set to the exact deployment name."
            ) from exc
        raise
    
    print("\n" + "=" * 80)
    print("✅ AGENT COMPLETED")
    print("=" * 80)
    print(result.text)
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())
