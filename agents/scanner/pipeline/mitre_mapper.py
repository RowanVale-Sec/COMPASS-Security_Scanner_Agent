"""
Scanner Pipeline - MITRE ATT&CK Mapper

Maps deduplicated security findings to MITRE ATT&CK techniques using a
provider-agnostic design:

  1. One MCP call at start to cache every Enterprise technique in memory.
  2. Per finding: Python shortlists the top-k candidates by token overlap.
  3. One `provider.structured_output(...)` call asks the LLM to pick the best
     match and adjust severity. No tool-use loop, no per-provider branches.

This module no longer depends on `agent_framework`; it uses the public `mcp`
SDK for MCP I/O (via `shared.mcp_utils`) and the `LLMProvider` abstraction for
reasoning, so it works identically under `LLM_PROVIDER=azure` and
`LLM_PROVIDER=claude`.
"""

import os
import re
import json
import asyncio
from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

from pydantic import Field

from shared.cloud_auth import auth_headers
from shared.llm_provider import get_provider
from shared.mcp_utils import mcp_session, call_tool_json
from shared.local_store import load_json, save_json


MITRE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "technique_id":      {"type": "string"},
        "technique_name":    {"type": "string"},
        "tactic":            {"type": "string"},
        "adjusted_severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"]},
        "confidence":        {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "rationale":         {"type": "string"},
    },
    "required": [
        "technique_id",
        "technique_name",
        "tactic",
        "adjusted_severity",
        "confidence",
        "rationale",
    ],
    "additionalProperties": False,
}


SYSTEM_PROMPT = """You are an expert security analyst specializing in the MITRE ATT&CK framework.
For each finding, pick the single best-matching ATT&CK technique from the candidate list
provided in the user message and adjust severity based on the tactic it belongs to.

You MUST return a single JSON object with EXACTLY these six keys, ALL required:
  - technique_id      (string, MITRE T#### or T####.### from the candidate list)
  - technique_name    (string, the `name` field of the candidate you picked)
  - tactic            (string, e.g. "Credential Access", "Initial Access")
  - adjusted_severity (one of: "CRITICAL", "HIGH", "MEDIUM", "LOW")
  - confidence        (one of: "HIGH", "MEDIUM", "LOW")
  - rationale         (string, one or two sentences explaining the match)

Never omit a key. Never wrap the JSON in prose or code fences.

Severity mapping by tactic:
  CRITICAL: Privilege Escalation, Credential Access, Initial Access, Execution
  HIGH:     Lateral Movement, Persistence, Impact, Defense Evasion
  MEDIUM:   Discovery, Collection, Command and Control
  LOW:      Informational findings only

If no candidate fits, return the single closest match and set `confidence` to LOW with a
rationale explaining why."""


_TOKEN_RE = re.compile(r"[A-Za-z0-9]+")
_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "of", "in", "on", "to", "for",
    "with", "is", "are", "was", "were", "be", "been", "by", "at", "from",
    "this", "that", "these", "those", "it", "its", "as", "if", "not",
}


def _tokenize(text: str) -> List[str]:
    return [t for t in (m.group(0).lower() for m in _TOKEN_RE.finditer(text or ""))
            if t not in _STOPWORDS and len(t) > 2]


def shortlist_techniques(
    finding: Dict[str, Any],
    techniques: List[Dict[str, Any]],
    k: int = 40,
) -> List[Dict[str, Any]]:
    """Rank `techniques` by token-overlap against the finding's text fields and
    return the top `k`. Deterministic and dependency-free so tests don't need
    a real LLM or MCP server.

    Each returned technique is the original dict filtered to the fields the
    prompt needs: `mitre_id`, `name`, `description` (truncated).
    """
    if not techniques:
        return []

    finding_text = " ".join([
        str(finding.get("finding_title", "")),
        str(finding.get("description", "")),
        str(finding.get("scan_type", "")),
        str(finding.get("resource_type", "")),
        str(finding.get("file_path", "")),
    ])
    finding_tokens = set(_tokenize(finding_text))
    if not finding_tokens:
        return [_compact(t) for t in techniques[:k]]

    scored: List[tuple] = []
    for tech in techniques:
        if not tech.get("mitre_id"):
            continue
        tech_text = f"{tech.get('name', '')} {tech.get('description', '')}"
        tech_tokens = set(_tokenize(tech_text))
        if not tech_tokens:
            continue
        score = len(finding_tokens & tech_tokens)
        if score > 0:
            scored.append((score, tech))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [_compact(t) for _, t in scored[:k]]


def _compact(tech: Dict[str, Any]) -> Dict[str, Any]:
    """Strip a technique dict down to what the LLM prompt needs."""
    desc = tech.get("description") or ""
    if len(desc) > 300:
        desc = desc[:297] + "..."
    return {
        "technique_id": tech.get("mitre_id", ""),
        "name": tech.get("name", ""),
        "description": desc,
    }


async def _load_technique_cache(session) -> List[Dict[str, Any]]:
    """Fetch all Enterprise techniques once, with descriptions, from the MCP
    server. Paginates until `has_more` is false so we don't silently truncate
    at the server's default page size (Montimage mitre-mcp caps at 20).
    Returns an empty list on failure so the pipeline degrades gracefully
    (the LLM can still attempt a mapping from training data)."""
    all_techniques: List[Dict[str, Any]] = []
    offset = 0
    page_size = 500

    try:
        while True:
            payload = await call_tool_json(
                session,
                "get_techniques",
                {
                    "domain": "enterprise-attack",
                    "include_descriptions": True,
                    "limit": page_size,
                    "offset": offset,
                },
            )
            if isinstance(payload, list):
                all_techniques.extend(payload)
                break
            if not isinstance(payload, dict):
                print(f"[MITRE] Unexpected get_techniques payload shape: {type(payload).__name__}")
                break
            page = payload.get("techniques") or []
            all_techniques.extend(page)
            pagination = payload.get("pagination") or {}
            if not pagination.get("has_more") or not page:
                break
            offset += len(page)
            if offset > 10000:  # runaway safeguard
                print(f"[MITRE] Pagination guard tripped at offset={offset}; stopping.")
                break
    except Exception as e:
        print(f"[MITRE] Failed to load technique cache at offset={offset}: {e}. Returning {len(all_techniques)} techniques loaded so far.")

    return all_techniques


def _build_prompt(finding_id: str, finding: Dict[str, Any], candidates: List[Dict[str, Any]]) -> str:
    fields = {
        "finding_id":    finding_id,
        "tool":          finding.get("tool_name", finding.get("tool", "unknown")),
        "scan_type":     finding.get("scan_type", "N/A"),
        "file_path":     finding.get("file_path", "N/A"),
        "resource_type": finding.get("resource_type", "N/A"),
        "title":         finding.get("finding_title", finding.get("title", "N/A")),
        "description":   finding.get("description", "N/A"),
        "severity":      finding.get("severity", "UNKNOWN"),
    }
    return (
        "Finding:\n"
        + json.dumps(fields, indent=2)
        + "\n\nCandidate MITRE ATT&CK techniques (pick exactly one `technique_id` from this list):\n"
        + json.dumps(candidates, indent=2)
        + "\n\nReturn a single JSON object with exactly these keys: "
          "technique_id, technique_name, tactic, adjusted_severity, confidence, rationale. "
          "All six are required."
    )


async def analyze_findings_with_mitre(
    findings_path: Annotated[str, Field(description="Local file path of deduplicated findings")],
) -> str:
    """
    Analyze security findings by mapping each to a MITRE ATT&CK technique.

    Runs concurrently (15 parallel workers) but issues exactly one LLM call per
    finding, grounded in a technique list fetched once from the MITRE MCP
    server at `MITRE_MCP_URL` (default `http://mitre-mcp:8000/mcp`).

    The URL is read from an env var rather than a tool parameter because LLMs
    tend to hallucinate plausible-looking URLs when they see an optional arg.
    """
    mitre_mcp_url = os.environ.get("MITRE_MCP_URL", "http://mitre-mcp:8000/mcp")
    print(f"[MITRE] Starting analysis for findings from {findings_path}")

    try:
        findings_data = load_json(findings_path)
    except Exception as e:
        return f"Error loading findings: {e}"

    findings: List[Dict[str, Any]] = findings_data.get("findings", [])
    total_findings = len(findings)
    print(f"[MITRE] Downloaded {total_findings} findings")
    if total_findings == 0:
        return "No findings to analyze"

    provider = get_provider()

    print(f"[MITRE] Connecting to MCP server at {mitre_mcp_url}")
    async with mcp_session(mitre_mcp_url, headers=auth_headers(mitre_mcp_url)) as session:
        print("[MITRE] MCP connected. Loading technique cache...")
        technique_cache = await _load_technique_cache(session)
        print(f"[MITRE] Cached {len(technique_cache)} techniques. Starting {total_findings} concurrent analyses...")

        semaphore = asyncio.Semaphore(15)
        tool_prefixes = {
            "trivy-iac": "TI", "trivy-sca": "TS", "trivy-secret": "TX",
            "trivy-image": "TG", "checkov": "C", "bandit": "B",
            "semgrep": "S", "unknown": "U",
        }
        tool_counts: Dict[str, int] = {}
        id_lock = asyncio.Lock()

        async def analyze_one(finding: Dict[str, Any], index: int) -> Dict[str, Any]:
            async with semaphore:
                tool_name = str(finding.get("tool_name", finding.get("tool", "unknown"))).lower()
                prefix = tool_prefixes.get(tool_name, "U")
                async with id_lock:
                    tool_counts[prefix] = tool_counts.get(prefix, 0) + 1
                    finding_id = f"FND-{prefix}-{tool_counts[prefix]}"

                try:
                    candidates = shortlist_techniques(finding, technique_cache, k=40)
                    prompt = _build_prompt(finding_id, finding, candidates)

                    mitre_data = await provider.structured_output(
                        schema=MITRE_SCHEMA,
                        prompt=prompt,
                        system=SYSTEM_PROMPT,
                        temperature=0.0,
                        max_tokens=800,
                    )

                    print(f"[MITRE] {index + 1}/{total_findings}: {finding_id} -> {mitre_data.get('technique_id', 'UNMAPPED')}")
                    return {finding_id: {"finding": finding, "mitre_analysis": mitre_data}}

                except Exception as e:
                    print(f"[MITRE] {index + 1}/{total_findings}: error for {finding_id}: {e}")
                    return {
                        f"FND-ERR-{index}": {
                            "finding": finding,
                            "mitre_analysis": {
                                "technique_id": "ERROR",
                                "technique_name": "Analysis Failed",
                                "tactic": "N/A",
                                "adjusted_severity": "UNKNOWN",
                                "confidence": "NONE",
                                "rationale": f"Error: {e}",
                            },
                        }
                    }

        results = await asyncio.gather(*(analyze_one(f, i) for i, f in enumerate(findings)))

    mitre_mapped: Dict[str, Any] = {
        "metadata": {
            "analysis_date": datetime.utcnow().isoformat(),
            "total_findings": total_findings,
            "mitre_mcp_url": mitre_mcp_url,
            "source_file": findings_path,
            "tool_distribution": dict(tool_counts),
            "technique_cache_size": len(technique_cache),
        }
    }
    for r in results:
        mitre_mapped.update(r)

    out_path = save_json(mitre_mapped, "mitre-mapped-findings")
    mapped = sum(1 for r in results if not any("ERR" in k for k in r.keys()))
    errors = total_findings - mapped
    print(f"[MITRE] Complete: {mapped} mapped, {errors} errors. Wrote {out_path}")
    return out_path
