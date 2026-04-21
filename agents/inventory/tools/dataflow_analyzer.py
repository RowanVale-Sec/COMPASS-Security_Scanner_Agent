"""
Inventory Tool - AI-Powered Data Flow Analyzer
Generates data flow diagrams (DFD) from architecture model and source code,
identifying trust boundaries, data flows, and entry points.
"""

import os
import json
from typing import Annotated
from pydantic import Field


async def analyze_data_flows(
    folder_path: Annotated[str, Field(description="Path to the codebase")],
    architecture_json: Annotated[str, Field(description="JSON string of architecture model from analyze_architecture")]
) -> str:
    """
    AI-powered Data Flow Diagram generation.

    Takes the architecture model and source code to identify:
    - Trust boundaries (network, process, machine boundaries)
    - Data flows between components with classification (PII, credentials, etc.)
    - Entry/exit points (APIs, UIs, file I/O)
    - Data stores and their sensitivity levels

    Returns: JSON string with DFD model.
    """
    print(f"[DataFlow] Analyzing data flows for {folder_path}")

    try:
        architecture = json.loads(architecture_json)
    except json.JSONDecodeError:
        architecture = {}

    # Read key source files that handle data (routes, models, config)
    data_files = _collect_data_handling_files(folder_path)

    context = f"Architecture Model:\n{json.dumps(architecture, indent=2)}\n\n"
    context += "Data-handling source files:\n\n"
    for filepath, content in data_files.items():
        context += f"--- {filepath} ---\n{content[:2000]}\n\n"

    from shared.llm_provider import get_provider
    provider = get_provider()

    prompt = f"""Analyze the architecture and source code to generate a Data Flow Diagram (DFD).

{context}

Generate a comprehensive DFD as JSON with:

1. "trust_boundaries": Array of boundaries, each with:
   - "name": Boundary name (e.g., "Internet Boundary", "Database Tier")
   - "type": "network" | "process" | "machine"
   - "components_inside": Array of component names inside this boundary
   - "components_outside": Array of component names outside this boundary
   - "security_controls": What security exists at this boundary

2. "flows": Array of data flows, each with:
   - "source": Source component name
   - "destination": Destination component name
   - "data_classification": "PII" | "credentials" | "financial" | "health" | "public" | "internal"
   - "data_description": What data flows (e.g., "user login credentials", "order details")
   - "protocol": Communication protocol (e.g., "HTTPS", "TCP/5432", "AMQP")
   - "encrypted": boolean - whether data is encrypted in transit
   - "authentication": Authentication method used for this flow

3. "entry_points": Array of external entry points, each with:
   - "component": Component name
   - "type": "HTTP API" | "WebSocket" | "CLI" | "message_queue" | "file_upload" | "database_port"
   - "authentication": Authentication mechanism (e.g., "JWT", "API Key", "None")
   - "exposure": "public" | "internal" | "vpn_only"
   - "data_accepted": What data types this endpoint accepts

4. "data_stores": Array of data stores, each with:
   - "name": Store name
   - "type": "relational_db" | "nosql_db" | "cache" | "file_system" | "object_storage" | "message_queue"
   - "technology": Specific technology (e.g., "PostgreSQL", "Redis", "S3")
   - "data_sensitivity": "critical" | "sensitive" | "internal" | "public"
   - "encryption_at_rest": boolean
   - "data_types_stored": Array of data types stored

Return ONLY valid JSON."""

    try:
        dfd = await provider.structured_output(
            schema={"type": "object"},
            prompt=prompt,
            system="You are a security architect creating Data Flow Diagrams for threat modeling. Return only valid JSON.",
            temperature=0.2,
            max_tokens=4096,
        )

        flows_count = len(dfd.get('flows', []))
        boundaries_count = len(dfd.get('trust_boundaries', []))
        entry_count = len(dfd.get('entry_points', []))
        print(f"[DataFlow] DFD complete: {flows_count} flows, {boundaries_count} boundaries, {entry_count} entry points")

        return json.dumps(dfd, indent=2)

    except Exception as e:
        print(f"[DataFlow] Analysis failed: {e}")
        return json.dumps({
            "trust_boundaries": [],
            "flows": [],
            "entry_points": [],
            "data_stores": [],
            "error": str(e)
        })


def _collect_data_handling_files(folder_path: str) -> dict:
    """Collect files that handle data: routes, models, database configs."""
    data_keywords = {
        'route', 'api', 'view', 'controller', 'model', 'schema',
        'database', 'db', 'auth', 'login', 'user', 'config',
        'handler', 'middleware', 'service'
    }
    source_extensions = {'.py', '.js', '.ts', '.java', '.go', '.rb'}

    file_contents = {}
    max_files = 20

    for root, dirs, files in os.walk(folder_path):
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {
            'node_modules', '__pycache__', '.git', 'venv', '.venv', 'vendor'
        }]

        for filename in files:
            if len(file_contents) >= max_files:
                break

            ext = os.path.splitext(filename)[1]
            name_lower = filename.lower()

            if ext in source_extensions and any(kw in name_lower for kw in data_keywords):
                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, folder_path)
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        file_contents[rel_path] = f.read(4000)
                except Exception:
                    pass

    print(f"[DataFlow] Collected {len(file_contents)} data-handling files")
    return file_contents
