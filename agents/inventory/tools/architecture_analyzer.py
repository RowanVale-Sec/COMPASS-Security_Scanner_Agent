"""
Inventory Tool - AI-Powered Architecture Analyzer
Reads source code, Dockerfiles, K8s manifests, Terraform files to discover
application architecture using LLM analysis.
"""

import os
import json
from typing import Annotated
from pydantic import Field


async def analyze_architecture(
    folder_path: Annotated[str, Field(description="Path to the codebase to analyze architecture")]
) -> str:
    """
    AI-powered architecture discovery from source code and configuration files.

    Reads Dockerfiles, docker-compose.yml, Kubernetes manifests, Terraform files,
    application source code, and configuration files to identify:
    - Components (services, databases, caches, queues, gateways)
    - Communication patterns (REST, gRPC, messaging)
    - Deployment topology
    - Technology stack
    - Port configurations

    Returns: JSON string with architecture model.
    """
    print(f"[Architecture] Analyzing architecture of {folder_path}")

    # Collect relevant files for analysis
    file_contents = _collect_architecture_files(folder_path)

    if not file_contents:
        print("[Architecture] No architecture-relevant files found")
        return json.dumps({
            "type": "unknown",
            "components": [],
            "communication_patterns": [],
            "note": "No architecture files found for analysis"
        })

    # Build analysis context
    context = "Architecture-relevant files found:\n\n"
    for filepath, content in file_contents.items():
        context += f"--- {filepath} ---\n{content[:3000]}\n\n"

    from shared.llm_provider import get_provider
    provider = get_provider()

    prompt = f"""Analyze the following codebase files and extract the application architecture.

{context}

Identify and return JSON with:
1. "type": Architecture type ("microservices", "monolithic", "serverless", "hybrid")
2. "components": Array of components, each with:
   - "name": Component/service name
   - "type": "service" | "database" | "cache" | "queue" | "gateway" | "storage" | "external_api"
   - "technology": Framework/technology (e.g., "Flask", "PostgreSQL", "Redis")
   - "ports": Array of port numbers
   - "dependencies": Array of other component names this depends on
   - "exposure": "internet-facing" | "internal"
   - "description": Brief description of what this component does
3. "communication_patterns": Array of patterns (e.g., "REST", "gRPC", "TCP", "AMQP")
4. "deployment": Object with:
   - "containerized": boolean
   - "orchestration": "kubernetes" | "docker-compose" | "ecs" | "none"
   - "cloud_provider": "aws" | "azure" | "gcp" | "none"
5. "technology_stack": Object with:
   - "languages": Array of programming languages
   - "frameworks": Array of frameworks
   - "databases": Array of databases
   - "infrastructure": Array of IaC tools

Return ONLY valid JSON."""

    try:
        architecture = await provider.structured_output(
            schema={"type": "object"},
            prompt=prompt,
            system="You are a software architect analyzing codebases to extract architecture models. Return only valid JSON.",
            temperature=0.2,
            max_tokens=4096,
        )
        components_count = len(architecture.get('components', []))
        print(f"[Architecture] Discovered {components_count} components, type: {architecture.get('type', 'unknown')}")

        return json.dumps(architecture, indent=2)

    except Exception as e:
        print(f"[Architecture] Analysis failed: {e}")
        return json.dumps({
            "type": "unknown",
            "components": [],
            "communication_patterns": [],
            "error": str(e)
        })


def _collect_architecture_files(folder_path: str) -> dict:
    """Collect architecture-relevant files from the codebase."""
    relevant_patterns = {
        'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
        'requirements.txt', 'package.json', 'go.mod', 'pom.xml', 'build.gradle',
        '.env', '.env.example',
    }
    relevant_extensions = {
        '.tf', '.yaml', '.yml', '.toml', '.cfg', '.ini', '.conf'
    }
    # Also grab main source files to understand the application
    source_extensions = {'.py', '.js', '.ts', '.java', '.go'}

    file_contents = {}
    max_files = 30  # Limit to avoid overwhelming the LLM

    for root, dirs, files in os.walk(folder_path):
        # Skip hidden dirs and common non-relevant dirs
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in {
            'node_modules', '__pycache__', '.git', 'venv', '.venv', 'vendor'
        }]

        for filename in files:
            if len(file_contents) >= max_files:
                break

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, folder_path)

            should_include = (
                filename in relevant_patterns or
                os.path.splitext(filename)[1] in relevant_extensions or
                (os.path.splitext(filename)[1] in source_extensions and
                 'test' not in rel_path.lower())
            )

            if should_include:
                try:
                    with open(filepath, 'r', errors='ignore') as f:
                        content = f.read(5000)  # Read first 5KB
                    file_contents[rel_path] = content
                except Exception:
                    pass

    print(f"[Architecture] Collected {len(file_contents)} files for analysis")
    return file_contents
