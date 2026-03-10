"""
Scanner Pipeline - Deduplicator
Downloads findings from S3, uses embeddings to find semantically similar findings,
and validates clusters via AI agents before merging duplicates.
"""

import os
import re
import json
import asyncio
from datetime import datetime
from typing import Annotated
from pydantic import Field

from shared.base_agent import get_azure_api_key, get_azure_endpoint, get_openai_client, get_deployment_name, get_embedding_deployment_name, create_chat_client
from shared.s3_helpers import download_json_from_s3, upload_json_to_s3


async def deduplicate_findings_from_s3(
    s3_location: Annotated[str, Field(description="S3 location (s3://bucket/key) of findings to deduplicate")]
) -> str:
    """
    Download findings from S3, deduplicate using embeddings, and re-upload.

    Pipeline:
    1. Download findings from S3
    2. Generate embeddings for semantic similarity
    3. Cluster similar findings (cosine similarity >= 0.85)
    4. Validate each cluster via AI agent
    5. Upload deduplicated results to S3
    """
    print(f"[Dedup] Downloading findings from {s3_location}")

    try:
        findings_data = download_json_from_s3(s3_location)
    except Exception as e:
        return f"Error downloading from S3: {e}"

    original_findings = findings_data.get('findings', [])
    original_count = len(original_findings)

    print(f"[Dedup] Downloaded {original_count} findings")

    if original_count == 0:
        return f"Error: No findings found in {s3_location}"

    try:
        import numpy as np
        from sklearn.metrics.pairwise import cosine_similarity

        openai_client = get_openai_client()

        print("[Dedup] Generating embeddings for semantic similarity...")

        # Generate embeddings
        embeddings = []
        for idx, finding in enumerate(original_findings):
            text = (
                f"Title: {finding.get('finding_title', '')}\n"
                f"Description: {finding.get('description', '')}\n"
                f"File: {finding.get('file_path', '')}\n"
                f"Resource: {finding.get('resource_name', '')}\n"
                f"Severity: {finding.get('severity', '')}"
            )

            response = openai_client.embeddings.create(
                model=get_embedding_deployment_name(),
                input=text
            )
            embeddings.append(response.data[0].embedding)

            if (idx + 1) % 10 == 0:
                print(f"  Generated {idx + 1}/{original_count} embeddings")

        print(f"[Dedup] Generated {len(embeddings)} embeddings")

        embeddings_array = np.array(embeddings)
        similarity_matrix = cosine_similarity(embeddings_array)

        # Cluster similar findings
        threshold = 0.85
        clusters = []
        processed = set()

        for i in range(len(original_findings)):
            if i in processed:
                continue

            cluster = [original_findings[i]]
            cluster_indices = [i]
            processed.add(i)

            for j in range(i + 1, len(original_findings)):
                if j not in processed and similarity_matrix[i][j] >= threshold:
                    cluster.append(original_findings[j])
                    cluster_indices.append(j)
                    processed.add(j)

            clusters.append((cluster, cluster_indices))

        print(f"[Dedup] Found {len(clusters)} clusters")

        # Validate clusters via AI agents
        from agent_framework.azure import AzureOpenAIChatClient

        chat_client = AzureOpenAIChatClient(
            endpoint=get_azure_endpoint(),
            api_key=get_azure_api_key(),
            model=get_deployment_name()
        )

        unique_findings = []
        duplicates_removed = 0

        for c_index, (cluster, indices) in enumerate(clusters, 1):
            if len(cluster) == 1:
                unique_findings.append(cluster[0])
                continue

            print(f"  [Dedup] Cluster {c_index}: {len(cluster)} similar findings - validating via agent")

            cluster_items_text = []
            for k, f in enumerate(cluster, 1):
                cluster_items_text.append(
                    f"Item {k}: tool={f.get('tool_name', 'unknown')}, "
                    f"title={f.get('finding_title', '')}, "
                    f"file={f.get('file_path', '')}, "
                    f"resource={f.get('resource_name', '')}, "
                    f"recommendation={f.get('recommendation', '')}"
                )

            instructions = (
                f"You are a security engineer assisting with deduplication. "
                f"Below are {len(cluster)} findings clustered by semantic similarity. "
                f"Determine whether these findings represent the SAME implementation "
                f"(same code path, configuration block, or resource instance) such that "
                f"all but one can be safely removed as duplicates.\n\n"
                f"Respond with ONLY valid JSON:\n"
                f'{{"remove_duplicates": true|false, "keep_index": 1, '
                f'"explanation": "short rationale"}}\n\n'
                f"Cluster items:\n" + "\n".join(cluster_items_text)
            )

            try:
                agent = chat_client.create_agent(
                    name=f"DedupValidator_C{c_index}",
                    instructions=instructions,
                    tools=[]
                )
                result = await agent.run(
                    f"Assess cluster {c_index} for implementation-level duplication and return JSON."
                )

                analysis_text = str(result.text) if hasattr(result, 'text') else str(result)

                # Extract JSON decision
                json_match = re.search(r'\{.*?"remove_duplicates".*?\}', analysis_text, re.DOTALL)
                agent_decision = None
                if json_match:
                    try:
                        agent_decision = json.loads(json_match.group(0))
                    except Exception:
                        pass

                if not agent_decision:
                    if '"remove_duplicates":true' in analysis_text.replace(' ', ''):
                        agent_decision = {"remove_duplicates": True, "keep_index": 1, "explanation": "Parsed fallback"}
                    else:
                        agent_decision = {"remove_duplicates": False, "keep_index": 1, "explanation": "Ambiguous response"}

                if agent_decision.get('remove_duplicates'):
                    keep_idx = max(1, int(agent_decision.get('keep_index', 1))) - 1
                    keep_idx = min(keep_idx, len(cluster) - 1)

                    primary = cluster[keep_idx].copy()
                    primary['detected_by_tools'] = list(set(f.get('tool_name', 'unknown') for f in cluster))
                    primary['duplicate_count'] = len(cluster)
                    primary['merged_from_indices'] = indices

                    recommendations = set()
                    for f in cluster:
                        rec = f.get('recommendation', '')
                        if rec and rec != 'N/A':
                            recommendations.add(rec)
                    if recommendations:
                        primary['combined_recommendations'] = list(recommendations)

                    primary['dedup_validation'] = {
                        'validator_explanation': agent_decision.get('explanation', ''),
                        'validator_keep_index': keep_idx + 1
                    }

                    unique_findings.append(primary)
                    duplicates_removed += len(cluster) - 1
                    print(f"    [Dedup] Cluster {c_index} merged (removed {len(cluster) - 1} duplicates)")
                else:
                    for f in cluster:
                        unique_findings.append(f)
                    print(f"    [Dedup] Cluster {c_index} NOT merged: {agent_decision.get('explanation', '')}")

            except Exception as e:
                print(f"    [Dedup] Agent error for cluster {c_index}: {e} - keeping all items")
                unique_findings.extend(cluster)

        print(f"[Dedup] Deduplicated: {original_count} -> {len(unique_findings)} findings")
        if original_count > 0:
            print(f"[Dedup] Removed {duplicates_removed} duplicates ({100 * duplicates_removed / original_count:.1f}% reduction)")

        deduplicated_data = {
            'scan_timestamp': findings_data.get('scan_timestamp'),
            'deduplication_timestamp': datetime.utcnow().isoformat(),
            'original_finding_count': original_count,
            'deduplicated_finding_count': len(unique_findings),
            'duplicates_removed': duplicates_removed,
            'reduction_percentage': round(100 * duplicates_removed / original_count, 1) if original_count > 0 else 0,
            'similarity_threshold': threshold,
            'findings': unique_findings
        }

        s3_location = upload_json_to_s3(deduplicated_data, "scan-results", filename_suffix="-deduplicated")
        print(f"[Dedup] Uploaded deduplicated results to {s3_location}")
        return s3_location

    except Exception as e:
        import traceback
        error_msg = f"Error during deduplication: {e}\n{traceback.format_exc()}"
        print(f"[Dedup] {error_msg}")
        return f"Error: {error_msg}"
