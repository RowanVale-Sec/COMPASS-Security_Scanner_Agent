# Threat Modeling Agent Framework
## Architecture Extraction & Threat Scenario Generation

---

## Overview

This document captures the technical design, agent responsibilities, and user stories for a multi-agent system that ingests a codebase and its security scan results, extracts the system architecture and data flows, and generates threat scenarios for security analysis.

The system is built using the **Microsoft Agent SDK** for orchestration, **Claude API** as the LLM reasoning backbone, and a shared **knowledge base** (e.g., MongoDB or Neo4j) for inter-agent state management.

---

## System Architecture

### Design Principles

- **General purpose**: Designed to work across any codebase type—monolith, microservices, polyglot.
- **Language-agnostic**: Initial scope covers common patterns (REST APIs, database queries, message queues, third-party SDKs), with support expandable over time.
- **Agent-native reasoning**: Each agent has a self-questioning loop—not just executing tasks, but validating assumptions and flagging uncertainty.
- **Shared knowledge base**: All agents read from and write to a unified, versioned knowledge base. Each agent's output becomes context for the next.

### High-Level Agent Pipeline

```
[Codebase Files] + [Scan Results JSON]
        │
        ▼
┌──────────────────────────────┐
│  Agent 1: Code Intake &      │
│  Normalization               │
└──────────────┬───────────────┘
               │ Artifact Graph
               ▼
┌──────────────────────────────┐
│  Agent 2: Semantic           │
│  Classification              │
└──────────────┬───────────────┘
               │ Enriched Graph (with roles + confidence)
               ▼
┌──────────────────────────────┐
│  Agent 3: Data Flow          │
│  Tracing                     │
└──────────────┬───────────────┘
               │ Flow Paths + Gap Reports
               ▼
┌──────────────────────────────┐
│  Agent 4: Architecture       │
│  Synthesis                   │
└──────────────┬───────────────┘
               │ Final Architecture Model
               ▼
┌──────────────────────────────┐
│  Threat Modeling Agent       │
│  (Scenario Generation)       │
└──────────────────────────────┘
```

---

## Agent Definitions

### Agent 1 — Code Intake and Normalization

**Purpose**: Parse raw codebase files and deduplicated scan results JSON into a normalized, language-agnostic artifact graph.

**Inputs**:
- Raw codebase files (polyglot)
- Deduplicated scan results in JSON format

**Processing**:
- Detect programming language(s) and invoke appropriate parsing logic
- Extract all code artifacts: functions, classes, API endpoints, database queries, imports, dependencies, external service calls
- Build a directed graph where nodes = code artifacts, edges = relationships (calls, imports, inherits)
- Deduplicate and normalize artifact names and signatures

**Output Schema — Artifact Graph**:
```json
{
  "nodes": [
    {
      "id": "uuid",
      "name": "string",
      "type": "function | class | endpoint | db_query | external_call | import",
      "language": "string",
      "file_location": "string",
      "signature": "string",
      "raw_code_ref": "string"
    }
  ],
  "edges": [
    {
      "from": "node_id",
      "to": "node_id",
      "relationship": "calls | imports | inherits | reads | writes"
    }
  ],
  "parsing_gaps": [
    {
      "file": "string",
      "reason": "string",
      "severity": "warning | error"
    }
  ]
}
```

**Storage**: Persisted to knowledge base as the base artifact graph, versioned.

---

### Agent 2 — Semantic Classification

**Purpose**: Enrich the artifact graph by assigning each node a semantic role, data sensitivity level, and confidence score.

**Inputs**:
- Artifact graph from Agent 1
- Predefined role taxonomy

**Role Taxonomy**:
- `data_source` — originates data (user input, file reads, DB reads)
- `processor` — transforms or computes on data
- `storage` — persists data (DB writes, file writes, cache)
- `api_gateway` — external-facing interface
- `external_service` — outbound call to third-party system
- `utility` — shared helper with no direct data role

**Processing**:
- Classify each node by semantic role using LLM reasoning over code signatures and context
- Infer data sensitivity levels: PII, credentials, financial data, internal metadata, etc.
- Assign confidence score (0.0–1.0) per classification
- Flag uncertain or conflicting classifications for human review

**Output Schema — Enriched Graph**:
Extends artifact graph nodes with:
```json
{
  "role": "data_source | processor | storage | api_gateway | external_service | utility",
  "data_sensitivity": "PII | credentials | financial | internal | none | unknown",
  "confidence_score": 0.85,
  "classification_notes": "string",
  "flagged_for_review": false
}
```

**Storage**: Updates knowledge base nodes with semantic annotations. Prior artifact graph structure preserved.

---

### Agent 3 — Data Flow Tracing

**Purpose**: Starting from identified entry points, trace all data movement paths through the system. Identify trust boundary crossings, transformations, and security mechanisms in place.

**Inputs**:
- Semantically enriched artifact graph from Agent 2
- Identified entry points (derived from `api_gateway` and `data_source` nodes)

**Processing**:
- Walk the graph from each entry point, following data through `calls` and `writes` edges
- Annotate each flow step with: data type, transformation applied, trust boundary status, authentication/authorization mechanisms
- Flag gaps: places where a trace cannot be continued due to missing information, dynamic dispatch, or external black-box calls
- Detect circular dependencies and unusual flow patterns
- Self-validate: ensure all entry points have been traced; re-query if traces appear incomplete

**Output Schema — Flow Paths**:
```json
{
  "flow_paths": [
    {
      "id": "uuid",
      "entry_point": "node_id",
      "path": [
        {
          "node_id": "string",
          "data_type": "string",
          "transformation": "string",
          "trust_boundary_crossed": true,
          "security_mechanism": "OAuth2 | JWT | none | unknown"
        }
      ],
      "exit_point": "node_id",
      "data_sensitivity": "string",
      "confidence_score": 0.78
    }
  ],
  "gap_reports": [
    {
      "node_id": "string",
      "reason": "string",
      "impact": "high | medium | low"
    }
  ],
  "anomalies": [
    {
      "type": "circular_dependency | missing_auth | untraced_sink",
      "nodes_involved": ["node_id"],
      "description": "string"
    }
  ]
}
```

**Storage**: Stored as a separate `flow_paths` collection in knowledge base, referencing artifact graph node IDs.

---

### Agent 4 — Architecture Synthesis

**Purpose**: Consume all prior agent outputs and synthesize a coherent, validated, queryable architecture model ready for threat scenario generation.

**Inputs**:
- Artifact graph (Agent 1)
- Enriched semantic graph (Agent 2)
- Flow paths and gap reports (Agent 3)
- Original scan results JSON

**Processing**:
- Build final architecture model: entities, relationships, trust boundaries, external interfaces, data classifications
- Validate logical coherence: no orphaned nodes, no conflicting trust relationships, no unresolved gaps that affect completeness
- Surface conflicts between agent outputs with explanatory notes
- Produce a queryable structure the threat modeling agent can traverse by attack surface, data type, trust boundary, or vulnerability

**Output Schema — Architecture Model**:
```json
{
  "entities": [
    {
      "id": "uuid",
      "name": "string",
      "role": "string",
      "data_sensitivity": "string",
      "trust_zone": "internal | dmz | external | untrusted"
    }
  ],
  "relationships": [
    {
      "from": "entity_id",
      "to": "entity_id",
      "type": "calls | reads | writes | authenticates",
      "protocol": "string",
      "encrypted": true
    }
  ],
  "trust_boundaries": [
    {
      "id": "uuid",
      "name": "string",
      "entities_inside": ["entity_id"],
      "crossing_flows": ["flow_path_id"]
    }
  ],
  "external_interfaces": [
    {
      "id": "uuid",
      "name": "string",
      "type": "REST | gRPC | message_queue | file | SDK",
      "direction": "inbound | outbound | bidirectional",
      "authentication": "string"
    }
  ],
  "known_vulnerabilities": [
    {
      "scan_ref_id": "string",
      "entity_id": "string",
      "severity": "critical | high | medium | low",
      "description": "string"
    }
  ],
  "conflicts": [
    {
      "agents_involved": ["Agent2", "Agent3"],
      "description": "string",
      "recommendation": "string"
    }
  ]
}
```

**Storage**: Written as the final `architecture_model` document in knowledge base. This is the primary input for the threat modeling agent.

---

## User Stories

### Agent 1 — Code Intake and Normalization

**User Story**:
As a security architect, I want to ingest a codebase and its scan results so that all code artifacts are cataloged in a normalized, language-agnostic format, enabling downstream semantic analysis.

**Acceptance Criteria**:
- [ ] The agent identifies all functions, classes, endpoints, imports, dependencies, and external calls across the codebase
- [ ] The agent handles polyglot codebases by detecting language and applying appropriate parsing logic
- [ ] Output is a deduplicated artifact graph with nodes representing code entities and edges representing relationships
- [ ] Each node includes: name, type, language, file location, and signature
- [ ] Parsing gaps or unhandled file types are explicitly flagged with severity level
- [ ] The artifact graph is persisted to the shared knowledge base in versioned format
- [ ] Agent does not require human prompting to determine what to extract — parsing logic is built into the framework

---

### Agent 2 — Semantic Classification

**User Story**:
As a security architect, I want to understand the semantic role of each code component so that I can trace data flows and identify trust boundaries with confidence.

**Acceptance Criteria**:
- [ ] Every artifact node is assigned a role from the predefined taxonomy: `data_source`, `processor`, `storage`, `api_gateway`, `external_service`, `utility`
- [ ] Each classification includes a confidence score between 0.0 and 1.0
- [ ] Data sensitivity context (PII, credentials, financial, etc.) is inferred where identifiable from code context
- [ ] Uncertain or conflicting classifications are flagged for human review with reasoning notes
- [ ] Output enriches the artifact graph without removing or overwriting prior agent data
- [ ] Agent self-validates: checks that all nodes have been classified before finalizing output

---

### Agent 3 — Data Flow Tracing

**User Story**:
As a security architect, I want to trace how data moves through the system from entry points to storage and external systems so that I can identify all data flows, trust boundary crossings, and implicit security gaps.

**Acceptance Criteria**:
- [ ] Tracing begins from all identified entry points (API gateways, data sources)
- [ ] Each flow path documents: data type, transformations applied, trust boundaries crossed, and security mechanisms in place
- [ ] Gaps in tracing are explicitly reported with the node, reason for failure, and estimated impact level
- [ ] Circular dependencies and anomalous flow patterns (e.g., untraced sinks, missing authentication) are flagged
- [ ] Agent self-validates: confirms all entry points have been traced and re-analyzes if traces appear incomplete
- [ ] Flow paths and gap reports are persisted to the knowledge base referencing artifact graph node IDs

---

### Agent 4 — Architecture Synthesis

**User Story**:
As a security architect, I want a coherent, queryable architecture model so that threat modeling agents can reason about the system's attack surface, data exposure, and exploitable paths.

**Acceptance Criteria**:
- [ ] The final architecture model includes: entities, relationships, trust boundaries, external interfaces, and data classifications
- [ ] Known vulnerabilities from the original scan results are mapped to relevant entities
- [ ] Logical consistency is validated: no orphaned components, no unresolved critical gaps, no conflicting trust zone assignments
- [ ] Conflicts between agent outputs are surfaced with descriptions and recommendations
- [ ] The architecture model is queryable by: attack surface, data sensitivity, trust boundary, vulnerability, or component role
- [ ] The output is in a structured JSON format consumable directly by the threat modeling agent

---

## Technology Stack

| Component | Technology |
|---|---|
| Agent Orchestration | Microsoft Agent SDK |
| LLM Reasoning | Claude API (Anthropic) |
| Inter-Agent Communication | Microsoft Agent SDK messaging layer |
| Knowledge Base | MongoDB or Neo4j (TBD) |
| Input Format | Deduplicated JSON (scan results) + raw codebase files |
| Output Format | Structured JSON (architecture model) |

---

## Open Questions

1. **Feedback loops**: Should later agents be able to trigger re-analysis by earlier agents when they discover gaps or inconsistencies?
2. **Scoping for initial implementation**: Which codebase types and languages should be prioritized for the first release?
3. **Knowledge base selection**: MongoDB (document-oriented) vs Neo4j (native graph) — depends on query patterns needed by the threat modeling agent.
4. **Human review workflow**: How are flagged classifications and tracing gaps surfaced to a human reviewer in the initial phase?
5. **Threat modeling agent design**: Once architecture model is finalized, what framework does the threat modeling agent use to reason over scenarios (STRIDE, MITRE ATLAS, custom taxonomy)?

---

*Document generated from technical design session. Version 1.0 — Draft.*
