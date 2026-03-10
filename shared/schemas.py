"""
COMPASS Data Contracts - Pydantic models defining inter-agent data schemas.
These schemas define what each agent produces and consumes.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime


# ============================================================================
# Common Models
# ============================================================================

class MitreAnalysis(BaseModel):
    technique_id: str = "UNMAPPED"
    technique_name: str = "Unable to map"
    tactic: str = "Unknown"
    adjusted_severity: str = "UNKNOWN"
    confidence: str = "LOW"
    rationale: str = ""


class DedupMetadata(BaseModel):
    detected_by_tools: List[str] = Field(default_factory=list)
    duplicate_count: int = 1


# ============================================================================
# Scanner Agent Output
# ============================================================================

class ScanFinding(BaseModel):
    finding_id: str = ""
    tool_name: str = ""
    scan_type: str = ""  # IaC, SAST, SCA, Container, Secrets
    file_path: str = ""
    finding_title: str = ""
    description: str = ""
    severity: str = "INFO"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    recommendation: str = ""
    resource_type: str = ""
    resource_name: str = ""
    mitre_analysis: Optional[MitreAnalysis] = None
    dedup_metadata: Optional[DedupMetadata] = None


class PipelineStats(BaseModel):
    aggregation: Dict[str, Any] = Field(default_factory=dict)
    deduplication: Dict[str, Any] = Field(default_factory=dict)
    mitre_mapping: Dict[str, Any] = Field(default_factory=dict)


class ScannerOutput(BaseModel):
    compass_version: str = "2.0"
    agent: str = "security_scanner"
    scan_timestamp: str = ""
    scan_folder: str = ""
    pipeline: PipelineStats = Field(default_factory=PipelineStats)
    findings: List[ScanFinding] = Field(default_factory=list)


# ============================================================================
# Inventory Agent Output
# ============================================================================

class SBOMPackage(BaseModel):
    name: str = ""
    version: str = ""
    purl: str = ""  # Package URL (e.g., pkg:pypi/flask@2.0.1)
    cpe: str = ""   # CPE identifier
    license: str = ""
    supplier: str = ""
    known_vulnerabilities: List[str] = Field(default_factory=list)
    risk_level: str = "NONE"  # HIGH, MEDIUM, LOW, NONE


class SBOMData(BaseModel):
    format: str = "spdx-json"
    total_packages: int = 0
    packages: List[SBOMPackage] = Field(default_factory=list)


class ArchitectureComponent(BaseModel):
    name: str = ""
    type: str = ""  # service, database, cache, queue, gateway
    technology: str = ""
    ports: List[int] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    exposure: str = "internal"  # internet-facing, internal


class Architecture(BaseModel):
    type: str = ""  # microservices, monolithic, serverless
    components: List[ArchitectureComponent] = Field(default_factory=list)
    communication_patterns: List[str] = Field(default_factory=list)


class TrustBoundary(BaseModel):
    name: str = ""
    type: str = ""  # network, process, machine
    components_inside: List[str] = Field(default_factory=list)
    components_outside: List[str] = Field(default_factory=list)


class DataFlow(BaseModel):
    source: str = ""
    destination: str = ""
    data_classification: str = ""  # PII, credentials, financial, public
    protocol: str = ""
    encrypted: bool = False


class EntryPoint(BaseModel):
    component: str = ""
    type: str = ""  # HTTP API, WebSocket, CLI, message queue
    authentication: str = ""
    exposure: str = "internal"  # public, internal


class DataFlowDiagram(BaseModel):
    trust_boundaries: List[TrustBoundary] = Field(default_factory=list)
    flows: List[DataFlow] = Field(default_factory=list)
    entry_points: List[EntryPoint] = Field(default_factory=list)


class AssetInventory(BaseModel):
    total_assets: int = 0
    by_category: Dict[str, int] = Field(default_factory=dict)
    assets: List[Dict[str, Any]] = Field(default_factory=list)


class InventoryOutput(BaseModel):
    compass_version: str = "2.0"
    agent: str = "inventory"
    timestamp: str = ""
    scan_folder: str = ""
    sbom: SBOMData = Field(default_factory=SBOMData)
    architecture: Architecture = Field(default_factory=Architecture)
    data_flow: DataFlowDiagram = Field(default_factory=DataFlowDiagram)
    asset_inventory: AssetInventory = Field(default_factory=AssetInventory)


# ============================================================================
# Threat Model Agent Output
# ============================================================================

class VulnerabilityCorrelation(BaseModel):
    finding_id: str = ""
    affected_component: str = ""
    exposure: str = ""
    data_at_risk: List[str] = Field(default_factory=list)
    mitre_tactic: str = ""


class AttackScenario(BaseModel):
    name: str = ""
    entry_point: str = ""
    target_asset: str = ""
    attack_steps: List[str] = Field(default_factory=list)
    grounded_in: List[str] = Field(default_factory=list)  # Finding IDs
    likelihood: str = "MEDIUM"
    severity: str = "MEDIUM"
    impact: str = ""


class StrideThreat(BaseModel):
    threat_id: str = ""
    category: str = ""  # Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege
    description: str = ""
    affected_component: str = ""
    severity: str = "MEDIUM"
    mitigation: str = ""
    related_findings: List[str] = Field(default_factory=list)


class StrideAnalysis(BaseModel):
    threats: List[StrideThreat] = Field(default_factory=list)
    by_category: Dict[str, int] = Field(default_factory=dict)


class RiskAnalysis(BaseModel):
    overall_risk_score: float = 0.0
    critical_priorities: List[Dict[str, Any]] = Field(default_factory=list)
    quick_wins: List[Dict[str, Any]] = Field(default_factory=list)
    strategic_improvements: List[Dict[str, Any]] = Field(default_factory=list)
    compliance_gaps: List[Dict[str, Any]] = Field(default_factory=list)


class ThreatModelOutput(BaseModel):
    compass_version: str = "2.0"
    agent: str = "threat_model"
    timestamp: str = ""
    inputs: Dict[str, str] = Field(default_factory=dict)
    vulnerability_correlation: List[VulnerabilityCorrelation] = Field(default_factory=list)
    attack_scenarios: List[AttackScenario] = Field(default_factory=list)
    stride_analysis: StrideAnalysis = Field(default_factory=StrideAnalysis)
    risk_analysis: RiskAnalysis = Field(default_factory=RiskAnalysis)
