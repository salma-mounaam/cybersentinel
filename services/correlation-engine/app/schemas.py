from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactics: List[str] = []
    mitre_url: Optional[str] = None
    confidence: float = 0.0
    source: Optional[str] = None


class Finding(BaseModel):
    tool: str
    type: str
    severity: str
    title: str

    file: Optional[str] = None
    line: Optional[int] = None
    rule_id: Optional[str] = None

    category: Optional[str] = None
    surface: Optional[str] = None
    description: Optional[str] = None

    cve_id: Optional[str] = None
    package_name: Optional[str] = None
    fix_available: Optional[bool] = False

    confidence: Optional[float] = 0.5
    metadata: Dict[str, Any] = Field(default_factory=dict)

    mitre: Optional[MitreTechnique] = None

    anomaly_score: Optional[float] = None
    exploit_confirmed: Optional[bool] = False
    exploit_score: Optional[float] = None
    asset_criticality: Optional[float] = None


class RScoreBreakdown(BaseModel):
    anomaly_score: float
    vulnerability_score: float
    exploitability_score: float
    criticality_score: float
    weights: Dict[str, float]
    final_score: int
    final_level: str


class ScoredFinding(BaseModel):
    finding: Finding
    r_score: int
    risk_level: str
    score_breakdown: Dict[str, int]
    r_score_breakdown: Optional[RScoreBreakdown] = None


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: str
    r_score: int
    risk_level: str
    status: str = "open"

    category: str
    summary: str

    sources: List[str]
    affected_files: List[str]
    evidence_count: int
    evidence: List[str]

    mitre: List[MitreTechnique]
    recommendations: List[str]

    grouped_by: Dict[str, Any] = Field(default_factory=dict)
    r_score_breakdown: Optional[RScoreBreakdown] = None


class CorrelationRequest(BaseModel):
    findings: List[Finding]


class CorrelationResponse(BaseModel):
    total_findings: int
    scored_findings: List[ScoredFinding]
    incidents: List[Incident]