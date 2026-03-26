from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


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
    description: Optional[str] = None
    recommendation: Optional[str] = None

    category: Optional[str] = None
    surface: Optional[str] = None
    cve_id: Optional[str] = None
    package_name: Optional[str] = None
    fix_available: Optional[bool] = False
    confidence: Optional[float] = 0.5
    metadata: Dict[str, Any] = Field(default_factory=dict)

    mitre: Optional[MitreTechnique] = None


class ToolSummary(BaseModel):
    tool: str
    total_findings: int
    status: str
    error: Optional[str] = None


class SeveritySummary(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFO: int = 0
    UNKNOWN: int = 0


class RiskScore(BaseModel):
    score: int
    level: str


class GlobalSummary(BaseModel):
    total_findings: int
    by_tool: List[ToolSummary]
    by_severity: SeveritySummary
    risk: RiskScore


class ScanResponse(BaseModel):
    status: str
    tool: str
    total_findings: int
    findings: List[Finding]


class AllScanResponse(BaseModel):
    status: str
    tool: str
    summary: GlobalSummary
    findings: List[Finding]
    report_path: Optional[str] = None
    enriched_findings_count: int = 0
    incidents_count: int = 0
    incidents: List[Dict[str, Any]] = []
    correlation: Optional[Dict[str, Any]] = None