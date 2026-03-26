from datetime import datetime
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


class AlertEvent(BaseModel):
    alert_id: str
    source: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    attack_type: str
    severity: int
    raw_confidence: float
    details: Dict[str, Any] = Field(default_factory=dict)


class FusedAlert(BaseModel):
    fusion_id: str
    start_time: datetime
    end_time: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str
    sources: List[str]
    attack_types: List[str]
    events_count: int
    aggregated_severity: int
    avg_raw_confidence: float
    member_alert_ids: List[str]

    confidence_score: float = 0.0
    confidence_level: str = "low"


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


class LegacyFusionResponse(BaseModel):
    input_alerts: int
    fused_alerts: int
    results: List[FusedAlert]


class FusionRequest(BaseModel):
    findings: List[Finding]
    ml_events: List[Dict[str, Any]] = []
    dast_results: List[Dict[str, Any]] = []
    asset_context: Dict[str, Any] = Field(default_factory=dict)


class FusionResponse(BaseModel):
    fused_findings: List[Finding]
    incidents: List[Dict[str, Any]]
    total_findings: int
    total_incidents: int