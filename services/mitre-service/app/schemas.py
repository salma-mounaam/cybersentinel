from pydantic import BaseModel
from typing import List, Optional


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactics: List[str]
    mitre_url: str
    confidence: float = 0.8
    source: str = "rule_mapping"


class Finding(BaseModel):
    tool: str
    type: str
    severity: str
    title: str
    file: Optional[str] = None
    line: Optional[int] = None
    rule_id: Optional[str] = None


class EnrichedFinding(Finding):
    mitre: Optional[MitreTechnique] = None