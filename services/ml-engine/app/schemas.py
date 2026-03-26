from typing import Dict, Any, Optional
from pydantic import BaseModel


class FlowFeaturesRequest(BaseModel):
    features: Dict[str, float]


class PredictionResponse(BaseModel):
    model: str
    anomaly_score: float
    threshold: float
    is_anomaly: bool
    risk_level: str
    details: Optional[Dict[str, Any]] = None