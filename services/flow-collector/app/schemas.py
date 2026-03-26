from pydantic import BaseModel
from typing import Optional


class FlowFeature(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packet_count: int
    byte_count: int
    duration: float
    avg_packet_size: float


class MLResponse(BaseModel):
    anomaly_score: float
    is_anomaly: bool
    model: Optional[str] = None