from typing import Dict, Optional, Any

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CyberSentinel Signature Adapter")

ML_ENGINE_URL = "http://ml-engine:8000/predict"


class SignatureAdapterRequest(BaseModel):
    features: Optional[Dict[str, float]] = None
    metadata: Optional[Dict[str, Any]] = None


def get_sample_features() -> Dict[str, float]:
    return {
        "Protocol": 6,
        "Flow Duration": 1000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 5,
        "Fwd Packets Length Total": 500,
        "Bwd Packets Length Total": 200,
        "Fwd Packet Length Max": 100,
        "Fwd Packet Length Min": 20,
        "Fwd Packet Length Mean": 50,
        "Fwd Packet Length Std": 10,
        "Bwd Packet Length Max": 80,
        "Bwd Packet Length Min": 10,
        "Bwd Packet Length Mean": 40,
        "Bwd Packet Length Std": 8,
        "Flow Bytes/s": 300,
        "Flow Packets/s": 20,
        "Flow IAT Mean": 100,
        "Flow IAT Std": 20,
        "Flow IAT Max": 200,
        "Flow IAT Min": 10,
        "Fwd IAT Total": 500,
        "Fwd IAT Mean": 50,
        "Fwd IAT Std": 10,
        "Fwd IAT Max": 100,
        "Fwd IAT Min": 5,
        "Bwd IAT Total": 300,
        "Bwd IAT Mean": 30,
        "Bwd IAT Std": 6,
        "Bwd IAT Max": 60,
        "Bwd IAT Min": 3,
        "Fwd PSH Flags": 0,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 0,
        "Bwd URG Flags": 0,
        "Fwd Header Length": 200,
        "Bwd Header Length": 100,
        "Fwd Packets/s": 12,
        "Bwd Packets/s": 8,
        "Packet Length Min": 10,
        "Packet Length Max": 100,
        "Packet Length Mean": 45,
        "Packet Length Std": 12,
        "Packet Length Variance": 144,
        "FIN Flag Count": 0,
        "SYN Flag Count": 1,
        "RST Flag Count": 0,
        "PSH Flag Count": 0,
        "ACK Flag Count": 1,
        "URG Flag Count": 0,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        "Down/Up Ratio": 0.5,
        "Avg Packet Size": 48,
        "Avg Fwd Segment Size": 50,
        "Avg Bwd Segment Size": 40,
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": 10,
        "Subflow Fwd Bytes": 500,
        "Subflow Bwd Packets": 5,
        "Subflow Bwd Bytes": 200,
        "Init Fwd Win Bytes": 1024,
        "Init Bwd Win Bytes": 1024,
        "Fwd Act Data Packets": 8,
        "Fwd Seg Size Min": 20,
        "Active Mean": 100,
        "Active Std": 10,
        "Active Max": 120,
        "Active Min": 80,
        "Idle Mean": 50,
        "Idle Std": 5,
        "Idle Max": 60,
        "Idle Min": 40,
    }


@app.get("/")
def root():
    return {"service": "signature-adapter", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy", "ml_engine_url": ML_ENGINE_URL}


@app.post("/forward-to-ml")
def forward_to_ml(request: Optional[SignatureAdapterRequest] = None):
    features = request.features if request and request.features else get_sample_features()
    metadata = request.metadata if request and request.metadata else {}

    payload = {"features": features}

    try:
        response = requests.post(ML_ENGINE_URL, json=payload, timeout=15)
        response.raise_for_status()
        ml_result = response.json()

        return {
            "source": "signature-adapter",
            "forwarded_to": "ml-engine",
            "metadata": metadata,
            "ml_result": ml_result,
            "final_decision": {
                "is_anomaly": ml_result.get("is_anomaly", False),
                "risk_level": ml_result.get("risk_level", "unknown"),
            },
        }

    except requests.RequestException as e:
        raise HTTPException(
            status_code=500,
            detail=f"Erreur appel ml-engine: {str(e)}"
        )