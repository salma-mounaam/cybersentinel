from fastapi import FastAPI, HTTPException
from app.collector import start_sniffing, flow_store
from app.ml_client import send_features_to_ml

app = FastAPI(title="CyberSentinel Flow Collector")


@app.get("/")
def root():
    return {"service": "flow-collector", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/capture")
def capture_traffic(timeout: int = 30):
    try:
        flow_store.clear()
        features = start_sniffing(timeout=timeout)
        return {
            "captured_flows": len(features),
            "features": features
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/capture-and-analyze")
def capture_and_analyze(timeout: int = 30):
    try:
        flow_store.clear()
        features = start_sniffing(timeout=timeout)

        if not features:
            return {
                "captured_flows": 0,
                "features": [],
                "ml_result": None
            }

        ml_result = send_features_to_ml(features)

        return {
            "captured_flows": len(features),
            "features": features,
            "ml_result": ml_result
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))