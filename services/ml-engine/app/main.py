from fastapi import FastAPI, HTTPException

from app.schemas import FlowFeaturesRequest, PredictionResponse
from app.inference.predictor import AutoencoderPredictor

app = FastAPI(title="CyberSentinel ML Engine")

predictor = None


@app.on_event("startup")
def startup_event():
    global predictor
    predictor = AutoencoderPredictor()


@app.get("/")
def root():
    return {"service": "ml-engine", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/predict", response_model=PredictionResponse)
def predict(request: FlowFeaturesRequest):
    try:
        result = predictor.predict(request.features)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))