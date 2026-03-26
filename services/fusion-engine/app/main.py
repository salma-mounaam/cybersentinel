from typing import List
from fastapi import FastAPI, HTTPException

from app.schemas import AlertEvent, LegacyFusionResponse, FusionRequest, FusionResponse
from app.fusion_service import temporal_fusion, enrich_findings_for_r_score
from app.sample_data import get_sample_alerts
from app.evaluation_data import get_evaluation_alerts
from app.evaluation import build_evaluation_summary
from app.clients import send_to_correlation_engine

app = FastAPI(
    title="CyberSentinel Fusion Engine",
    description="Microservice de fusion temporelle + préparation R-score",
    version="2.0.0"
)


@app.get("/")
def root():
    return {
        "service": "fusion-engine",
        "status": "running",
        "phase": "4.x temporal fusion + 6.x R-score bridge"
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


# ancien moteur IDS
@app.post("/fuse", response_model=LegacyFusionResponse)
def fuse_alerts(alerts: List[AlertEvent]):
    fused = temporal_fusion(alerts)
    return LegacyFusionResponse(
        input_alerts=len(alerts),
        fused_alerts=len(fused),
        results=fused
    )


@app.get("/demo", response_model=LegacyFusionResponse)
def demo_fusion():
    alerts = get_sample_alerts()
    fused = temporal_fusion(alerts)
    return LegacyFusionResponse(
        input_alerts=len(alerts),
        fused_alerts=len(fused),
        results=fused
    )


@app.get("/evaluation/demo")
def evaluation_demo():
    alerts = get_evaluation_alerts()
    return build_evaluation_summary(alerts)


@app.post("/evaluation/run")
def evaluation_run(alerts: List[AlertEvent]):
    return build_evaluation_summary(alerts)


# nouveau bridge vers correlation-engine
@app.post("/fuse/r-score", response_model=FusionResponse)
def fuse_r_score(request: FusionRequest):
    try:
        fused_findings = enrich_findings_for_r_score(
            findings=request.findings,
            ml_events=request.ml_events,
            dast_results=request.dast_results,
            asset_context=request.asset_context,
        )

        correlation_result = send_to_correlation_engine(
            [f.model_dump() for f in fused_findings]
        )

        incidents = correlation_result.get("incidents", [])

        return FusionResponse(
            fused_findings=fused_findings,
            incidents=incidents,
            total_findings=len(fused_findings),
            total_incidents=len(incidents),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))