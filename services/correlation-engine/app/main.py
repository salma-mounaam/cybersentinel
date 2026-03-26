from pydantic import BaseModel
from typing import List,Optional

from fastapi import FastAPI
from app.schemas import (
    Finding,
    ScoredFinding,
    CorrelationRequest,
    CorrelationResponse,
)
from app.scoring import compute_finding_score, compute_group_context
from app.r_engine import compute_r_score_for_finding
from app.correlator import correlate_findings
from app.incident_generator import generate_incident

app = FastAPI(title="CyberSentinel Correlation Engine")

class DastFinding(BaseModel):
    type: Optional[str] = None
    name: Optional[str] = None
    url: Optional[str] = None
    method: Optional[str] = None
    risk: Optional[str] = None
    risk_score: float = 0.0
    description: Optional[str] = None
    solution: Optional[str] = None
    cwe: Optional[str] = None
    wasc: Optional[str] = None
    plugin_id: Optional[str] = None


class DastPayload(BaseModel):
    scan_id: str
    source: str
    target_url: str
    exploit_confirmed: bool
    exploit_score: float
    findings_count: int
    findings: List[DastFinding]
class FinalCorrelationPayload(BaseModel):
    scan_id: str
    anomaly_score: float = 0.0
    vuln_score: float = 0.0
    exploit_confirmed: bool = False
    asset_criticality: float = 0.5


def clamp(value: float) -> float:
    return max(0.0, min(1.0, value))

@app.get("/")
def root():
    return {"service": "correlation-engine", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.post("/score/finding")
def score_single_finding(finding: Finding):
    heuristic_score, breakdown = compute_finding_score(finding)
    r_breakdown = compute_r_score_for_finding(finding)

    return {
        "finding": finding,
        "heuristic_score": heuristic_score,
        "score_breakdown": breakdown,
        "r_score": r_breakdown.final_score,
        "risk_level": r_breakdown.final_level,
        "r_score_breakdown": r_breakdown,
    }


@app.post("/score/findings", response_model=List[ScoredFinding])
def score_findings(findings: List[Finding]):
    scored_findings = []

    for finding in findings:
        heuristic_score, breakdown = compute_finding_score(finding)
        r_breakdown = compute_r_score_for_finding(finding)

        scored_findings.append(
            ScoredFinding(
                finding=finding,
                r_score=r_breakdown.final_score,
                risk_level=r_breakdown.final_level,
                score_breakdown=breakdown,
                r_score_breakdown=r_breakdown,
            )
        )

    return scored_findings


@app.post("/correlate")
def correlate_only(request: CorrelationRequest):
    groups = correlate_findings(request.findings)

    return {
        "total_findings": len(request.findings),
        "total_groups": len(groups),
        "groups": {
            group_id: [f.model_dump() for f in findings]
            for group_id, findings in groups.items()
        }
    }


@app.post("/incidents", response_model=CorrelationResponse)
def generate_incidents(request: CorrelationRequest):
    groups = correlate_findings(request.findings)

    scored_findings = []
    incidents = []

    for group_id, findings in groups.items():
        ctx = compute_group_context(findings)

        for finding in findings:
            heuristic_score, breakdown = compute_finding_score(
                finding=finding,
                same_group_count=ctx["same_group_count"],
                correlated_tools_count=ctx["correlated_tools_count"],
            )
            r_breakdown = compute_r_score_for_finding(finding)

            scored_findings.append(
                ScoredFinding(
                    finding=finding,
                    r_score=r_breakdown.final_score,
                    risk_level=r_breakdown.final_level,
                    score_breakdown=breakdown,
                    r_score_breakdown=r_breakdown,
                )
            )

        incidents.append(generate_incident(group_id, findings))

    incidents.sort(key=lambda x: x.r_score, reverse=True)
    scored_findings.sort(key=lambda x: x.r_score, reverse=True)

    return CorrelationResponse(
        total_findings=len(request.findings),
        scored_findings=scored_findings,
        incidents=incidents,
    )

@app.post("/correlate/dast")
def correlate_dast(payload: DastPayload):
    e = payload.exploit_score
    r_score = round((0.25 * e + 0.25 * (1 if payload.exploit_confirmed else 0)) * 10, 2)

    return {
        "scan_id": payload.scan_id,
        "status": "correlated",
        "source": payload.source,
        "target_url": payload.target_url,
        "findings_count": payload.findings_count,
        "exploit_confirmed": payload.exploit_confirmed,
        "exploit_score": payload.exploit_score,
        "r_score_partial": r_score
    }
@app.post("/correlate/final")
def correlate_final(payload: FinalCorrelationPayload):
    alpha = 0.35
    beta = 0.30
    gamma = 0.25
    delta = 0.10

    A = clamp(payload.anomaly_score)
    V = clamp(payload.vuln_score)
    E = 1.0 if payload.exploit_confirmed else 0.0
    C = clamp(payload.asset_criticality)

    r = (alpha * A) + (beta * V) + (gamma * E) + (delta * C)
    r_final = round(r * 10, 2)

    if r_final >= 8:
        severity = "CRITICAL"
    elif r_final >= 6:
        severity = "HIGH"
    elif r_final >= 4:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "scan_id": payload.scan_id,
        "inputs": {
            "anomaly_score": A,
            "vuln_score": V,
            "exploit_confirmed": payload.exploit_confirmed,
            "asset_criticality": C
        },
        "weights": {
            "alpha_ids": alpha,
            "beta_vuln": beta,
            "gamma_exploit": gamma,
            "delta_criticality": delta
        },
        "components": {
            "ids_component": round(alpha * A, 4),
            "vuln_component": round(beta * V, 4),
            "exploit_component": round(gamma * E, 4),
            "criticality_component": round(delta * C, 4)
        },
        "r_score": r_final,
        "severity": severity
    }