from typing import Dict, List

from app.schemas import Finding, RScoreBreakdown
from app.utils import normalize_severity, infer_category, risk_level_from_score


DEFAULT_WEIGHTS = {
    "A": 0.35,  # Anomaly
    "V": 0.30,  # Vulnerability severity
    "E": 0.25,  # Exploitability
    "C": 0.10,  # Asset criticality
}


SEVERITY_TO_SCORE = {
    "CRITICAL": 1.00,
    "HIGH": 0.85,
    "MEDIUM": 0.60,
    "LOW": 0.30,
    "INFO": 0.10,
}


CATEGORY_TO_SCORE = {
    "secret_exposure": 0.95,
    "credential_exposure": 0.90,
    "code_vulnerability": 0.80,
    "dependency_vulnerability": 0.70,
    "misconfiguration": 0.50,
    "container_risk": 0.55,
    "network_alert": 0.75,
    "generic_security_finding": 0.40,
}


def clamp(value: float, min_value: float = 0.0, max_value: float = 1.0) -> float:
    return max(min_value, min(max_value, value))


def compute_anomaly_score(finding: Finding) -> float:
    if finding.anomaly_score is not None:
        return round(clamp(finding.anomaly_score), 4)
    return 0.0


def compute_vulnerability_score(finding: Finding) -> float:
    severity = normalize_severity(finding.severity)
    severity_score = SEVERITY_TO_SCORE.get(severity, 0.30)

    category = infer_category(finding)
    category_score = CATEGORY_TO_SCORE.get(category, 0.40)

    confidence = clamp(finding.confidence if finding.confidence is not None else 0.5)

    score = (
        0.50 * severity_score +
        0.30 * category_score +
        0.20 * confidence
    )
    return round(clamp(score), 4)


def compute_exploitability_score(finding: Finding) -> float:
    if finding.exploit_score is not None:
        return round(clamp(finding.exploit_score), 4)

    if finding.exploit_confirmed:
        return 1.0

    title = (finding.title or "").lower()
    category = infer_category(finding)

    if "sql" in title or "sqli" in title:
        return 0.75
    if "command" in title or "rce" in title or "exec" in title:
        return 0.80
    if "secret" in title or "password" in title or "token" in title or "apikey" in title:
        return 0.85
    if category == "dependency_vulnerability" and finding.fix_available:
        return 0.60
    if category == "network_alert":
        return 0.50

    return 0.30


def compute_criticality_score(finding: Finding) -> float:
    if finding.asset_criticality is not None:
        return round(clamp(finding.asset_criticality), 4)

    surface = (finding.surface or "").lower()
    title = (finding.title or "").lower()
    file_path = (finding.file or "").lower()

    if "auth" in surface or "login" in title or "jwt" in title or "token" in title:
        return 0.90
    if "config" in file_path or "secret" in title or "password" in title:
        return 0.95
    if "api" in file_path or "controller" in file_path or surface == "web":
        return 0.80
    if "dockerfile" in file_path or surface == "container":
        return 0.50
    if surface == "network":
        return 0.70

    return 0.50


def compute_r_score_for_finding(
    finding: Finding,
    weights: Dict[str, float] | None = None
) -> RScoreBreakdown:
    weights = weights or DEFAULT_WEIGHTS

    A = compute_anomaly_score(finding)
    V = compute_vulnerability_score(finding)
    E = compute_exploitability_score(finding)
    C = compute_criticality_score(finding)

    r = (
        weights["A"] * A +
        weights["V"] * V +
        weights["E"] * E +
        weights["C"] * C
    )

    final_score = round(clamp(r) * 100)
    final_level = risk_level_from_score(final_score)

    return RScoreBreakdown(
        anomaly_score=A,
        vulnerability_score=V,
        exploitability_score=E,
        criticality_score=C,
        weights=weights,
        final_score=final_score,
        final_level=final_level,
    )


def compute_r_score_for_incident(
    findings: List[Finding],
    weights: Dict[str, float] | None = None
) -> RScoreBreakdown:
    weights = weights or DEFAULT_WEIGHTS

    if not findings:
        return RScoreBreakdown(
            anomaly_score=0.0,
            vulnerability_score=0.0,
            exploitability_score=0.0,
            criticality_score=0.0,
            weights=weights,
            final_score=0,
            final_level="INFO",
        )

    anomaly_scores = [compute_anomaly_score(f) for f in findings]
    vulnerability_scores = [compute_vulnerability_score(f) for f in findings]
    exploitability_scores = [compute_exploitability_score(f) for f in findings]
    criticality_scores = [compute_criticality_score(f) for f in findings]

    # stratégie prudente : on retient le max par dimension
    A = max(anomaly_scores) if anomaly_scores else 0.0
    V = max(vulnerability_scores) if vulnerability_scores else 0.0
    E = max(exploitability_scores) if exploitability_scores else 0.0
    C = max(criticality_scores) if criticality_scores else 0.0

    r = (
        weights["A"] * A +
        weights["V"] * V +
        weights["E"] * E +
        weights["C"] * C
    )

    final_score = round(clamp(r) * 100)
    final_level = risk_level_from_score(final_score)

    return RScoreBreakdown(
        anomaly_score=round(A, 4),
        vulnerability_score=round(V, 4),
        exploitability_score=round(E, 4),
        criticality_score=round(C, 4),
        weights=weights,
        final_score=final_score,
        final_level=final_level,
    )