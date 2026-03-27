from app.sandbox_manager import SandboxManager
from app.zap_client import run_zap_scan, get_zap_messages_for_target
from app.correlation_client import send_dast_result
from app.ml_client import send_features_to_ml
from app.feature_builder import build_ml_features_from_zap_messages

import math

sandbox_manager = SandboxManager()


def normalize_risk(risk: str) -> float:
    mapping = {
        "informational": 0.0,
        "low": 0.3,
        "medium": 0.6,
        "high": 0.9,
        "critical": 1.0
    }
    return mapping.get((risk or "").lower(), 0.0)


def normalize_ml_score(raw_score: float, threshold: float | None = None) -> float:
    """
    Convertit un score brut potentiellement énorme en score borné [0, 1].
    """
    if raw_score is None:
        return 0.0

    if raw_score <= 0:
        return 0.0

    normalized = 1.0 - math.exp(-math.log10(raw_score + 1.0))
    normalized = max(0.0, min(1.0, normalized))
    return round(normalized, 4)


def enrich_ml_result(ml_result: dict | None) -> dict | None:
    if ml_result is None:
        return None

    raw_score = ml_result.get("anomaly_score")
    threshold = ml_result.get("threshold")

    normalized_score = normalize_ml_score(raw_score, threshold)

    enriched = dict(ml_result)
    enriched["raw_anomaly_score"] = raw_score
    enriched["normalized_anomaly_score"] = normalized_score

    return enriched


def filter_alerts(alerts: list) -> list:
    filtered = []
    seen = set()

    for alert in alerts:
        risk = (alert.get("risk") or "").lower()
        key = (alert.get("alert"), alert.get("url"))

        if risk == "informational":
            continue

        if key in seen:
            continue

        seen.add(key)
        filtered.append(alert)

    return filtered


def build_dast_payload(
    scan_id: str,
    target_url: str,
    alerts: list,
    ml_result: dict | None = None
) -> dict:
    max_risk = 0.0
    findings = []

    for alert in alerts:
        risk_label = alert.get("risk", "Informational")
        risk_score = normalize_risk(risk_label)
        max_risk = max(max_risk, risk_score)

        findings.append({
            "type": alert.get("alert"),
            "name": alert.get("name"),
            "url": alert.get("url"),
            "method": alert.get("method"),
            "risk": risk_label,
            "risk_score": risk_score,
            "description": alert.get("description"),
            "solution": alert.get("solution"),
            "cwe": alert.get("cweid"),
            "wasc": alert.get("wascid"),
            "plugin_id": alert.get("pluginId")
        })

    payload = {
        "scan_id": scan_id,
        "source": "dast",
        "target_url": target_url,
        "exploit_confirmed": len(findings) > 0,
        "exploit_score": max_risk,
        "findings_count": len(findings),
        "findings": findings
    }

    if ml_result is not None:
        payload["ml_anomaly_score"] = ml_result.get("normalized_anomaly_score")
        payload["ml_raw_anomaly_score"] = ml_result.get("raw_anomaly_score")
        payload["ml_is_anomaly"] = ml_result.get("is_anomaly")
        payload["ml_model"] = ml_result.get("model")
        payload["ml_threshold"] = ml_result.get("threshold")
        payload["ml_risk_level"] = ml_result.get("risk_level")

    return payload


def run_dast_scan(scan_id: str):
    sandbox = sandbox_manager.create_target_container(scan_id, "dvwa")
    target_url = sandbox["target_url"]

    try:
        # 1) Scan ZAP
        raw_alerts = run_zap_scan(target_url)
        filtered_alerts = filter_alerts(raw_alerts)

        # 2) Messages HTTP vus par ZAP
        zap_messages = get_zap_messages_for_target(target_url)

        # 3) Features compatibles ml-engine
        ml_features = build_ml_features_from_zap_messages(zap_messages, target_url)

        # 4) Appel du ML
        ml_result = send_features_to_ml(ml_features)
        ml_result = enrich_ml_result(ml_result)

        # 5) Payload DAST enrichi
        dast_result = build_dast_payload(
            scan_id=scan_id,
            target_url=target_url,
            alerts=filtered_alerts,
            ml_result=ml_result
        )

        # 6) Envoi à la corrélation
        correlation_response = send_dast_result(dast_result)

        return {
            "dast_result": dast_result,
            "ml_result": ml_result,
            "ml_features": ml_features,
            "messages_count": len(zap_messages),
            "correlation_response": correlation_response
        }

    finally:
        sandbox_manager.delete_target_container(scan_id)