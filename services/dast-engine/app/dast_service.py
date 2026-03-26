from app.sandbox_manager import SandboxManager
from app.zap_client import run_zap_scan
from app.correlation_client import send_dast_result

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


def build_dast_payload(scan_id: str, target_url: str, alerts: list) -> dict:
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

    return {
        "scan_id": scan_id,
        "source": "dast",
        "target_url": target_url,
        "exploit_confirmed": len(findings) > 0,
        "exploit_score": max_risk,
        "findings_count": len(findings),
        "findings": findings
    }


def run_dast_scan(scan_id: str):
    sandbox = sandbox_manager.create_target_container(scan_id, "dvwa")
    target_url = sandbox["target_url"]

    try:
        raw_alerts = run_zap_scan(target_url)
        filtered_alerts = filter_alerts(raw_alerts)

        dast_result = build_dast_payload(scan_id, target_url, filtered_alerts)

        correlation_response = send_dast_result(dast_result)

        return {
            "dast_result": dast_result,
            "correlation_response": correlation_response
        }

    finally:
        sandbox_manager.delete_target_container(scan_id)