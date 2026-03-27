from typing import Any, Dict, List


def _normalize_severity(value: str) -> str:
    return str(value or "").strip().lower()


def _count_by_severity(findings: List[Dict[str, Any]], severity: str) -> int:
    target = severity.lower()
    return sum(
        1
        for finding in findings
        if _normalize_severity(finding.get("severity")) == target
    )


def _count_secrets(findings: List[Dict[str, Any]]) -> int:
    secret_keywords = {
        "secret",
        "token",
        "password",
        "credential",
        "api_key",
        "apikey",
        "private_key",
        "aws_access_key",
    }

    count = 0
    for finding in findings:
        title = str(finding.get("title", "")).lower()
        finding_type = str(finding.get("type", "")).lower()
        rule_id = str(finding.get("rule_id", "")).lower()
        description = str(finding.get("description", "")).lower()

        if any(
            keyword in title
            or keyword in finding_type
            or keyword in rule_id
            or keyword in description
            for keyword in secret_keywords
        ):
            count += 1

    return count


def evaluate_quality_gate(
    sast_result: Dict[str, Any],
    dast_result: Dict[str, Any],
    correlation_result: Dict[str, Any],
) -> Dict[str, Any]:
    sast_findings = sast_result.get("findings", []) or []
    dast_findings = dast_result.get("findings", []) or []
    all_findings = list(sast_findings) + list(dast_findings)

    critical_count = _count_by_severity(all_findings, "critical")
    high_count = _count_by_severity(all_findings, "high")
    secrets_count = _count_secrets(all_findings)

    exploit_confirmed = bool(dast_result.get("exploit_confirmed", False))
    r_score = float(correlation_result.get("r_score", 0.0))
    ml_anomaly = bool(correlation_result.get("ml_anomaly", False))

    fail_reasons = []

    if critical_count > 0:
        fail_reasons.append(f"{critical_count} critical finding(s) detected")

    if secrets_count > 0:
        fail_reasons.append(f"{secrets_count} exposed secret(s) detected")

    if exploit_confirmed:
        fail_reasons.append("exploit confirmed by DAST")

    if r_score >= 8:
        fail_reasons.append(f"R score too high: {r_score}")

    if fail_reasons:
        return {
            "status": "FAIL",
            "reasons": fail_reasons,
            "summary": {
                "critical_count": critical_count,
                "high_count": high_count,
                "secrets_count": secrets_count,
                "exploit_confirmed": exploit_confirmed,
                "r_score": r_score,
                "ml_anomaly": ml_anomaly,
            },
        }

    warning_reasons = []

    if 5 <= r_score < 8:
        warning_reasons.append(f"R score warning range: {r_score}")

    if high_count > 0:
        warning_reasons.append(f"{high_count} high finding(s) detected")

    if ml_anomaly:
        warning_reasons.append("network anomaly detected without confirmed exploit")

    if warning_reasons:
        return {
            "status": "WARNING",
            "reasons": warning_reasons,
            "summary": {
                "critical_count": critical_count,
                "high_count": high_count,
                "secrets_count": secrets_count,
                "exploit_confirmed": exploit_confirmed,
                "r_score": r_score,
                "ml_anomaly": ml_anomaly,
            },
        }

    return {
        "status": "PASS",
        "reasons": ["No blocking issue detected"],
        "summary": {
            "critical_count": critical_count,
            "high_count": high_count,
            "secrets_count": secrets_count,
            "exploit_confirmed": exploit_confirmed,
            "r_score": r_score,
            "ml_anomaly": ml_anomaly,
        },
    }