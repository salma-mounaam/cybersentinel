from collections import defaultdict
from datetime import timedelta
from uuid import uuid4
from typing import List, Tuple, Dict, Any

from app.schemas import AlertEvent, FusedAlert, Finding
from app.scoring import enrich_with_confidence
from app.criticality import infer_asset_criticality

FUSION_WINDOW_SECONDS = 10


def build_group_key(alert: AlertEvent) -> Tuple[str, str, int | None, str]:
    return (
        alert.src_ip,
        alert.dst_ip,
        alert.dst_port,
        alert.protocol.upper()
    )


def is_within_time_window(
    previous_alert: AlertEvent,
    current_alert: AlertEvent,
    window_seconds: int = FUSION_WINDOW_SECONDS
) -> bool:
    return (current_alert.timestamp - previous_alert.timestamp) <= timedelta(seconds=window_seconds)


def build_fused_alert(cluster: List[AlertEvent]) -> FusedAlert:
    first = cluster[0]
    last = cluster[-1]

    sources = sorted(set(alert.source for alert in cluster))
    attack_types = sorted(set(alert.attack_type for alert in cluster))
    member_ids = [alert.alert_id for alert in cluster]

    avg_confidence = round(
        sum(alert.raw_confidence for alert in cluster) / len(cluster),
        4
    )

    aggregated_severity = max(alert.severity for alert in cluster)

    fused_alert = FusedAlert(
        fusion_id=str(uuid4()),
        start_time=first.timestamp,
        end_time=last.timestamp,
        src_ip=first.src_ip,
        dst_ip=first.dst_ip,
        src_port=first.src_port,
        dst_port=first.dst_port,
        protocol=first.protocol.upper(),
        sources=sources,
        attack_types=attack_types,
        events_count=len(cluster),
        aggregated_severity=aggregated_severity,
        avg_raw_confidence=avg_confidence,
        member_alert_ids=member_ids
    )

    return enrich_with_confidence(fused_alert)


def temporal_fusion(alerts: List[AlertEvent]) -> List[FusedAlert]:
    if not alerts:
        return []

    grouped_alerts = defaultdict(list)

    for alert in sorted(alerts, key=lambda a: a.timestamp):
        key = build_group_key(alert)
        grouped_alerts[key].append(alert)

    fused_alerts: List[FusedAlert] = []

    for _, group in grouped_alerts.items():
        current_cluster = [group[0]]

        for current_alert in group[1:]:
            previous_alert = current_cluster[-1]

            if is_within_time_window(previous_alert, current_alert):
                current_cluster.append(current_alert)
            else:
                fused_alerts.append(build_fused_alert(current_cluster))
                current_cluster = [current_alert]

        if current_cluster:
            fused_alerts.append(build_fused_alert(current_cluster))

    fused_alerts.sort(key=lambda x: x.start_time)
    return fused_alerts


def find_best_anomaly_score(finding: Finding, ml_events: List[Dict[str, Any]]) -> float:
    if not ml_events:
        return 0.0

    file_path = (finding.file or "").lower()
    title = (finding.title or "").lower()
    related_scores = []

    for event in ml_events:
        event_surface = str(event.get("surface", "")).lower()
        event_score = float(event.get("anomaly_score", 0.0))

        if "api" in file_path and event_surface == "web":
            related_scores.append(event_score)
        elif "sql" in title and event_surface in {"web", "database"}:
            related_scores.append(event_score)
        elif ("command" in title or "exec" in title or "rce" in title) and event_surface in {"web", "system"}:
            related_scores.append(event_score)
        else:
            related_scores.append(event_score * 0.5)

    return round(max(related_scores) if related_scores else 0.0, 4)


def find_exploitability(finding: Finding, dast_results: List[Dict[str, Any]]) -> tuple[bool, float]:
    title = (finding.title or "").lower()
    file_path = (finding.file or "").lower()

    for result in dast_results:
        vuln_type = str(result.get("type", "")).lower()
        confirmed = bool(result.get("confirmed", False))

        if not confirmed:
            continue

        if "sql" in title and "sql" in vuln_type:
            return True, 1.0
        if ("command" in title or "exec" in title or "rce" in title) and ("rce" in vuln_type or "command" in vuln_type):
            return True, 1.0
        if "xss" in title and "xss" in vuln_type:
            return True, 1.0
        if "api" in file_path and result.get("surface") == "web":
            return True, 0.8

    if "sql" in title:
        return False, 0.75
    if "command" in title or "rce" in title or "exec" in title:
        return False, 0.80
    if "secret" in title or "token" in title or "password" in title or "apikey" in title:
        return False, 0.85

    return False, 0.30


def enrich_findings_for_r_score(
    findings: List[Finding],
    ml_events: List[Dict[str, Any]],
    dast_results: List[Dict[str, Any]],
    asset_context: Dict[str, Any],
) -> List[Finding]:
    fused = []

    for finding in findings:
        finding.anomaly_score = find_best_anomaly_score(finding, ml_events)

        exploit_confirmed, exploit_score = find_exploitability(finding, dast_results)
        finding.exploit_confirmed = exploit_confirmed
        finding.exploit_score = exploit_score

        finding.asset_criticality = infer_asset_criticality(finding, asset_context)

        fused.append(finding)

    return fused