from datetime import datetime, timedelta

from app.schemas import FusedAlert
from app.scoring import (
    compute_confidence_score,
    classify_confidence,
    enrich_with_confidence
)


def test_confidence_score_high_for_multisource_alert():
    fused_alert = FusedAlert(
        fusion_id="fusion-1",
        start_time=datetime.fromisoformat("2026-03-16T10:20:00"),
        end_time=datetime.fromisoformat("2026-03-16T10:20:04"),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        src_port=52344,
        dst_port=80,
        protocol="TCP",
        sources=["suricata", "ml_autoencoder"],
        attack_types=["PortScan", "Anomaly"],
        events_count=4,
        aggregated_severity=4,
        avg_raw_confidence=0.83,
        member_alert_ids=["1", "2", "3", "4"]
    )

    score = compute_confidence_score(fused_alert)

    assert 0.70 <= score <= 1.0
    assert classify_confidence(score) == "high"


def test_confidence_score_low_for_single_weak_alert():
    fused_alert = FusedAlert(
        fusion_id="fusion-2",
        start_time=datetime.fromisoformat("2026-03-16T10:20:00"),
        end_time=datetime.fromisoformat("2026-03-16T10:20:00"),
        src_ip="192.168.1.20",
        dst_ip="10.0.0.8",
        src_port=44444,
        dst_port=443,
        protocol="TCP",
        sources=["ml_isolation_forest"],
        attack_types=["Anomaly"],
        events_count=1,
        aggregated_severity=1,
        avg_raw_confidence=0.51,
        member_alert_ids=["9"]
    )

    score = compute_confidence_score(fused_alert)

    assert 0.0 <= score < 0.40
    assert classify_confidence(score) == "low"


def test_enrich_with_confidence_updates_fields():
    fused_alert = FusedAlert(
        fusion_id="fusion-3",
        start_time=datetime.now(),
        end_time=datetime.now() + timedelta(seconds=3),
        src_ip="1.1.1.1",
        dst_ip="2.2.2.2",
        src_port=1111,
        dst_port=80,
        protocol="TCP",
        sources=["suricata", "ml_ocsvm"],
        attack_types=["Suspicious", "Anomaly"],
        events_count=3,
        aggregated_severity=3,
        avg_raw_confidence=0.74,
        member_alert_ids=["a", "b", "c"]
    )

    enriched = enrich_with_confidence(fused_alert)

    assert 0.0 <= enriched.confidence_score <= 1.0
    assert enriched.confidence_level in ["low", "medium", "high"]