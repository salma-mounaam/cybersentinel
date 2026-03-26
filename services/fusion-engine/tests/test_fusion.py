from datetime import datetime

from app.schemas import AlertEvent
from app.fusion_service import temporal_fusion


def test_temporal_fusion_creates_two_clusters():
    alerts = [
        AlertEvent(
            alert_id="1",
            source="suricata",
            timestamp=datetime.fromisoformat("2026-03-16T10:20:00"),
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            src_port=52344,
            dst_port=80,
            protocol="TCP",
            attack_type="PortScan",
            severity=3,
            raw_confidence=0.78,
            details={}
        ),
        AlertEvent(
            alert_id="2",
            source="ml_autoencoder",
            timestamp=datetime.fromisoformat("2026-03-16T10:20:04"),
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            src_port=52344,
            dst_port=80,
            protocol="TCP",
            attack_type="Anomaly",
            severity=2,
            raw_confidence=0.84,
            details={}
        ),
        AlertEvent(
            alert_id="3",
            source="ml_ocsvm",
            timestamp=datetime.fromisoformat("2026-03-16T10:20:25"),
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            src_port=52344,
            dst_port=80,
            protocol="TCP",
            attack_type="Anomaly",
            severity=2,
            raw_confidence=0.66,
            details={}
        )
    ]

    result = temporal_fusion(alerts)

    assert len(result) == 2
    assert result[0].events_count == 2
    assert result[1].events_count == 1
    assert result[0].member_alert_ids == ["1", "2"]
    assert result[1].member_alert_ids == ["3"]
    assert 0.0 <= result[0].confidence_score <= 1.0
    assert result[0].confidence_level in ["low", "medium", "high"]


def test_temporal_fusion_separates_different_flows():
    alerts = [
        AlertEvent(
            alert_id="1",
            source="suricata",
            timestamp=datetime.fromisoformat("2026-03-16T10:20:00"),
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            src_port=50000,
            dst_port=80,
            protocol="TCP",
            attack_type="PortScan",
            severity=3,
            raw_confidence=0.80,
            details={}
        ),
        AlertEvent(
            alert_id="2",
            source="ml_autoencoder",
            timestamp=datetime.fromisoformat("2026-03-16T10:20:03"),
            src_ip="192.168.1.11",
            dst_ip="10.0.0.5",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            attack_type="Anomaly",
            severity=2,
            raw_confidence=0.82,
            details={}
        )
    ]

    result = temporal_fusion(alerts)

    assert len(result) == 2
    assert result[0].events_count == 1
    assert result[1].events_count == 1