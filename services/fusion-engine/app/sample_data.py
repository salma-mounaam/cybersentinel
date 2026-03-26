from datetime import datetime
from app.schemas import AlertEvent


def get_sample_alerts():
    return [
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
            details={
                "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected"
            }
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
            details={
                "reconstruction_error": 0.27
            }
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
            details={
                "decision_score": -0.41
            }
        ),
    ]