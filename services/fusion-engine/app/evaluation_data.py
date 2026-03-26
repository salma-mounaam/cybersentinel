from datetime import datetime

from app.schemas import AlertEvent


def get_evaluation_alerts():
    """
    Jeu de données simulé pour l'évaluation.
    Chaque alerte possède un label de vérité terrain dans details["ground_truth"] :
    - "attack"  -> vrai positif potentiel
    - "benign"  -> faux positif potentiel si détecté
    """

    return [
        # Incident réel 1 : Suricata + ML sur le même flux => doit être fusionné, vrai incident
        AlertEvent(
            alert_id="a1",
            source="suricata",
            timestamp=datetime.fromisoformat("2026-03-16T11:00:00"),
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            attack_type="PortScan",
            severity=4,
            raw_confidence=0.88,
            details={"ground_truth": "attack"}
        ),
        AlertEvent(
            alert_id="a2",
            source="ml_autoencoder",
            timestamp=datetime.fromisoformat("2026-03-16T11:00:03"),
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            src_port=50001,
            dst_port=80,
            protocol="TCP",
            attack_type="Anomaly",
            severity=3,
            raw_confidence=0.81,
            details={"ground_truth": "attack"}
        ),

        # Incident réel 2 : ML seul, doit rester détecté
        AlertEvent(
            alert_id="a3",
            source="ml_ocsvm",
            timestamp=datetime.fromisoformat("2026-03-16T11:01:00"),
            src_ip="192.168.1.20",
            dst_ip="10.0.0.8",
            src_port=53000,
            dst_port=443,
            protocol="TCP",
            attack_type="Anomaly",
            severity=4,
            raw_confidence=0.79,
            details={"ground_truth": "attack"}
        ),

        # Bruit bénin 1 : alerte faible isolée
        AlertEvent(
            alert_id="b1",
            source="ml_isolation_forest",
            timestamp=datetime.fromisoformat("2026-03-16T11:02:00"),
            src_ip="192.168.1.30",
            dst_ip="10.0.0.9",
            src_port=54000,
            dst_port=53,
            protocol="UDP",
            attack_type="Anomaly",
            severity=1,
            raw_confidence=0.52,
            details={"ground_truth": "benign"}
        ),

        # Bruit bénin 2 : alerte signature isolée faible/moyenne
        AlertEvent(
            alert_id="b2",
            source="suricata",
            timestamp=datetime.fromisoformat("2026-03-16T11:03:00"),
            src_ip="192.168.1.40",
            dst_ip="10.0.0.10",
            src_port=55000,
            dst_port=8080,
            protocol="TCP",
            attack_type="Suspicious",
            severity=2,
            raw_confidence=0.58,
            details={"ground_truth": "benign"}
        ),

        # Bruit bénin 3 + 4 : deux alertes faibles mais même flux
        AlertEvent(
            alert_id="b3",
            source="ml_ocsvm",
            timestamp=datetime.fromisoformat("2026-03-16T11:04:00"),
            src_ip="192.168.1.50",
            dst_ip="10.0.0.11",
            src_port=56000,
            dst_port=22,
            protocol="TCP",
            attack_type="Anomaly",
            severity=1,
            raw_confidence=0.50,
            details={"ground_truth": "benign"}
        ),
        AlertEvent(
            alert_id="b4",
            source="ml_isolation_forest",
            timestamp=datetime.fromisoformat("2026-03-16T11:04:07"),
            src_ip="192.168.1.50",
            dst_ip="10.0.0.11",
            src_port=56000,
            dst_port=22,
            protocol="TCP",
            attack_type="Anomaly",
            severity=1,
            raw_confidence=0.51,
            details={"ground_truth": "benign"}
        ),
    ]