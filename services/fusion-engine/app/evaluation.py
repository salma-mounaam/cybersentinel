from typing import Dict, List

from app.schemas import AlertEvent, FusedAlert
from app.fusion_service import temporal_fusion


def compute_binary_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "fpr": round(fpr, 4),
    }


def evaluate_raw_alerts(
    alerts: List[AlertEvent],
    raw_confidence_threshold: float = 0.60
) -> Dict[str, float]:
    """
    Évaluation simple des alertes brutes.
    Une alerte est considérée comme 'détection positive' si raw_confidence >= seuil.
    """
    tp = fp = tn = fn = 0

    for alert in alerts:
        ground_truth = alert.details.get("ground_truth", "benign")
        predicted_positive = alert.raw_confidence >= raw_confidence_threshold

        if ground_truth == "attack" and predicted_positive:
            tp += 1
        elif ground_truth == "attack" and not predicted_positive:
            fn += 1
        elif ground_truth == "benign" and predicted_positive:
            fp += 1
        elif ground_truth == "benign" and not predicted_positive:
            tn += 1

    return compute_binary_metrics(tp, fp, tn, fn)


def determine_fused_ground_truth(member_alerts: List[AlertEvent]) -> str:
    """
    Si au moins une alerte du cluster correspond à une vraie attaque,
    on considère l'incident fusionné comme une attaque.
    """
    truths = [alert.details.get("ground_truth", "benign") for alert in member_alerts]
    return "attack" if "attack" in truths else "benign"


def build_alert_lookup(alerts: List[AlertEvent]) -> Dict[str, AlertEvent]:
    return {alert.alert_id: alert for alert in alerts}


def evaluate_fused_alerts(
    alerts: List[AlertEvent],
    fused_confidence_threshold: float = 0.65
) -> Dict[str, float]:
    """
    Évaluation des alertes fusionnées.
    Une alerte fusionnée est positive si confidence_score >= seuil.
    """
    fused_alerts = temporal_fusion(alerts)
    alert_lookup = build_alert_lookup(alerts)

    tp = fp = tn = fn = 0

    for fused in fused_alerts:
        member_alerts = [alert_lookup[alert_id] for alert_id in fused.member_alert_ids]
        ground_truth = determine_fused_ground_truth(member_alerts)
        predicted_positive = fused.confidence_score >= fused_confidence_threshold

        if ground_truth == "attack" and predicted_positive:
            tp += 1
        elif ground_truth == "attack" and not predicted_positive:
            fn += 1
        elif ground_truth == "benign" and predicted_positive:
            fp += 1
        elif ground_truth == "benign" and not predicted_positive:
            tn += 1

    return compute_binary_metrics(tp, fp, tn, fn)


def compare_raw_vs_fused(
    alerts: List[AlertEvent],
    raw_confidence_threshold: float = 0.60,
    fused_confidence_threshold: float = 0.65
) -> Dict[str, Dict[str, float]]:
    raw_metrics = evaluate_raw_alerts(alerts, raw_confidence_threshold=raw_confidence_threshold)
    fused_metrics = evaluate_fused_alerts(alerts, fused_confidence_threshold=fused_confidence_threshold)

    return {
        "raw_alerts": raw_metrics,
        "fused_alerts": fused_metrics
    }


def build_evaluation_summary(
    alerts: List[AlertEvent],
    raw_confidence_threshold: float = 0.60,
    fused_confidence_threshold: float = 0.65
) -> Dict:
    comparison = compare_raw_vs_fused(
        alerts=alerts,
        raw_confidence_threshold=raw_confidence_threshold,
        fused_confidence_threshold=fused_confidence_threshold
    )

    raw_metrics = comparison["raw_alerts"]
    fused_metrics = comparison["fused_alerts"]

    return {
        "dataset_size": len(alerts),
        "raw_threshold": raw_confidence_threshold,
        "fused_threshold": fused_confidence_threshold,
        "raw_alerts": raw_metrics,
        "fused_alerts": fused_metrics,
        "improvements": {
            "precision_gain": round(fused_metrics["precision"] - raw_metrics["precision"], 4),
            "recall_gain": round(fused_metrics["recall"] - raw_metrics["recall"], 4),
            "f1_gain": round(fused_metrics["f1_score"] - raw_metrics["f1_score"], 4),
            "fpr_reduction": round(raw_metrics["fpr"] - fused_metrics["fpr"], 4)
        }
    }