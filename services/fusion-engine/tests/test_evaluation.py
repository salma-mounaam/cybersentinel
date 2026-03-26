from app.evaluation_data import get_evaluation_alerts
from app.evaluation import (
    evaluate_raw_alerts,
    evaluate_fused_alerts,
    compare_raw_vs_fused,
    build_evaluation_summary,
)


def test_evaluate_raw_alerts_returns_valid_metrics():
    alerts = get_evaluation_alerts()
    metrics = evaluate_raw_alerts(alerts, raw_confidence_threshold=0.60)

    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "fpr" in metrics

    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert 0.0 <= metrics["fpr"] <= 1.0


def test_evaluate_fused_alerts_returns_valid_metrics():
    alerts = get_evaluation_alerts()
    metrics = evaluate_fused_alerts(alerts, fused_confidence_threshold=0.65)

    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "fpr" in metrics

    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1_score"] <= 1.0
    assert 0.0 <= metrics["fpr"] <= 1.0


def test_compare_raw_vs_fused_contains_both_sections():
    alerts = get_evaluation_alerts()
    result = compare_raw_vs_fused(alerts)

    assert "raw_alerts" in result
    assert "fused_alerts" in result


def test_build_evaluation_summary_contains_improvements():
    alerts = get_evaluation_alerts()
    summary = build_evaluation_summary(alerts)

    assert "dataset_size" in summary
    assert "raw_alerts" in summary
    assert "fused_alerts" in summary
    assert "improvements" in summary

    improvements = summary["improvements"]
    assert "precision_gain" in improvements
    assert "recall_gain" in improvements
    assert "f1_gain" in improvements
    assert "fpr_reduction" in improvements