from app.schemas import FusedAlert

SOURCE_WEIGHTS = {
    "suricata": 0.80,
    "ml_isolation_forest": 0.65,
    "ml_ocsvm": 0.68,
    "ml_autoencoder": 0.72
}


def compute_source_score(fused_alert: FusedAlert) -> float:
    weights = [SOURCE_WEIGHTS.get(source, 0.50) for source in fused_alert.sources]
    return round(sum(weights) / len(weights), 4) if weights else 0.0


def compute_severity_score(fused_alert: FusedAlert) -> float:
    return round(min(fused_alert.aggregated_severity / 5, 1.0), 4)


def compute_repetition_score(fused_alert: FusedAlert) -> float:
    return round(min(fused_alert.events_count / 5, 1.0), 4)


def compute_temporal_coherence_score(fused_alert: FusedAlert) -> float:
    duration_seconds = (fused_alert.end_time - fused_alert.start_time).total_seconds()

    if fused_alert.events_count <= 1:
        return 0.5

    if duration_seconds <= 5:
        return 1.0
    if duration_seconds <= 10:
        return 0.9
    if duration_seconds <= 20:
        return 0.7
    return 0.5


def compute_multi_source_score(fused_alert: FusedAlert) -> float:
    return 1.0 if len(fused_alert.sources) > 1 else 0.0


def classify_confidence(score: float) -> str:
    if score >= 0.70:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"


def compute_confidence_score(fused_alert: FusedAlert) -> float:
    source_score = compute_source_score(fused_alert)
    severity_score = compute_severity_score(fused_alert)
    repetition_score = compute_repetition_score(fused_alert)
    temporal_score = compute_temporal_coherence_score(fused_alert)
    multi_source_score = compute_multi_source_score(fused_alert)

    final_score = (
        0.35 * source_score +
        0.20 * severity_score +
        0.20 * repetition_score +
        0.15 * temporal_score +
        0.10 * multi_source_score
    )

    return round(min(max(final_score, 0.0), 1.0), 4)


def enrich_with_confidence(fused_alert: FusedAlert) -> FusedAlert:
    score = compute_confidence_score(fused_alert)
    level = classify_confidence(score)

    fused_alert.confidence_score = score
    fused_alert.confidence_level = level
    return fused_alert