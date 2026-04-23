"""
Sentinel – ML Risk Score Predictor
Scores each finding 0.0–1.0 based on its feature vector.
"""
import logging
import numpy as np
from backend.ml.trainer import load_or_train, FEATURE_COLUMNS

logger = logging.getLogger(__name__)

# Severity → numeric score mapping (for display)
SEVERITY_SCORE_MAP = {
    "CRITICAL": 1.0,
    "HIGH": 0.75,
    "MEDIUM": 0.5,
    "LOW": 0.25,
}

_model = None
_label_encoder = None


def _get_model():
    global _model, _label_encoder
    if _model is None:
        _model, _label_encoder = load_or_train()
    return _model, _label_encoder


def predict_risk_score(ml_features: dict) -> float:
    """
    Given a feature dict, return a risk score between 0.0 and 1.0.
    Falls back to severity-based score if features are missing.
    """
    if not ml_features:
        return 0.5

    try:
        clf, le = _get_model()

        # Build feature vector in correct column order
        feature_vector = [[ml_features.get(col, 0) for col in FEATURE_COLUMNS]]

        # Get probability for each class
        proba = clf.predict_proba(feature_vector)[0]
        # Weighted score: CRITICAL=1.0, HIGH=0.75, MEDIUM=0.5, LOW=0.25
        weights = []
        for cls in le.classes_:
            weights.append(SEVERITY_SCORE_MAP.get(cls, 0.5))

        score = float(np.dot(proba, weights))
        return round(min(max(score, 0.0), 1.0), 4)

    except Exception as e:
        logger.warning(f"ML prediction failed, using fallback: {e}")
        return 0.5


def predict_batch(findings: list[dict]) -> list[float]:
    """Score a batch of findings."""
    return [predict_risk_score(f.get("ml_features", {})) for f in findings]
