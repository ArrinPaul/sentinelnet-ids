"""
ML Model Inference Module
Loads the trained Isolation Forest model and provides prediction functions.
"""

import os
import numpy as np
import joblib
import logging

logger = logging.getLogger("network-ids.ml-inference")

# ── Paths ────────────────────────────────────────────────────────────────────
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

# ── Protocol encoding (must match training) ──────────────────────────────────
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}

# ── Global model instance ───────────────────────────────────────────────────
_model = None


def load_model():
    """Load the trained model from disk."""
    global _model
    if os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
        logger.info(f"ML model loaded from {MODEL_PATH}")
    else:
        logger.warning(f"ML model not found at {MODEL_PATH}. ML IDS will be disabled.")
        _model = None


def prepare_features(traffic: dict) -> np.ndarray:
    """Convert traffic record to feature vector matching training format."""
    protocol_flag = PROTOCOL_MAP.get(traffic.get("protocol", "").upper(), 3)
    features = np.array([
        traffic["packet_rate"],
        traffic["unique_ports"],
        traffic["avg_packet_size"],
        traffic["duration"],
        protocol_flag,
    ]).reshape(1, -1)
    return features


def predict(traffic: dict) -> dict:
    """
    Run anomaly detection on a traffic record.
    Returns: {anomaly: bool, score: float, confidence: float}
    """
    global _model

    if _model is None:
        load_model()

    if _model is None:
        return {
            "anomaly": False,
            "score": 0.0,
            "confidence": 0.0,
            "status": "model_unavailable",
        }

    features = prepare_features(traffic)

    # Isolation Forest: predict returns 1 (normal) or -1 (anomaly)
    prediction = _model.predict(features)[0]
    # decision_function: negative = more anomalous, positive = more normal
    anomaly_score = _model.decision_function(features)[0]

    is_anomaly = prediction == -1

    # Convert score to 0-1 confidence (lower decision score = higher anomaly confidence)
    confidence = max(0.0, min(1.0, 0.5 - anomaly_score))

    return {
        "anomaly": bool(is_anomaly),
        "score": round(float(anomaly_score), 4),
        "confidence": round(float(confidence), 4),
        "status": "ok",
    }
