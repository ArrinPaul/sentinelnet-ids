"""
ML Model Inference Module
Loads the trained Isolation Forest model + scaler and provides prediction functions.
Uses StandardScaler for feature normalization matching training pipeline.
"""

import os
import numpy as np
import joblib
import logging

logger = logging.getLogger("network-ids.ml-inference")

# ── Paths ────────────────────────────────────────────────────────────────────
ML_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(ML_DIR, "model.pkl")
SCALER_PATH = os.path.join(ML_DIR, "scaler.pkl")

# ── Protocol encoding (must match training) ──────────────────────────────────
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}

# ── Global instances ─────────────────────────────────────────────────────────
_model = None
_scaler = None


def load_model():
    """Load the trained model and scaler from disk."""
    global _model, _scaler

    if os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
        logger.info(f"ML model loaded from {MODEL_PATH}")
    else:
        logger.warning(f"ML model not found at {MODEL_PATH}. ML IDS will be disabled.")
        _model = None

    if os.path.exists(SCALER_PATH):
        _scaler = joblib.load(SCALER_PATH)
        logger.info(f"Scaler loaded from {SCALER_PATH}")
    else:
        logger.warning(f"Scaler not found at {SCALER_PATH}. Features will not be scaled.")
        _scaler = None


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

    Returns:
        dict with: anomaly (bool), score (float), confidence (float), status (str)
    """
    global _model, _scaler

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

    # Apply scaler if available (matches training pipeline)
    if _scaler is not None:
        features = _scaler.transform(features)

    # Isolation Forest: predict returns 1 (normal) or -1 (anomaly)
    prediction = _model.predict(features)[0]
    # decision_function: negative = more anomalous, positive = more normal
    anomaly_score = _model.decision_function(features)[0]

    is_anomaly = prediction == -1

    # Calibrated confidence based on anomaly score distribution
    # Typical decision_function range is roughly [-0.5, 0.5]
    # Map to [0, 1] where higher = more confident it's anomalous
    if is_anomaly:
        # For anomalies: more negative score = higher confidence
        confidence = min(1.0, max(0.3, 0.5 + abs(anomaly_score) * 2.0))
    else:
        # For normal: more positive score = higher confidence it's normal
        confidence = min(1.0, max(0.0, anomaly_score * 1.5))

    return {
        "anomaly": bool(is_anomaly),
        "score": round(float(anomaly_score), 4),
        "confidence": round(float(confidence), 4),
        "status": "ok",
    }
