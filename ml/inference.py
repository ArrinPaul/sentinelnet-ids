"""
ML Model Inference Module
Loads the trained Isolation Forest + LOF ensemble and provides prediction functions.
Uses StandardScaler + derived features matching the training pipeline (v3.0).

Features (10 total):
  Raw (6):     packet_rate, unique_ports, avg_packet_size, duration, protocol_flag, connection_count
  Derived (4): bytes_per_second, port_scan_ratio, size_rate_ratio, conn_rate
"""

import os
import numpy as np
import joblib
import logging

logger = logging.getLogger("network-ids.ml-inference")

# ── Paths ────────────────────────────────────────────────────────────────────
ML_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(ML_DIR, "model.pkl")
ENSEMBLE_LOF_PATH = os.path.join(ML_DIR, "ensemble_lof.pkl")
SCALER_PATH = os.path.join(ML_DIR, "scaler.pkl")

# ── Protocol encoding (must match training) ──────────────────────────────────
PROTOCOL_MAP = {"TCP": 0, "UDP": 1, "ICMP": 2}

# ── Global instances ─────────────────────────────────────────────────────────
_if_model = None
_lof_model = None
_scaler = None
_ensemble_available = False

# Ensemble weights (must match training pipeline)
IF_WEIGHT = 0.65
LOF_WEIGHT = 0.35
ENSEMBLE_THRESHOLD = 0.45


def load_model():
    """Load the trained models and scaler from disk."""
    global _if_model, _lof_model, _scaler, _ensemble_available

    if os.path.exists(MODEL_PATH):
        _if_model = joblib.load(MODEL_PATH)
        logger.info(f"Isolation Forest model loaded from {MODEL_PATH}")
    else:
        logger.warning(f"IF model not found at {MODEL_PATH}. ML IDS will be disabled.")
        _if_model = None

    if os.path.exists(ENSEMBLE_LOF_PATH):
        _lof_model = joblib.load(ENSEMBLE_LOF_PATH)
        _ensemble_available = True
        logger.info(f"LOF ensemble model loaded from {ENSEMBLE_LOF_PATH}")
    else:
        logger.info("LOF ensemble model not found — using IF-only mode.")
        _lof_model = None
        _ensemble_available = False

    if os.path.exists(SCALER_PATH):
        _scaler = joblib.load(SCALER_PATH)
        logger.info(f"Scaler loaded from {SCALER_PATH}")
    else:
        logger.warning(f"Scaler not found at {SCALER_PATH}. Features will not be scaled.")
        _scaler = None


def prepare_features(traffic: dict) -> np.ndarray:
    """Convert traffic record to feature vector matching training format.
    Must produce the same 10 features in the same order as training:
    [packet_rate, unique_ports, avg_packet_size, duration, protocol_flag, connection_count,
     bytes_per_second, port_scan_ratio, size_rate_ratio, conn_rate]
    """
    protocol_flag = PROTOCOL_MAP.get(traffic.get("protocol", "").upper(), 3)

    packet_rate = float(traffic["packet_rate"])
    unique_ports = float(traffic["unique_ports"])
    avg_packet_size = float(traffic["avg_packet_size"])
    duration = float(traffic["duration"])
    connection_count = float(traffic.get("connection_count", 1))

    # Derived features (must match add_derived_features in train_model.py)
    bytes_per_second = packet_rate * avg_packet_size
    port_scan_ratio = unique_ports / max(duration, 0.1)
    size_rate_ratio = avg_packet_size / max(packet_rate, 0.1)
    conn_rate = connection_count / max(duration, 0.1)

    features = np.array([
        packet_rate,
        unique_ports,
        avg_packet_size,
        duration,
        protocol_flag,
        connection_count,
        bytes_per_second,
        port_scan_ratio,
        size_rate_ratio,
        conn_rate,
    ]).reshape(1, -1)
    return features


def predict(traffic: dict) -> dict:
    """
    Run anomaly detection on a traffic record using ensemble (IF+LOF) or IF-only.

    Returns:
        dict with: anomaly (bool), score (float), confidence (float), status (str), model_used (str)
    """
    global _if_model, _lof_model, _scaler, _ensemble_available

    if _if_model is None:
        load_model()

    if _if_model is None:
        return {
            "anomaly": False,
            "score": 0.0,
            "confidence": 0.0,
            "status": "model_unavailable",
            "model_used": "none",
        }

    features = prepare_features(traffic)

    # Apply scaler if available (matches training pipeline)
    if _scaler is not None:
        features = _scaler.transform(features)

    # Isolation Forest prediction
    if_prediction = _if_model.predict(features)[0]
    anomaly_score = _if_model.decision_function(features)[0]

    # Ensemble voting if LOF available
    if _ensemble_available and _lof_model is not None:
        lof_prediction = _lof_model.predict(features)[0]

        if_anomaly = 1.0 if if_prediction == -1 else 0.0
        lof_anomaly = 1.0 if lof_prediction == -1 else 0.0

        combined_score = if_anomaly * IF_WEIGHT + lof_anomaly * LOF_WEIGHT
        is_anomaly = combined_score >= ENSEMBLE_THRESHOLD
        model_used = "ensemble_if_lof"
    else:
        is_anomaly = if_prediction == -1
        model_used = "isolation_forest"

    # Calibrated confidence based on anomaly score distribution
    if is_anomaly:
        confidence = min(1.0, max(0.3, 0.5 + abs(anomaly_score) * 2.0))
    else:
        confidence = min(1.0, max(0.0, anomaly_score * 1.5))

    return {
        "anomaly": bool(is_anomaly),
        "score": round(float(anomaly_score), 4),
        "confidence": round(float(confidence), 4),
        "status": "anomaly_detected" if is_anomaly else "normal",
        "model_used": model_used,
    }
