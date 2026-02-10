"""
ML-Based IDS Wrapper
Bridges the ML inference module with the backend IDS pipeline.
"""

import logging
from ml.inference import predict, load_model

logger = logging.getLogger("network-ids.ml-ids")

# Load model on module import
load_model()


def analyze(traffic: dict) -> dict:
    """
    Run ML anomaly detection on a traffic record.
    Returns standardized result compatible with the fusion engine.
    """
    result = predict(traffic)

    return {
        "anomaly": result["anomaly"],
        "score": result["score"],
        "confidence": result["confidence"],
        "status": result["status"],
    }
