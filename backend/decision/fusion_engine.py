"""
Decision Fusion Engine
Combines rule-based IDS and ML-based anomaly detection outputs
into a single unified security decision.
"""

import logging
from datetime import datetime

logger = logging.getLogger("network-ids.fusion")


def fuse(rule_result: dict, ml_result: dict, traffic: dict) -> dict:
    """
    Combine rule-based and ML-based detection results into a unified decision.

    Severity Mapping:
        Rule HIGH + ML Anomaly → CRITICAL
        Rule MEDIUM + ML Anomaly → HIGH
        ML Anomaly only → MEDIUM
        Rule alert only → MEDIUM
        Neither → SAFE

    Args:
        rule_result: Output from rule_ids.analyze()
        ml_result: Output from ml_ids.analyze()
        traffic: Original traffic record

    Returns:
        Unified fusion decision dict
    """
    rule_alert = rule_result.get("alert", False)
    rule_severity = rule_result.get("severity")
    rule_type = rule_result.get("type")

    ml_anomaly = ml_result.get("anomaly", False)
    ml_confidence = ml_result.get("confidence", 0.0)

    # ── Determine intrusion status and severity ─────────────────────────────
    intrusion_detected = rule_alert or ml_anomaly

    if not intrusion_detected:
        return {
            "intrusion_detected": False,
            "severity": "SAFE",
            "attack_type": None,
            "confidence": 0.0,
            "recommended_action": "No action required",
            "rule_triggered": False,
            "ml_triggered": False,
        }

    # Both systems triggered
    if rule_alert and ml_anomaly:
        if rule_severity == "HIGH":
            severity = "CRITICAL"
            confidence = min(1.0, 0.8 + ml_confidence * 0.2)
        else:
            severity = "HIGH"
            confidence = min(1.0, 0.6 + ml_confidence * 0.3)
        attack_type = rule_type or "Combined Anomaly"

    # Only ML triggered
    elif ml_anomaly and not rule_alert:
        severity = "MEDIUM"
        confidence = ml_confidence
        attack_type = "ML-Detected Anomaly"

    # Only rule triggered
    elif rule_alert and not ml_anomaly:
        severity = "MEDIUM"
        confidence = 0.7 if rule_severity == "HIGH" else 0.5
        attack_type = rule_type or "Rule Violation"

    else:
        severity = "LOW"
        confidence = 0.3
        attack_type = "Unknown"

    # ── Determine recommended action ────────────────────────────────────────
    action_map = {
        "CRITICAL": "BLOCK source IP immediately. Reroute traffic via backup path.",
        "HIGH": "Block specific ports. Increase monitoring. Consider rerouting.",
        "MEDIUM": "Log and monitor. Alert administrator.",
        "LOW": "Log for review.",
    }

    logger.warning(
        f"Fusion decision: {severity} — {attack_type} | "
        f"Rule={rule_alert} ML={ml_anomaly} Confidence={confidence:.2f}"
    )

    return {
        "intrusion_detected": True,
        "severity": severity,
        "attack_type": attack_type,
        "confidence": round(confidence, 4),
        "recommended_action": action_map.get(severity, "Monitor"),
        "rule_triggered": rule_alert,
        "ml_triggered": ml_anomaly,
        "rule_detail": rule_result if rule_alert else None,
        "ml_detail": {
            "score": ml_result.get("score"),
            "confidence": ml_result.get("confidence"),
        } if ml_anomaly else None,
    }
