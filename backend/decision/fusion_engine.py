"""
Decision Fusion Engine
Combines rule-based IDS and ML-based anomaly detection outputs
into a single unified security decision.

Features: weighted scoring, alert deduplication, historical tracking.
"""

import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger("network-ids.fusion")

# ── Configurable Weights ────────────────────────────────────────────────────
FUSION_WEIGHTS = {
    "rule_weight": 0.5,
    "ml_weight": 0.5,
}

# ── Alert Deduplication ─────────────────────────────────────────────────────
# Track recent alerts per IP to prevent alert flooding
_recent_alerts: dict[str, list[dict]] = defaultdict(list)
DEDUP_WINDOW_SEC = 10  # suppress duplicate alerts within this window


def _is_duplicate_alert(src_ip: str, attack_type: str) -> bool:
    """Check if a similar alert was raised recently for this IP."""
    now = datetime.now()
    recent = _recent_alerts.get(src_ip, [])
    # Clean old entries
    recent = [a for a in recent if (now - a["time"]).total_seconds() < DEDUP_WINDOW_SEC]
    _recent_alerts[src_ip] = recent

    for a in recent:
        if a["attack_type"] == attack_type:
            return True
    return False


def _record_alert(src_ip: str, attack_type: str):
    """Record that an alert was raised for dedup tracking."""
    _recent_alerts[src_ip].append({
        "attack_type": attack_type,
        "time": datetime.now(),
    })


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
    all_rules = rule_result.get("all_rules_triggered", [])

    ml_anomaly = ml_result.get("anomaly", False)
    ml_confidence = ml_result.get("confidence", 0.0)

    src_ip = traffic.get("src_ip", "unknown")

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
            "rules_matched": 0,
        }

    # Both systems triggered
    if rule_alert and ml_anomaly:
        if rule_severity == "HIGH":
            severity = "CRITICAL"
            confidence = min(1.0, FUSION_WEIGHTS["rule_weight"] * 0.9 + FUSION_WEIGHTS["ml_weight"] * ml_confidence)
        else:
            severity = "HIGH"
            confidence = min(1.0, FUSION_WEIGHTS["rule_weight"] * 0.7 + FUSION_WEIGHTS["ml_weight"] * ml_confidence)
        attack_type = rule_type or "Combined Anomaly"

    # Only ML triggered
    elif ml_anomaly and not rule_alert:
        severity = "MEDIUM"
        confidence = ml_confidence * FUSION_WEIGHTS["ml_weight"]
        attack_type = "ML-Detected Anomaly"

    # Only rule triggered
    elif rule_alert and not ml_anomaly:
        severity = rule_severity if rule_severity == "HIGH" else "MEDIUM"
        confidence = (0.7 if rule_severity == "HIGH" else 0.5) * FUSION_WEIGHTS["rule_weight"]
        attack_type = rule_type or "Rule Violation"

    else:
        severity = "LOW"
        confidence = 0.3
        attack_type = "Unknown"

    # ── Alert Deduplication ─────────────────────────────────────────────────
    is_dup = _is_duplicate_alert(src_ip, attack_type)
    if is_dup:
        # Still return the decision, but mark as duplicate
        return {
            "intrusion_detected": True,
            "severity": severity,
            "attack_type": attack_type,
            "confidence": round(confidence, 4),
            "recommended_action": "Duplicate alert — already actioned",
            "rule_triggered": rule_alert,
            "ml_triggered": ml_anomaly,
            "duplicate": True,
            "rules_matched": len(all_rules),
        }

    _record_alert(src_ip, attack_type)

    # ── Determine recommended action ────────────────────────────────────────
    action_map = {
        "CRITICAL": "BLOCK source IP immediately. Reroute traffic via backup path.",
        "HIGH": "Block specific ports. Increase monitoring. Consider rerouting.",
        "MEDIUM": "Log and monitor. Alert administrator.",
        "LOW": "Log for review.",
    }

    logger.warning(
        f"Fusion decision: {severity} — {attack_type} | "
        f"Rule={rule_alert} ML={ml_anomaly} Confidence={confidence:.2f} "
        f"Rules matched={len(all_rules)}"
    )

    return {
        "intrusion_detected": True,
        "severity": severity,
        "attack_type": attack_type,
        "confidence": round(confidence, 4),
        "recommended_action": action_map.get(severity, "Monitor"),
        "rule_triggered": rule_alert,
        "ml_triggered": ml_anomaly,
        "duplicate": False,
        "rules_matched": len(all_rules),
        "rule_detail": rule_result if rule_alert else None,
        "ml_detail": {
            "score": ml_result.get("score"),
            "confidence": ml_result.get("confidence"),
        } if ml_anomaly else None,
    }
