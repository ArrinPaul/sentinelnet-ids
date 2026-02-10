"""
Rule-Based Intrusion Detection System
Detects known attack patterns using deterministic threshold rules.
"""

import logging

logger = logging.getLogger("network-ids.rule-ids")

# ── Configurable Thresholds ─────────────────────────────────────────────────
PORT_SCAN_THRESHOLD = 15       # unique ports accessed
FLOOD_THRESHOLD = 1000         # packets per second
SMALL_PACKET_THRESHOLD = 100   # avg packet size (bytes) — flood signature
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}


# ── Detection Functions ─────────────────────────────────────────────────────

def detect_port_scan(traffic: dict) -> dict | None:
    """Detect port scanning behavior: many unique ports accessed."""
    if traffic["unique_ports"] > PORT_SCAN_THRESHOLD:
        severity = "HIGH" if traffic["unique_ports"] > 50 else "MEDIUM"
        return {
            "alert": True,
            "type": "Port Scan",
            "severity": severity,
            "reason": f"Unique ports ({traffic['unique_ports']}) exceeds threshold ({PORT_SCAN_THRESHOLD})",
        }
    return None


def detect_flood(traffic: dict) -> dict | None:
    """Detect flooding/DoS: high packet rate with small packet sizes."""
    if traffic["packet_rate"] > FLOOD_THRESHOLD:
        # Classic flood: high rate + small packets
        if traffic["avg_packet_size"] < SMALL_PACKET_THRESHOLD:
            return {
                "alert": True,
                "type": "Flood Attack (DoS)",
                "severity": "HIGH",
                "reason": (
                    f"Packet rate ({traffic['packet_rate']}) exceeds threshold ({FLOOD_THRESHOLD}) "
                    f"with small avg packet size ({traffic['avg_packet_size']}B)"
                ),
            }
        # High rate but normal packet sizes — still suspicious
        return {
            "alert": True,
            "type": "High Traffic Rate",
            "severity": "MEDIUM",
            "reason": f"Packet rate ({traffic['packet_rate']}) exceeds threshold ({FLOOD_THRESHOLD})",
        }
    return None


def detect_protocol_anomaly(traffic: dict) -> dict | None:
    """Detect usage of non-standard/unexpected protocols."""
    protocol = traffic["protocol"].upper()
    if protocol not in VALID_PROTOCOLS:
        return {
            "alert": True,
            "type": "Protocol Anomaly",
            "severity": "MEDIUM",
            "reason": f"Non-standard protocol detected: {protocol} (expected: {VALID_PROTOCOLS})",
        }
    return None


# ── Combined Analysis ────────────────────────────────────────────────────────

def analyze(traffic: dict) -> dict:
    """
    Run all rule-based detection checks on a traffic record.
    Returns the highest-severity alert found, or a safe result.
    """
    checks = [
        detect_port_scan(traffic),
        detect_flood(traffic),
        detect_protocol_anomaly(traffic),
    ]

    # Filter out None results
    alerts = [c for c in checks if c is not None]

    if not alerts:
        return {
            "alert": False,
            "type": None,
            "severity": None,
            "reason": "No rule-based threats detected",
        }

    # Return highest severity alert
    severity_order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    alerts.sort(key=lambda a: severity_order.get(a["severity"], 0), reverse=True)

    top_alert = alerts[0]
    logger.info(f"Rule IDS alert: {top_alert['type']} ({top_alert['severity']}) from {traffic.get('src_ip', 'unknown')}")
    return top_alert
