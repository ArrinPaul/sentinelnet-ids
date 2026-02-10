"""
Rule-Based Intrusion Detection System
Detects known attack patterns using deterministic threshold rules.
Supports: Port Scan, Flood/DoS, SYN Flood, Protocol Anomaly,
          Slowloris, DNS Amplification.
"""

import logging
from datetime import datetime

logger = logging.getLogger("network-ids.rule-ids")

# ── Configurable Thresholds ─────────────────────────────────────────────────
# These can be updated at runtime via the /system/config endpoint.

THRESHOLDS = {
    "port_scan_ports": 15,            # unique ports accessed
    "port_scan_ports_critical": 50,   # unique ports for HIGH severity
    "flood_packet_rate": 1000,        # packets per second
    "flood_small_packet": 100,        # avg packet size (bytes)
    "syn_flood_rate": 2000,           # SYN flood rate threshold
    "syn_flood_packet_size": 80,      # max avg packet size for SYN flood
    "syn_flood_duration": 15,         # max duration for SYN flood pattern
    "slowloris_rate_max": 30,         # max packet rate for slowloris
    "slowloris_duration": 120,        # min duration for slowloris
    "slowloris_packet_size": 60,      # max avg packet size for slowloris
    "dns_amp_rate": 800,              # min rate for DNS amplification
    "dns_amp_packet_size": 1000,      # min avg packet size (amplified response)
}

VALID_PROTOCOLS = {"TCP", "UDP", "ICMP"}


def get_thresholds() -> dict:
    """Return current threshold configuration."""
    return THRESHOLDS.copy()


def update_thresholds(new_values: dict) -> dict:
    """Update thresholds with new values. Returns updated thresholds."""
    for key, value in new_values.items():
        if key in THRESHOLDS:
            THRESHOLDS[key] = value
    return THRESHOLDS.copy()


# ── Detection Functions ─────────────────────────────────────────────────────

def detect_port_scan(traffic: dict) -> dict | None:
    """Detect port scanning: many unique ports accessed."""
    if traffic["unique_ports"] > THRESHOLDS["port_scan_ports"]:
        severity = "HIGH" if traffic["unique_ports"] > THRESHOLDS["port_scan_ports_critical"] else "MEDIUM"
        return {
            "alert": True,
            "type": "Port Scan",
            "severity": severity,
            "reason": (
                f"Unique ports ({traffic['unique_ports']}) exceeds threshold "
                f"({THRESHOLDS['port_scan_ports']})"
            ),
        }
    return None


def detect_flood(traffic: dict) -> dict | None:
    """Detect flooding/DoS: high packet rate with small packet sizes."""
    if traffic["packet_rate"] > THRESHOLDS["flood_packet_rate"]:
        if traffic["avg_packet_size"] < THRESHOLDS["flood_small_packet"]:
            return {
                "alert": True,
                "type": "Flood Attack (DoS)",
                "severity": "HIGH",
                "reason": (
                    f"Packet rate ({traffic['packet_rate']}) exceeds threshold ({THRESHOLDS['flood_packet_rate']}) "
                    f"with small avg packet size ({traffic['avg_packet_size']}B)"
                ),
            }
        return {
            "alert": True,
            "type": "High Traffic Rate",
            "severity": "MEDIUM",
            "reason": f"Packet rate ({traffic['packet_rate']}) exceeds threshold ({THRESHOLDS['flood_packet_rate']})",
        }
    return None


def detect_syn_flood(traffic: dict) -> dict | None:
    """
    Detect SYN flood: very high packet rate + TCP + tiny packets + short duration.
    SYN packets are small (~40-80 bytes) and arrive in rapid bursts.
    """
    protocol = traffic.get("protocol", "").upper()
    if (
        protocol == "TCP"
        and traffic["packet_rate"] > THRESHOLDS["syn_flood_rate"]
        and traffic["avg_packet_size"] < THRESHOLDS["syn_flood_packet_size"]
        and traffic["duration"] < THRESHOLDS["syn_flood_duration"]
    ):
        return {
            "alert": True,
            "type": "SYN Flood",
            "severity": "HIGH",
            "reason": (
                f"SYN flood pattern: rate={traffic['packet_rate']}pps, "
                f"avg_size={traffic['avg_packet_size']}B, duration={traffic['duration']}s "
                f"(TCP, high rate, tiny packets, short burst)"
            ),
        }
    return None


def detect_slowloris(traffic: dict) -> dict | None:
    """
    Detect Slowloris attack: low rate + TCP + very long duration + tiny packets.
    Slowloris keeps connections alive slowly, exhausting server resources.
    """
    protocol = traffic.get("protocol", "").upper()
    if (
        protocol == "TCP"
        and traffic["packet_rate"] < THRESHOLDS["slowloris_rate_max"]
        and traffic["duration"] > THRESHOLDS["slowloris_duration"]
        and traffic["avg_packet_size"] < THRESHOLDS["slowloris_packet_size"]
    ):
        return {
            "alert": True,
            "type": "Slowloris Attack",
            "severity": "MEDIUM",
            "reason": (
                f"Slowloris pattern: rate={traffic['packet_rate']}pps, "
                f"duration={traffic['duration']}s, avg_size={traffic['avg_packet_size']}B "
                f"(low rate, long-lived, tiny packets — resource exhaustion)"
            ),
        }
    return None


def detect_dns_amplification(traffic: dict) -> dict | None:
    """
    Detect DNS amplification: high rate + UDP + abnormally large packets.
    Amplified DNS responses produce large UDP packets at high volume.
    """
    protocol = traffic.get("protocol", "").upper()
    if (
        protocol == "UDP"
        and traffic["packet_rate"] > THRESHOLDS["dns_amp_rate"]
        and traffic["avg_packet_size"] > THRESHOLDS["dns_amp_packet_size"]
    ):
        return {
            "alert": True,
            "type": "DNS Amplification",
            "severity": "HIGH",
            "reason": (
                f"DNS amplification pattern: rate={traffic['packet_rate']}pps, "
                f"avg_size={traffic['avg_packet_size']}B "
                f"(high-rate UDP with large response packets)"
            ),
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
        detect_syn_flood(traffic),      # check SYN flood before generic flood
        detect_flood(traffic),
        detect_slowloris(traffic),
        detect_dns_amplification(traffic),
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
    # Attach all triggered rules for transparency
    top_alert["all_rules_triggered"] = [
        {"type": a["type"], "severity": a["severity"]} for a in alerts
    ]

    logger.info(
        f"Rule IDS alert: {top_alert['type']} ({top_alert['severity']}) "
        f"from {traffic.get('src_ip', 'unknown')} — {len(alerts)} rule(s) triggered"
    )
    return top_alert
