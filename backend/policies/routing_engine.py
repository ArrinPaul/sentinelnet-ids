"""
Routing Policy Engine
Generates OSPF routing recommendations based on alert severity.
"""

import logging
from datetime import datetime

logger = logging.getLogger("network-ids.routing-engine")


def generate_routing_policy(alert: dict) -> dict:
    """
    Generate Cisco IOS-compatible OSPF routing recommendations.

    Severity-based routing:
        CRITICAL → Increase OSPF cost to 1000, reroute via backup
        HIGH     → Increase OSPF cost to 500, suggest backup path
        MEDIUM   → No routing change, monitor only

    Args:
        alert: Fusion engine alert with severity and source info

    Returns:
        Routing policy dict with commands and recommendations
    """
    severity = alert.get("severity", "MEDIUM")
    src_ip = alert.get("src_ip", "0.0.0.0")
    attack_type = alert.get("attack_type", "Unknown")

    commands = []
    recommendation = ""

    if severity == "CRITICAL":
        commands = [
            "! CRITICAL: Reroute traffic away from compromised path",
            "interface GigabitEthernet0/0",
            "ip ospf cost 1000",
            "!",
            "! Enable backup path with lower cost",
            "interface GigabitEthernet0/1",
            "ip ospf cost 10",
            "!",
            "! Redistribute with route-map to filter",
            "router ospf 1",
            f"distribute-list prefix BLOCK_{src_ip.replace('.', '_')} in",
        ]
        recommendation = (
            f"IMMEDIATE ACTION: Increase OSPF cost on primary interface to 1000. "
            f"Traffic from {src_ip} will be rerouted via backup path (GigabitEthernet0/1). "
            f"Consider complete interface shutdown if attack persists."
        )

    elif severity == "HIGH":
        commands = [
            "! HIGH: Increase cost on affected interface",
            "interface GigabitEthernet0/0",
            "ip ospf cost 500",
            "!",
            "! Monitor with OSPF debug",
            "debug ip ospf events",
        ]
        recommendation = (
            f"Increase OSPF cost on affected interface to 500. "
            f"Monitor traffic redistribution. "
            f"Backup path available via GigabitEthernet0/1."
        )

    elif severity == "MEDIUM":
        commands = [
            "! MEDIUM: No routing change — monitor only",
            "! Consider enabling OSPF logging",
            "router ospf 1",
            "log-adjacency-changes detail",
        ]
        recommendation = (
            f"No routing changes required. Continue monitoring traffic from {src_ip}. "
            f"Enable detailed OSPF logging for audit trail."
        )

    else:
        commands = ["! No routing action required"]
        recommendation = "No routing changes needed."

    routing_policy = {
        "severity": severity,
        "target_ip": src_ip,
        "attack_type": attack_type,
        "commands": commands,
        "recommendation": recommendation,
        "ospf_cost_change": 1000 if severity == "CRITICAL" else (500 if severity == "HIGH" else 0),
        "reroute_required": severity in ("CRITICAL", "HIGH"),
        "generated_at": datetime.now().isoformat(),
    }

    logger.info(f"Routing policy generated: cost_change={routing_policy['ospf_cost_change']} for {src_ip}")
    return routing_policy


def format_routing_text(routing_policy: dict) -> str:
    """Format routing policy as Cisco IOS configuration text."""
    lines = [
        f"! Routing Policy — Severity: {routing_policy['severity']}",
        f"! Target: {routing_policy['target_ip']}",
        f"! Attack: {routing_policy['attack_type']}",
        f"! Generated: {routing_policy['generated_at']}",
        "!",
    ]
    lines.extend(routing_policy["commands"])
    return "\n".join(lines)
