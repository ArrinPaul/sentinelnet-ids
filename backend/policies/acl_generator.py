"""
ACL Policy Generator
Generates Cisco IOS-compatible Access Control List rules based on alert severity.
"""

import logging
from datetime import datetime

logger = logging.getLogger("network-ids.acl-generator")


def generate_acl(alert: dict) -> dict:
    """
    Generate Cisco-compatible ACL rules based on intrusion alert.

    Severity-based policy:
        CRITICAL → deny ip host {src_ip} any (full block)
        HIGH     → deny tcp host {src_ip} any eq {port} (port-specific block)
        MEDIUM   → permit ip host {src_ip} any log (allow but log)

    Args:
        alert: Fusion engine alert with severity, src_ip, attack_type

    Returns:
        ACL policy dict with rules and metadata
    """
    src_ip = alert.get("src_ip", "0.0.0.0")
    severity = alert.get("severity", "MEDIUM")
    attack_type = alert.get("attack_type", "Unknown")

    rules = []
    acl_number = 100  # Extended ACL

    if severity == "CRITICAL":
        # Full IP block
        rules.append({
            "rule_number": 10,
            "action": "deny",
            "command": f"access-list {acl_number} deny ip host {src_ip} any",
            "description": f"Block all traffic from {src_ip} — {attack_type}",
        })
        rules.append({
            "rule_number": 20,
            "action": "deny",
            "command": f"access-list {acl_number} deny icmp host {src_ip} any",
            "description": f"Block ICMP from {src_ip}",
        })

    elif severity == "HIGH":
        # Port-specific block
        rules.append({
            "rule_number": 10,
            "action": "deny",
            "command": f"access-list {acl_number} deny tcp host {src_ip} any",
            "description": f"Block TCP from {src_ip} — {attack_type}",
        })
        rules.append({
            "rule_number": 20,
            "action": "deny",
            "command": f"access-list {acl_number} deny udp host {src_ip} any",
            "description": f"Block UDP from {src_ip}",
        })

    elif severity == "MEDIUM":
        # Allow but log for monitoring
        rules.append({
            "rule_number": 10,
            "action": "permit",
            "command": f"access-list {acl_number} permit ip host {src_ip} any log",
            "description": f"Permit with logging from {src_ip} — {attack_type}",
        })

    # Always add implicit permit at end
    rules.append({
        "rule_number": 999,
        "action": "permit",
        "command": f"access-list {acl_number} permit ip any any",
        "description": "Implicit permit all other traffic",
    })

    # Interface application commands
    interface_commands = [
        "interface GigabitEthernet0/0",
        f"ip access-group {acl_number} in",
    ]

    acl_policy = {
        "acl_number": acl_number,
        "severity": severity,
        "target_ip": src_ip,
        "attack_type": attack_type,
        "rules": rules,
        "commands": [r["command"] for r in rules],
        "interface_commands": interface_commands,
        "generated_at": datetime.now().isoformat(),
    }

    logger.info(f"ACL generated: {len(rules)} rules for {src_ip} (severity={severity})")
    return acl_policy


def format_acl_text(acl_policy: dict) -> str:
    """Format ACL policy as Cisco IOS configuration text."""
    lines = [
        f"! ACL Policy — Severity: {acl_policy['severity']}",
        f"! Target: {acl_policy['target_ip']}",
        f"! Attack: {acl_policy['attack_type']}",
        f"! Generated: {acl_policy['generated_at']}",
        "!",
    ]
    for rule in acl_policy["rules"]:
        lines.append(f"{rule['command']}    ! {rule['description']}")

    lines.append("!")
    for cmd in acl_policy["interface_commands"]:
        lines.append(cmd)

    return "\n".join(lines)
