"""
Traffic Simulator
Generates synthetic traffic data for demo and testing purposes.
"""

import random


def generate_normal_traffic() -> dict:
    """Generate a single normal traffic record."""
    return {
        "src_ip": f"192.168.1.{random.randint(1, 254)}",
        "dst_ip": f"10.0.0.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(50, 500), 1),
        "unique_ports": random.randint(1, 10),
        "avg_packet_size": round(random.uniform(200, 1500), 1),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "duration": round(random.uniform(1, 60), 1),
    }


def generate_port_scan() -> dict:
    """Generate port scan attack traffic."""
    return {
        "src_ip": f"10.10.10.{random.randint(1, 254)}",
        "dst_ip": f"192.168.1.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(200, 800), 1),
        "unique_ports": random.randint(20, 200),
        "avg_packet_size": round(random.uniform(40, 100), 1),
        "protocol": random.choice(["TCP", "UDP"]),
        "duration": round(random.uniform(1, 10), 1),
    }


def generate_flood() -> dict:
    """Generate flood/DoS attack traffic."""
    return {
        "src_ip": f"172.16.0.{random.randint(1, 254)}",
        "dst_ip": f"192.168.1.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(1500, 5000), 1),
        "unique_ports": random.randint(1, 5),
        "avg_packet_size": round(random.uniform(20, 80), 1),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "duration": round(random.uniform(1, 30), 1),
    }


def generate_protocol_anomaly() -> dict:
    """Generate protocol anomaly traffic."""
    return {
        "src_ip": f"203.0.113.{random.randint(1, 254)}",
        "dst_ip": f"192.168.1.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(100, 2000), 1),
        "unique_ports": random.randint(5, 100),
        "avg_packet_size": round(random.uniform(50, 300), 1),
        "protocol": random.choice(["GRE", "ESP", "AH", "SCTP"]),
        "duration": round(random.uniform(0.5, 5), 1),
    }


def generate_traffic(mode: str = "random") -> dict:
    """
    Generate traffic based on mode.

    Modes:
        normal      — Safe traffic
        port_scan   — Port scanning attack
        flood       — DoS/flooding attack
        anomaly     — Protocol anomaly
        random      — Random mix (70% normal, 30% attack)
    """
    generators = {
        "normal": generate_normal_traffic,
        "port_scan": generate_port_scan,
        "flood": generate_flood,
        "anomaly": generate_protocol_anomaly,
    }

    if mode in generators:
        return generators[mode]()

    # Random mode: 70% normal, 10% each attack type
    roll = random.random()
    if roll < 0.70:
        return generate_normal_traffic()
    elif roll < 0.80:
        return generate_port_scan()
    elif roll < 0.90:
        return generate_flood()
    else:
        return generate_protocol_anomaly()
