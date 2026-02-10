"""
Traffic Simulator
Generates synthetic traffic data for demo and testing purposes.
Supports 9 modes: normal, port_scan, flood, syn_flood, slowloris,
dns_amplification, anomaly, random, and mixed_attack.
"""

import random


def generate_normal_traffic() -> dict:
    """Generate a single normal traffic record."""
    return {
        "src_ip": f"192.168.{random.choice([1,2,10])}.{random.randint(1, 254)}",
        "dst_ip": f"10.0.{random.choice([0,1,2])}.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(20, 500), 1),
        "unique_ports": random.randint(1, 10),
        "avg_packet_size": round(random.uniform(200, 1500), 1),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "duration": round(random.uniform(1, 60), 1),
        "connection_count": random.randint(1, 12),
    }


def generate_port_scan() -> dict:
    """Generate port scan attack traffic."""
    return {
        "src_ip": f"10.10.10.{random.randint(1, 254)}",
        "dst_ip": f"192.168.1.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(150, 900), 1),
        "unique_ports": random.randint(20, 300),
        "avg_packet_size": round(random.uniform(40, 120), 1),
        "protocol": random.choice(["TCP", "UDP"]),
        "duration": round(random.uniform(0.5, 15), 1),
        "connection_count": random.randint(15, 150),
    }


def generate_flood() -> dict:
    """Generate generic flood/DoS attack traffic."""
    return {
        "src_ip": f"172.16.0.{random.randint(1, 254)}",
        "dst_ip": f"192.168.1.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(1500, 5000), 1),
        "unique_ports": random.randint(1, 5),
        "avg_packet_size": round(random.uniform(20, 80), 1),
        "protocol": random.choice(["TCP", "UDP", "ICMP"]),
        "duration": round(random.uniform(1, 30), 1),
        "connection_count": random.randint(30, 300),
    }


def generate_syn_flood() -> dict:
    """Generate SYN flood: very high rate, TCP, tiny packets, short burst."""
    return {
        "src_ip": f"45.33.{random.randint(1, 254)}.{random.randint(1, 254)}",
        "dst_ip": f"192.168.1.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(2500, 10000), 1),
        "unique_ports": random.randint(1, 3),
        "avg_packet_size": round(random.uniform(40, 75), 1),
        "protocol": "TCP",
        "duration": round(random.uniform(0.5, 10), 1),
        "connection_count": random.randint(80, 400),
    }


def generate_slowloris() -> dict:
    """Generate Slowloris: low rate, TCP, long duration, tiny packets."""
    return {
        "src_ip": f"198.51.{random.randint(1, 254)}.{random.randint(1, 254)}",
        "dst_ip": f"192.168.1.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(5, 25), 1),
        "unique_ports": random.randint(1, 2),
        "avg_packet_size": round(random.uniform(20, 55), 1),
        "protocol": "TCP",
        "duration": round(random.uniform(130, 600), 1),
        "connection_count": random.randint(40, 180),
    }


def generate_dns_amplification() -> dict:
    """Generate DNS amplification: high rate, UDP, large packets."""
    return {
        "src_ip": f"203.0.113.{random.randint(1, 254)}",
        "dst_ip": f"192.168.1.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(1000, 5000), 1),
        "unique_ports": random.randint(1, 2),
        "avg_packet_size": round(random.uniform(1200, 4000), 1),
        "protocol": "UDP",
        "duration": round(random.uniform(2, 60), 1),
        "connection_count": random.randint(5, 40),
    }


def generate_protocol_anomaly() -> dict:
    """Generate protocol anomaly traffic."""
    return {
        "src_ip": f"203.0.113.{random.randint(1, 254)}",
        "dst_ip": f"192.168.1.{random.randint(1, 254)}",
        "packet_rate": round(random.uniform(50, 3000), 1),
        "unique_ports": random.randint(3, 150),
        "avg_packet_size": round(random.uniform(40, 500), 1),
        "protocol": random.choice(["GRE", "ESP", "AH", "SCTP", "IGMP"]),
        "duration": round(random.uniform(0.5, 30), 1),
        "connection_count": random.randint(1, 25),
    }


def generate_traffic(mode: str = "random") -> dict:
    """
    Generate traffic based on mode.

    Modes:
        normal            — Safe traffic
        port_scan         — Port scanning attack
        flood             — Generic DoS/flooding
        syn_flood         — TCP SYN flood attack
        slowloris         — Slowloris resource exhaustion
        dns_amplification — DNS amplification attack
        anomaly           — Protocol anomaly
        random            — Random mix (65% normal, 35% attacks)
        mixed_attack      — Multi-vector attack (all attack types)
    """
    generators = {
        "normal": generate_normal_traffic,
        "port_scan": generate_port_scan,
        "flood": generate_flood,
        "syn_flood": generate_syn_flood,
        "slowloris": generate_slowloris,
        "dns_amplification": generate_dns_amplification,
        "anomaly": generate_protocol_anomaly,
    }

    if mode in generators:
        return generators[mode]()

    if mode == "mixed_attack":
        # Always generate an attack type (uniform random)
        attack_gen = random.choice([
            generate_port_scan,
            generate_flood,
            generate_syn_flood,
            generate_slowloris,
            generate_dns_amplification,
            generate_protocol_anomaly,
        ])
        return attack_gen()

    # Random mode: 65% normal, 35% attacks (distributed)
    roll = random.random()
    if roll < 0.65:
        return generate_normal_traffic()
    elif roll < 0.72:
        return generate_port_scan()
    elif roll < 0.79:
        return generate_flood()
    elif roll < 0.86:
        return generate_syn_flood()
    elif roll < 0.90:
        return generate_slowloris()
    elif roll < 0.95:
        return generate_dns_amplification()
    else:
        return generate_protocol_anomaly()
