"""
Generate training data for the Isolation Forest model.
Creates a large, realistic dataset with diverse traffic profiles.

Normal traffic:  5000 rows — varied but within safe ranges.
Attack traffic:  1500 rows — 6 distinct attack subtypes for validation.
"""

import pandas as pd
import numpy as np
import os

np.random.seed(42)

# ── Helpers ──────────────────────────────────────────────────────────────────

NORMAL_SUBNETS = ["192.168.1", "192.168.2", "192.168.10", "10.0.1", "10.0.2"]
ATTACK_SUBNETS = ["10.10.10", "172.16.0", "203.0.113", "198.51.100", "45.33.32"]
DST_SUBNETS = ["192.168.1", "10.0.0", "172.16.1"]


def random_ips(subnets: list, n: int) -> list:
    return [f"{np.random.choice(subnets)}.{np.random.randint(1, 254)}" for _ in range(n)]


# ═══════════════════════════════════════════════════════════════════════════
#   NORMAL TRAFFIC — 5000 rows
# ═══════════════════════════════════════════════════════════════════════════

n_normal = 5000

# Create diverse normal traffic profiles
# Profile 1: Web browsing (60%) — moderate rate, few ports, TCP dominant
n_web = int(n_normal * 0.60)
web_traffic = {
    "src_ip": random_ips(NORMAL_SUBNETS, n_web),
    "dst_ip": random_ips(DST_SUBNETS, n_web),
    "packet_rate": np.random.lognormal(mean=4.5, sigma=0.7, size=n_web).clip(20, 600).round(1),
    "unique_ports": np.random.randint(1, 8, n_web),
    "avg_packet_size": np.random.normal(loc=800, scale=300, size=n_web).clip(200, 1500).round(1),
    "protocol": np.random.choice(["TCP", "UDP", "ICMP"], n_web, p=[0.75, 0.20, 0.05]),
    "duration": np.random.exponential(scale=15, size=n_web).clip(1, 120).round(1),
}

# Profile 2: Streaming / file transfer (20%) — steady high rate, few ports, large packets
n_stream = int(n_normal * 0.20)
stream_traffic = {
    "src_ip": random_ips(NORMAL_SUBNETS, n_stream),
    "dst_ip": random_ips(DST_SUBNETS, n_stream),
    "packet_rate": np.random.normal(loc=400, scale=80, size=n_stream).clip(200, 700).round(1),
    "unique_ports": np.random.randint(1, 4, n_stream),
    "avg_packet_size": np.random.normal(loc=1200, scale=200, size=n_stream).clip(800, 1500).round(1),
    "protocol": np.random.choice(["TCP", "UDP"], n_stream, p=[0.6, 0.4]),
    "duration": np.random.normal(loc=45, scale=15, size=n_stream).clip(10, 120).round(1),
}

# Profile 3: DNS / small queries (15%) — low rate, 1-2 ports, small packets, UDP
n_dns = int(n_normal * 0.15)
dns_traffic = {
    "src_ip": random_ips(NORMAL_SUBNETS, n_dns),
    "dst_ip": random_ips(DST_SUBNETS, n_dns),
    "packet_rate": np.random.uniform(10, 150, n_dns).round(1),
    "unique_ports": np.random.randint(1, 3, n_dns),
    "avg_packet_size": np.random.normal(loc=250, scale=80, size=n_dns).clip(64, 512).round(1),
    "protocol": np.random.choice(["UDP", "TCP"], n_dns, p=[0.85, 0.15]),
    "duration": np.random.uniform(0.5, 10, n_dns).round(1),
}

# Profile 4: ICMP / ping (5%) — low rate, 1 port, fixed size
n_icmp = n_normal - n_web - n_stream - n_dns
icmp_traffic = {
    "src_ip": random_ips(NORMAL_SUBNETS, n_icmp),
    "dst_ip": random_ips(DST_SUBNETS, n_icmp),
    "packet_rate": np.random.uniform(5, 50, n_icmp).round(1),
    "unique_ports": np.ones(n_icmp, dtype=int),
    "avg_packet_size": np.random.normal(loc=64, scale=10, size=n_icmp).clip(32, 128).round(1),
    "protocol": np.full(n_icmp, "ICMP"),
    "duration": np.random.uniform(1, 30, n_icmp).round(1),
}

normal_df = pd.concat([
    pd.DataFrame(web_traffic),
    pd.DataFrame(stream_traffic),
    pd.DataFrame(dns_traffic),
    pd.DataFrame(icmp_traffic),
], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)


# ═══════════════════════════════════════════════════════════════════════════
#   ATTACK TRAFFIC — 1500 rows  (6 attack subtypes × 250 each)
# ═══════════════════════════════════════════════════════════════════════════

# Attack 1: Port Scan — high unique_ports, moderate rate, small packets
n_ps = 250
port_scan = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_ps),
    "dst_ip": random_ips(DST_SUBNETS, n_ps),
    "packet_rate": np.random.uniform(150, 900, n_ps).round(1),
    "unique_ports": np.random.randint(18, 500, n_ps),
    "avg_packet_size": np.random.uniform(40, 120, n_ps).round(1),
    "protocol": np.random.choice(["TCP", "UDP"], n_ps, p=[0.85, 0.15]),
    "duration": np.random.uniform(0.5, 15, n_ps).round(1),
}

# Attack 2: SYN Flood — very high rate, TCP, tiny packets, short duration
n_syn = 250
syn_flood = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_syn),
    "dst_ip": random_ips(DST_SUBNETS, n_syn),
    "packet_rate": np.random.uniform(2000, 10000, n_syn).round(1),
    "unique_ports": np.random.randint(1, 3, n_syn),
    "avg_packet_size": np.random.uniform(40, 80, n_syn).round(1),
    "protocol": np.full(n_syn, "TCP"),
    "duration": np.random.uniform(0.5, 10, n_syn).round(1),
}

# Attack 3: UDP Flood — high rate, UDP, small packets
n_udp = 250
udp_flood = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_udp),
    "dst_ip": random_ips(DST_SUBNETS, n_udp),
    "packet_rate": np.random.uniform(1500, 8000, n_udp).round(1),
    "unique_ports": np.random.randint(1, 5, n_udp),
    "avg_packet_size": np.random.uniform(20, 100, n_udp).round(1),
    "protocol": np.full(n_udp, "UDP"),
    "duration": np.random.uniform(1, 30, n_udp).round(1),
}

# Attack 4: Slowloris — low rate, TCP, very long duration, few ports
n_slow = 250
slowloris = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_slow),
    "dst_ip": random_ips(DST_SUBNETS, n_slow),
    "packet_rate": np.random.uniform(5, 30, n_slow).round(1),
    "unique_ports": np.random.randint(1, 3, n_slow),
    "avg_packet_size": np.random.uniform(20, 60, n_slow).round(1),
    "protocol": np.full(n_slow, "TCP"),
    "duration": np.random.uniform(120, 600, n_slow).round(1),
}

# Attack 5: DNS Amplification — high rate, UDP, large response packets
n_dns_amp = 250
dns_amp = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_dns_amp),
    "dst_ip": random_ips(DST_SUBNETS, n_dns_amp),
    "packet_rate": np.random.uniform(1000, 5000, n_dns_amp).round(1),
    "unique_ports": np.random.randint(1, 3, n_dns_amp),
    "avg_packet_size": np.random.uniform(1200, 4000, n_dns_amp).round(1),
    "protocol": np.full(n_dns_amp, "UDP"),
    "duration": np.random.uniform(2, 60, n_dns_amp).round(1),
}

# Attack 6: Protocol Anomaly — unusual protocols, varied patterns
n_proto = 250
protocol_anomaly = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_proto),
    "dst_ip": random_ips(DST_SUBNETS, n_proto),
    "packet_rate": np.random.uniform(50, 3000, n_proto).round(1),
    "unique_ports": np.random.randint(3, 150, n_proto),
    "avg_packet_size": np.random.uniform(40, 500, n_proto).round(1),
    "protocol": np.random.choice(["GRE", "ESP", "AH", "SCTP", "IGMP", "PIM"], n_proto),
    "duration": np.random.uniform(0.5, 30, n_proto).round(1),
}

attack_df = pd.concat([
    pd.DataFrame(port_scan).assign(attack_type="port_scan"),
    pd.DataFrame(syn_flood).assign(attack_type="syn_flood"),
    pd.DataFrame(udp_flood).assign(attack_type="udp_flood"),
    pd.DataFrame(slowloris).assign(attack_type="slowloris"),
    pd.DataFrame(dns_amp).assign(attack_type="dns_amplification"),
    pd.DataFrame(protocol_anomaly).assign(attack_type="protocol_anomaly"),
], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)


# ═══════════════════════════════════════════════════════════════════════════
#   SAVE CSVs
# ═══════════════════════════════════════════════════════════════════════════

data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
os.makedirs(data_dir, exist_ok=True)

normal_path = os.path.join(data_dir, "normal_traffic.csv")
attack_path = os.path.join(data_dir, "attack_traffic.csv")

normal_df.to_csv(normal_path, index=False)
attack_df.to_csv(attack_path, index=False)

print(f"{'=' * 60}")
print(f"  Data Generation Complete")
print(f"{'=' * 60}")
print(f"\n  Normal traffic: {len(normal_df):,} rows -> {normal_path}")
print(f"  Attack traffic: {len(attack_df):,} rows -> {attack_path}")
print(f"\n  Normal profiles: Web browsing, Streaming, DNS, ICMP")
print(f"  Attack types:    Port Scan, SYN Flood, UDP Flood,")
print(f"                   Slowloris, DNS Amplification, Protocol Anomaly")
print(f"\n  Normal sample:\n{normal_df.head(3).to_string()}")
print(f"\n  Attack sample:\n{attack_df.head(3).to_string()}")
print(f"\n  Attack type distribution:")
print(f"  {attack_df['attack_type'].value_counts().to_dict()}")
