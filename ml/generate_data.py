"""
Generate training data for the Isolation Forest IDS model.
Creates a large, realistic dataset with diverse traffic profiles,
borderline cases, and controlled noise to prevent overfitting.

Normal traffic:  20,000 rows — varied profiles with edge cases.
Attack traffic:   8,000 rows — 10 distinct attack subtypes.

Features per record:
  - src_ip, dst_ip (metadata only, not used in training)
  - packet_rate, unique_ports, avg_packet_size, duration, protocol (raw)
  - connection_count (helps distinguish brute force)
  - attack_type (label for attack rows only)
"""

import pandas as pd
import numpy as np
import os

np.random.seed(42)

# ── Helpers ──────────────────────────────────────────────────────────────────

NORMAL_SUBNETS = [
    "192.168.1", "192.168.2", "192.168.10", "192.168.50",
    "10.0.1", "10.0.2", "10.0.10", "10.1.0", "10.2.0",
]
ATTACK_SUBNETS = [
    "10.10.10", "172.16.0", "203.0.113", "198.51.100",
    "45.33.32", "45.33.144", "91.189.0", "104.16.0",
]
DST_SUBNETS = ["192.168.1", "10.0.0", "172.16.1", "10.0.1", "192.168.2"]


def random_ips(subnets: list, n: int) -> list:
    return [f"{np.random.choice(subnets)}.{np.random.randint(1, 254)}" for _ in range(n)]


# ═══════════════════════════════════════════════════════════════════════════
#   NORMAL TRAFFIC — 20,000 rows
# ═══════════════════════════════════════════════════════════════════════════

n_normal = 20000

# Profile 1: Web browsing (45%) — moderate rate, few ports, TCP dominant
n_web = int(n_normal * 0.45)
web_traffic = {
    "src_ip": random_ips(NORMAL_SUBNETS, n_web),
    "dst_ip": random_ips(DST_SUBNETS, n_web),
    "packet_rate": np.random.lognormal(mean=4.5, sigma=0.8, size=n_web).clip(10, 800).round(1),
    "unique_ports": np.random.randint(1, 10, n_web),
    "avg_packet_size": np.random.normal(loc=800, scale=350, size=n_web).clip(100, 1500).round(1),
    "protocol": np.random.choice(["TCP", "UDP", "ICMP"], n_web, p=[0.72, 0.22, 0.06]),
    "duration": np.random.exponential(scale=18, size=n_web).clip(0.5, 180).round(1),
    "connection_count": np.random.randint(1, 15, n_web),
}

# Profile 2: Streaming/file transfer (18%) — steady high rate, few ports, large packets
n_stream = int(n_normal * 0.18)
stream_traffic = {
    "src_ip": random_ips(NORMAL_SUBNETS, n_stream),
    "dst_ip": random_ips(DST_SUBNETS, n_stream),
    "packet_rate": np.random.normal(loc=450, scale=120, size=n_stream).clip(150, 900).round(1),
    "unique_ports": np.random.randint(1, 4, n_stream),
    "avg_packet_size": np.random.normal(loc=1200, scale=250, size=n_stream).clip(600, 1500).round(1),
    "protocol": np.random.choice(["TCP", "UDP"], n_stream, p=[0.55, 0.45]),
    "duration": np.random.normal(loc=60, scale=25, size=n_stream).clip(5, 300).round(1),
    "connection_count": np.random.randint(1, 5, n_stream),
}

# Profile 3: DNS / small queries (12%) — low rate, 1-2 ports, small packets, UDP
n_dns = int(n_normal * 0.12)
dns_traffic = {
    "src_ip": random_ips(NORMAL_SUBNETS, n_dns),
    "dst_ip": random_ips(DST_SUBNETS, n_dns),
    "packet_rate": np.random.uniform(5, 200, n_dns).round(1),
    "unique_ports": np.random.randint(1, 3, n_dns),
    "avg_packet_size": np.random.normal(loc=250, scale=100, size=n_dns).clip(40, 600).round(1),
    "protocol": np.random.choice(["UDP", "TCP"], n_dns, p=[0.82, 0.18]),
    "duration": np.random.uniform(0.3, 15, n_dns).round(1),
    "connection_count": np.random.randint(1, 8, n_dns),
}

# Profile 4: ICMP / ping (5%) — low rate, 1 port, fixed size
n_icmp = int(n_normal * 0.05)
icmp_traffic = {
    "src_ip": random_ips(NORMAL_SUBNETS, n_icmp),
    "dst_ip": random_ips(DST_SUBNETS, n_icmp),
    "packet_rate": np.random.uniform(3, 60, n_icmp).round(1),
    "unique_ports": np.ones(n_icmp, dtype=int),
    "avg_packet_size": np.random.normal(loc=64, scale=15, size=n_icmp).clip(28, 150).round(1),
    "protocol": np.full(n_icmp, "ICMP"),
    "duration": np.random.uniform(0.5, 40, n_icmp).round(1),
    "connection_count": np.random.randint(1, 3, n_icmp),
}

# Profile 5: *** BORDERLINE / EDGE CASES (10%) *** — legitimate traffic that LOOKS suspicious
# These prevent overfitting by teaching the model that high rates aren't always attacks
n_edge = int(n_normal * 0.10)
edge_cases = {
    "src_ip": random_ips(NORMAL_SUBNETS, n_edge),
    "dst_ip": random_ips(DST_SUBNETS, n_edge),
    "packet_rate": np.concatenate([
        np.random.uniform(800, 1800, n_edge // 3),       # high rate but legitimate (CDN/backup)
        np.random.uniform(50, 300, n_edge // 3),          # normal rate but many ports (microservices)
        np.random.uniform(100, 600, n_edge - 2 * (n_edge // 3)),  # long-lived connections (SSH/VPN)
    ]).round(1),
    "unique_ports": np.concatenate([
        np.random.randint(1, 4, n_edge // 3),             # few ports (CDN/backup)
        np.random.randint(8, 25, n_edge // 3),            # many ports (microservices)
        np.random.randint(1, 5, n_edge - 2 * (n_edge // 3)),  # few ports (SSH/VPN)
    ]),
    "avg_packet_size": np.random.normal(loc=700, scale=400, size=n_edge).clip(40, 1500).round(1),
    "protocol": np.random.choice(["TCP", "UDP"], n_edge, p=[0.7, 0.3]),
    "duration": np.concatenate([
        np.random.uniform(1, 20, n_edge // 3),            # short but fast
        np.random.uniform(5, 60, n_edge // 3),            # medium
        np.random.uniform(60, 300, n_edge - 2 * (n_edge // 3)),  # long-lived (SSH/VPN)
    ]).round(1),
    "connection_count": np.concatenate([
        np.random.randint(1, 8, n_edge // 3),
        np.random.randint(3, 20, n_edge // 3),            # microservices = more connections
        np.random.randint(1, 4, n_edge - 2 * (n_edge // 3)),
    ]),
}

# Profile 6: IoT / sensor traffic (5%) — periodic, predictable, low entropy
n_iot = int(n_normal * 0.05)
iot_traffic = {
    "src_ip": random_ips(["192.168.100", "10.0.100"], n_iot),
    "dst_ip": random_ips(DST_SUBNETS, n_iot),
    "packet_rate": np.random.uniform(1, 30, n_iot).round(1),
    "unique_ports": np.ones(n_iot, dtype=int),
    "avg_packet_size": np.random.normal(loc=128, scale=30, size=n_iot).clip(40, 256).round(1),
    "protocol": np.random.choice(["TCP", "UDP", "ICMP"], n_iot, p=[0.3, 0.6, 0.1]),
    "duration": np.random.uniform(1, 10, n_iot).round(1),
    "connection_count": np.ones(n_iot, dtype=int),
}

# Profile 7: Database/API backend (5%) — medium rate, stable, TCP heavy
n_db = n_normal - n_web - n_stream - n_dns - n_icmp - n_edge - n_iot
db_traffic = {
    "src_ip": random_ips(["10.0.50", "10.0.51"], n_db),
    "dst_ip": random_ips(["10.0.0", "192.168.1"], n_db),
    "packet_rate": np.random.normal(loc=300, scale=100, size=n_db).clip(50, 700).round(1),
    "unique_ports": np.random.randint(1, 6, n_db),
    "avg_packet_size": np.random.normal(loc=500, scale=200, size=n_db).clip(100, 1200).round(1),
    "protocol": np.full(n_db, "TCP"),
    "duration": np.random.exponential(scale=10, size=n_db).clip(0.5, 60).round(1),
    "connection_count": np.random.randint(2, 12, n_db),
}

normal_df = pd.concat([
    pd.DataFrame(web_traffic),
    pd.DataFrame(stream_traffic),
    pd.DataFrame(dns_traffic),
    pd.DataFrame(icmp_traffic),
    pd.DataFrame(edge_cases),
    pd.DataFrame(iot_traffic),
    pd.DataFrame(db_traffic),
], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)


# ═══════════════════════════════════════════════════════════════════════════
#   ATTACK TRAFFIC — 8,000 rows  (10 attack subtypes × 800 each)
# ═══════════════════════════════════════════════════════════════════════════

# Attack 1: Port Scan — high unique_ports, moderate rate, small packets
n_ps = 800
port_scan = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_ps),
    "dst_ip": random_ips(DST_SUBNETS, n_ps),
    "packet_rate": np.random.uniform(100, 1200, n_ps).round(1),
    "unique_ports": np.random.randint(15, 500, n_ps),
    "avg_packet_size": np.random.uniform(40, 150, n_ps).round(1),
    "protocol": np.random.choice(["TCP", "UDP"], n_ps, p=[0.85, 0.15]),
    "duration": np.random.uniform(0.3, 20, n_ps).round(1),
    "connection_count": np.random.randint(10, 200, n_ps),
}

# Attack 2: SYN Flood — very high rate, TCP, tiny packets, short duration
n_syn = 800
syn_flood = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_syn),
    "dst_ip": random_ips(DST_SUBNETS, n_syn),
    "packet_rate": np.random.uniform(1500, 15000, n_syn).round(1),
    "unique_ports": np.random.randint(1, 3, n_syn),
    "avg_packet_size": np.random.uniform(40, 80, n_syn).round(1),
    "protocol": np.full(n_syn, "TCP"),
    "duration": np.random.uniform(0.3, 15, n_syn).round(1),
    "connection_count": np.random.randint(50, 500, n_syn),
}

# Attack 3: UDP Flood — high rate, UDP, small packets
n_udp = 800
udp_flood = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_udp),
    "dst_ip": random_ips(DST_SUBNETS, n_udp),
    "packet_rate": np.random.uniform(1200, 10000, n_udp).round(1),
    "unique_ports": np.random.randint(1, 5, n_udp),
    "avg_packet_size": np.random.uniform(20, 120, n_udp).round(1),
    "protocol": np.full(n_udp, "UDP"),
    "duration": np.random.uniform(0.5, 35, n_udp).round(1),
    "connection_count": np.random.randint(20, 300, n_udp),
}

# Attack 4: Slowloris — low rate, TCP, very long duration, few ports
n_slow = 800
slowloris = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_slow),
    "dst_ip": random_ips(DST_SUBNETS, n_slow),
    "packet_rate": np.random.uniform(3, 40, n_slow).round(1),
    "unique_ports": np.random.randint(1, 3, n_slow),
    "avg_packet_size": np.random.uniform(15, 80, n_slow).round(1),
    "protocol": np.full(n_slow, "TCP"),
    "duration": np.random.uniform(100, 900, n_slow).round(1),
    "connection_count": np.random.randint(30, 200, n_slow),  # many half-open connections
}

# Attack 5: DNS Amplification — high rate, UDP, large response packets
n_dns_amp = 800
dns_amp = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_dns_amp),
    "dst_ip": random_ips(DST_SUBNETS, n_dns_amp),
    "packet_rate": np.random.uniform(800, 6000, n_dns_amp).round(1),
    "unique_ports": np.random.randint(1, 3, n_dns_amp),
    "avg_packet_size": np.random.uniform(1000, 4500, n_dns_amp).round(1),
    "protocol": np.full(n_dns_amp, "UDP"),
    "duration": np.random.uniform(1, 90, n_dns_amp).round(1),
    "connection_count": np.random.randint(5, 50, n_dns_amp),
}

# Attack 6: Protocol Anomaly — unusual protocols, varied patterns
n_proto = 800
protocol_anomaly = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_proto),
    "dst_ip": random_ips(DST_SUBNETS, n_proto),
    "packet_rate": np.random.uniform(30, 3500, n_proto).round(1),
    "unique_ports": np.random.randint(2, 200, n_proto),
    "avg_packet_size": np.random.uniform(40, 600, n_proto).round(1),
    "protocol": np.random.choice(["GRE", "ESP", "AH", "SCTP", "IGMP", "PIM"], n_proto),
    "duration": np.random.uniform(0.3, 40, n_proto).round(1),
    "connection_count": np.random.randint(1, 30, n_proto),
}

# Attack 7: Brute Force — moderate rate, SINGLE port, MANY connections, short bursts
# Key differentiator: very high connection_count with single port and short duration
n_brute = 800
brute_force = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_brute),
    "dst_ip": random_ips(DST_SUBNETS, n_brute),
    "packet_rate": np.random.uniform(80, 600, n_brute).round(1),
    "unique_ports": np.ones(n_brute, dtype=int),
    "avg_packet_size": np.random.uniform(60, 200, n_brute).round(1),
    "protocol": np.full(n_brute, "TCP"),
    "duration": np.random.uniform(0.2, 5, n_brute).round(1),
    "connection_count": np.random.randint(50, 500, n_brute),  # KEY: massive connection count
}

# Attack 8: ICMP Flood (Smurf) — high ICMP rate, fixed size, broadcast
n_icmp_atk = 800
icmp_flood = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_icmp_atk),
    "dst_ip": random_ips(DST_SUBNETS, n_icmp_atk),
    "packet_rate": np.random.uniform(2000, 12000, n_icmp_atk).round(1),
    "unique_ports": np.ones(n_icmp_atk, dtype=int),
    "avg_packet_size": np.random.normal(loc=64, scale=10, size=n_icmp_atk).clip(28, 128).round(1),
    "protocol": np.full(n_icmp_atk, "ICMP"),
    "duration": np.random.uniform(1, 30, n_icmp_atk).round(1),
    "connection_count": np.random.randint(10, 100, n_icmp_atk),
}

# Attack 9: HTTP Flood (Application layer) — high rate, TCP, large packets
n_http = 800
http_flood = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_http),
    "dst_ip": random_ips(DST_SUBNETS, n_http),
    "packet_rate": np.random.uniform(500, 5000, n_http).round(1),
    "unique_ports": np.random.randint(1, 8, n_http),
    "avg_packet_size": np.random.uniform(800, 1500, n_http).round(1),
    "protocol": np.full(n_http, "TCP"),
    "duration": np.random.uniform(2, 120, n_http).round(1),
    "connection_count": np.random.randint(20, 200, n_http),
}

# Attack 10: Stealthy probe — low & slow, evading rate-based detection
n_stealth = 800
stealth_probe = {
    "src_ip": random_ips(ATTACK_SUBNETS, n_stealth),
    "dst_ip": random_ips(DST_SUBNETS, n_stealth),
    "packet_rate": np.random.uniform(5, 80, n_stealth).round(1),
    "unique_ports": np.random.randint(10, 150, n_stealth),
    "avg_packet_size": np.random.uniform(40, 120, n_stealth).round(1),
    "protocol": np.random.choice(["TCP", "UDP"], n_stealth, p=[0.7, 0.3]),
    "duration": np.random.uniform(30, 600, n_stealth).round(1),
    "connection_count": np.random.randint(5, 60, n_stealth),
}

attack_df = pd.concat([
    pd.DataFrame(port_scan).assign(attack_type="port_scan"),
    pd.DataFrame(syn_flood).assign(attack_type="syn_flood"),
    pd.DataFrame(udp_flood).assign(attack_type="udp_flood"),
    pd.DataFrame(slowloris).assign(attack_type="slowloris"),
    pd.DataFrame(dns_amp).assign(attack_type="dns_amplification"),
    pd.DataFrame(protocol_anomaly).assign(attack_type="protocol_anomaly"),
    pd.DataFrame(brute_force).assign(attack_type="brute_force"),
    pd.DataFrame(icmp_flood).assign(attack_type="icmp_flood"),
    pd.DataFrame(http_flood).assign(attack_type="http_flood"),
    pd.DataFrame(stealth_probe).assign(attack_type="stealth_probe"),
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
print(f"\n  Normal profiles:")
print(f"    Web browsing:      {n_web:,} (45%)")
print(f"    Streaming:         {n_stream:,} (18%)")
print(f"    DNS:               {n_dns:,} (12%)")
print(f"    ICMP/Ping:         {n_icmp:,} (5%)")
print(f"    Edge cases:        {n_edge:,} (10%) <- prevents overfitting")
print(f"    IoT/Sensor:        {n_iot:,} (5%)")
print(f"    Database/API:      {n_db:,} (5%)")
print(f"\n  Attack types ({len(attack_df):,} total):")
for atype, count in attack_df['attack_type'].value_counts().sort_index().items():
    print(f"    {atype:<25} {count:,}")
print(f"\n  Features: packet_rate, unique_ports, avg_packet_size, duration, protocol, connection_count")
print(f"\n  Feature ranges (Normal):")
for col in ["packet_rate", "unique_ports", "avg_packet_size", "duration", "connection_count"]:
    print(f"    {col:<20} min={normal_df[col].min():.1f}  mean={normal_df[col].mean():.1f}  max={normal_df[col].max():.1f}")
print(f"\n  Feature ranges (Attack):")
for col in ["packet_rate", "unique_ports", "avg_packet_size", "duration", "connection_count"]:
    print(f"    {col:<20} min={attack_df[col].min():.1f}  mean={attack_df[col].mean():.1f}  max={attack_df[col].max():.1f}")
