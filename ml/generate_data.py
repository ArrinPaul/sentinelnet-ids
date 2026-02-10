"""
Generate training data for the Isolation Forest model.
Creates normal_traffic.csv (clean data) and attack_traffic.csv (for validation).
"""

import pandas as pd
import numpy as np
import os

np.random.seed(42)

# ── Normal Traffic Data (500 rows) ──────────────────────────────────────────
# Characteristics of normal traffic:
#   - packet_rate: 50-500 pps (moderate)
#   - unique_ports: 1-10 (few ports)
#   - avg_packet_size: 200-1500 bytes (normal range)
#   - duration: 1-60 seconds
#   - protocol: mostly TCP/UDP with occasional ICMP

n_normal = 500

normal_data = {
    "src_ip": [f"192.168.1.{np.random.randint(1, 254)}" for _ in range(n_normal)],
    "dst_ip": [f"10.0.0.{np.random.randint(1, 254)}" for _ in range(n_normal)],
    "packet_rate": np.random.uniform(50, 500, n_normal).round(1),
    "unique_ports": np.random.randint(1, 11, n_normal),
    "avg_packet_size": np.random.uniform(200, 1500, n_normal).round(1),
    "protocol": np.random.choice(["TCP", "UDP", "ICMP"], n_normal, p=[0.6, 0.3, 0.1]),
    "duration": np.random.uniform(1, 60, n_normal).round(1),
}

normal_df = pd.DataFrame(normal_data)

# ── Attack Traffic Data (120 rows) ─────────────────────────────────────────
# Mix of different attack patterns:

# Port Scan (40 rows): high unique_ports, moderate packet rate
port_scan = {
    "src_ip": [f"10.10.10.{np.random.randint(1, 254)}" for _ in range(40)],
    "dst_ip": [f"192.168.1.{np.random.randint(1, 254)}" for _ in range(40)],
    "packet_rate": np.random.uniform(200, 800, 40).round(1),
    "unique_ports": np.random.randint(20, 200, 40),
    "avg_packet_size": np.random.uniform(40, 100, 40).round(1),
    "protocol": np.random.choice(["TCP", "UDP"], 40, p=[0.8, 0.2]),
    "duration": np.random.uniform(1, 10, 40).round(1),
}

# Flood Attack (40 rows): very high packet rate, small packets
flood = {
    "src_ip": [f"172.16.0.{np.random.randint(1, 254)}" for _ in range(40)],
    "dst_ip": [f"192.168.1.{np.random.randint(1, 254)}" for _ in range(40)],
    "packet_rate": np.random.uniform(1500, 5000, 40).round(1),
    "unique_ports": np.random.randint(1, 5, 40),
    "avg_packet_size": np.random.uniform(20, 80, 40).round(1),
    "protocol": np.random.choice(["TCP", "UDP", "ICMP"], 40, p=[0.4, 0.3, 0.3]),
    "duration": np.random.uniform(1, 30, 40).round(1),
}

# Protocol Anomaly (40 rows): unusual protocols, varied patterns
anomaly = {
    "src_ip": [f"203.0.113.{np.random.randint(1, 254)}" for _ in range(40)],
    "dst_ip": [f"192.168.1.{np.random.randint(1, 254)}" for _ in range(40)],
    "packet_rate": np.random.uniform(100, 2000, 40).round(1),
    "unique_ports": np.random.randint(5, 100, 40),
    "avg_packet_size": np.random.uniform(50, 300, 40).round(1),
    "protocol": np.random.choice(["GRE", "ESP", "AH", "SCTP"], 40),
    "duration": np.random.uniform(0.5, 5, 40).round(1),
}

attack_df = pd.concat([
    pd.DataFrame(port_scan),
    pd.DataFrame(flood),
    pd.DataFrame(anomaly),
], ignore_index=True)

# ── Save CSVs ────────────────────────────────────────────────────────────────
data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
os.makedirs(data_dir, exist_ok=True)

normal_path = os.path.join(data_dir, "normal_traffic.csv")
attack_path = os.path.join(data_dir, "attack_traffic.csv")

normal_df.to_csv(normal_path, index=False)
attack_df.to_csv(attack_path, index=False)

print(f"✅ Normal traffic data: {len(normal_df)} rows → {normal_path}")
print(f"✅ Attack traffic data: {len(attack_df)} rows → {attack_path}")
print(f"\nNormal data sample:\n{normal_df.head()}")
print(f"\nAttack data sample:\n{attack_df.head()}")
