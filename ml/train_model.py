"""
Train Isolation Forest model on normal traffic data.
The model learns what "normal" looks like and flags deviations as anomalies.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
ENCODER_PATH = os.path.join(os.path.dirname(__file__), "protocol_encoder.pkl")

# ── Feature columns used for training ───────────────────────────────────────
FEATURE_COLS = ["packet_rate", "unique_ports", "avg_packet_size", "duration", "protocol_flag"]


def encode_protocol(df: pd.DataFrame) -> pd.DataFrame:
    """Encode protocol string to numeric flag."""
    protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
    df = df.copy()
    df["protocol_flag"] = df["protocol"].map(protocol_map).fillna(3)  # 3 = unknown/other
    return df


def train():
    """Train Isolation Forest on normal traffic data."""
    print("=" * 60)
    print("  Isolation Forest Model Training")
    print("=" * 60)

    # Load normal traffic data
    normal_path = os.path.join(DATA_DIR, "normal_traffic.csv")
    if not os.path.exists(normal_path):
        print(f"❌ Training data not found at {normal_path}")
        print("   Run `python ml/generate_data.py` first to create training data.")
        return

    df = pd.read_csv(normal_path)
    print(f"\n📊 Loaded {len(df)} normal traffic samples")
    print(f"   Features: {list(df.columns)}")

    # Feature engineering
    df = encode_protocol(df)
    X_train = df[FEATURE_COLS].values

    print(f"\n🔧 Training features: {FEATURE_COLS}")
    print(f"   Training samples: {X_train.shape[0]}")
    print(f"   Feature dimensions: {X_train.shape[1]}")

    # Train Isolation Forest
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,   # Expect ~5% false positives on training data
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )

    model.fit(X_train)

    # Save model
    joblib.dump(model, MODEL_PATH)
    print(f"\n💾 Model saved to: {MODEL_PATH}")

    # Validate on training data
    train_preds = model.predict(X_train)
    train_scores = model.decision_function(X_train)
    n_anomalies = (train_preds == -1).sum()

    print(f"\n📈 Training Validation:")
    print(f"   Normal classified correctly: {(train_preds == 1).sum()}/{len(train_preds)}")
    print(f"   False positives on training: {n_anomalies}/{len(train_preds)} ({n_anomalies/len(train_preds)*100:.1f}%)")
    print(f"   Avg anomaly score: {train_scores.mean():.4f}")

    # Validate on attack data if available
    attack_path = os.path.join(DATA_DIR, "attack_traffic.csv")
    if os.path.exists(attack_path):
        attack_df = pd.read_csv(attack_path)
        attack_df = encode_protocol(attack_df)
        X_attack = attack_df[FEATURE_COLS].values

        attack_preds = model.predict(X_attack)
        attack_scores = model.decision_function(X_attack)
        n_detected = (attack_preds == -1).sum()

        print(f"\n🎯 Attack Detection Validation:")
        print(f"   Attacks detected: {n_detected}/{len(attack_preds)} ({n_detected/len(attack_preds)*100:.1f}%)")
        print(f"   Missed attacks: {(attack_preds == 1).sum()}/{len(attack_preds)}")
        print(f"   Avg anomaly score: {attack_scores.mean():.4f}")

    print(f"\n{'=' * 60}")
    print("  Training complete!")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    train()
