"""
Train Isolation Forest model on normal traffic data.
Includes feature scaling, proper evaluation metrics, cross-validation,
and model comparison (Isolation Forest vs One-Class SVM vs LOF).
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import KFold
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
)
import joblib
import os
import json

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
ML_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(ML_DIR, "model.pkl")
SCALER_PATH = os.path.join(ML_DIR, "scaler.pkl")
METRICS_PATH = os.path.join(ML_DIR, "training_metrics.json")

# ── Feature columns used for training ───────────────────────────────────────
FEATURE_COLS = ["packet_rate", "unique_ports", "avg_packet_size", "duration", "protocol_flag"]


def encode_protocol(df: pd.DataFrame) -> pd.DataFrame:
    """Encode protocol string to numeric flag."""
    protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
    df = df.copy()
    df["protocol_flag"] = df["protocol"].map(protocol_map).fillna(3)  # 3 = unknown/other
    return df


def evaluate_model(model, X_normal, X_attack, model_name="Model", use_fit_predict=False):
    """Evaluate a model on normal + attack data and print metrics."""
    if use_fit_predict:
        normal_preds = model.fit_predict(X_normal)
    else:
        normal_preds = model.predict(X_normal)
    attack_preds = model.predict(X_attack)

    # Convert: sklearn anomaly = -1, normal = 1  ->  standard: anomaly = 1, normal = 0
    y_true = np.concatenate([np.zeros(len(X_normal)), np.ones(len(X_attack))])
    y_pred = np.concatenate([
        (normal_preds == -1).astype(int),
        (attack_preds == -1).astype(int),
    ])

    # Calculate scores for attack detection (if model has decision_function)
    if hasattr(model, "decision_function"):
        normal_scores = model.decision_function(X_normal)
        attack_scores = model.decision_function(X_attack)
        all_scores = np.concatenate([-normal_scores, -attack_scores])  # negate: higher = more anomalous
        try:
            auc = roc_auc_score(y_true, all_scores)
        except ValueError:
            auc = 0.0
    else:
        auc = 0.0
        normal_scores = np.zeros(len(X_normal))
        attack_scores = np.zeros(len(X_attack))

    # Metrics
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    normal_correct = (normal_preds == 1).sum()
    attack_detected = (attack_preds == -1).sum()
    false_positives = (normal_preds == -1).sum()

    print(f"\n{'─' * 50}")
    print(f"  {model_name}")
    print(f"{'─' * 50}")
    print(f"  Normal classified correctly: {normal_correct}/{len(X_normal)} ({normal_correct/len(X_normal)*100:.1f}%)")
    print(f"  False positives (normal as attack): {false_positives}/{len(X_normal)} ({false_positives/len(X_normal)*100:.1f}%)")
    print(f"  Attacks detected: {attack_detected}/{len(X_attack)} ({attack_detected/len(X_attack)*100:.1f}%)")
    print(f"  Missed attacks: {len(X_attack) - attack_detected}/{len(X_attack)}")
    print(f"\n  Precision: {precision:.4f}")
    print(f"  Recall:    {recall:.4f}")
    print(f"  F1 Score:  {f1:.4f}")
    print(f"  ROC-AUC:   {auc:.4f}")
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]:4d}  FP={cm[0][1]:4d}")
    print(f"    FN={cm[1][0]:4d}  TP={cm[1][1]:4d}")

    return {
        "model": model_name,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(auc, 4),
        "normal_accuracy": round(normal_correct / len(X_normal), 4),
        "attack_detection_rate": round(attack_detected / len(X_attack), 4),
        "false_positive_rate": round(false_positives / len(X_normal), 4),
        "confusion_matrix": cm.tolist(),
    }


def cross_validate_isolation_forest(X, n_splits=5):
    """K-Fold cross-validation on normal data for Isolation Forest."""
    print(f"\n  {n_splits}-Fold Cross-Validation on Normal Data:")
    kf = KFold(n_splits=n_splits, shuffle=True, random_state=42)
    fp_rates = []

    for fold, (train_idx, val_idx) in enumerate(kf.split(X)):
        X_train, X_val = X[train_idx], X[val_idx]
        model = IsolationForest(
            n_estimators=150, contamination=0.03, max_samples="auto",
            random_state=42, n_jobs=-1,
        )
        model.fit(X_train)
        preds = model.predict(X_val)
        fp_rate = (preds == -1).sum() / len(preds)
        fp_rates.append(fp_rate)
        print(f"    Fold {fold+1}: FP rate = {fp_rate:.4f}")

    avg_fp = np.mean(fp_rates)
    std_fp = np.std(fp_rates)
    print(f"    Average FP rate: {avg_fp:.4f} +/- {std_fp:.4f}")
    return {"avg_fp_rate": round(avg_fp, 4), "std_fp_rate": round(std_fp, 4)}


def train():
    """Full training pipeline with scaling, evaluation, and model comparison."""
    print("=" * 60)
    print("  ML Training Pipeline — Isolation Forest IDS")
    print("=" * 60)

    # ── Load Data ────────────────────────────────────────────────────────
    normal_path = os.path.join(DATA_DIR, "normal_traffic.csv")
    attack_path = os.path.join(DATA_DIR, "attack_traffic.csv")

    if not os.path.exists(normal_path):
        print(f"  Training data not found at {normal_path}")
        print("  Run `python ml/generate_data.py` first.")
        return

    normal_df = pd.read_csv(normal_path)
    attack_df = pd.read_csv(attack_path) if os.path.exists(attack_path) else None

    print(f"\n  Loaded {len(normal_df):,} normal samples")
    if attack_df is not None:
        print(f"  Loaded {len(attack_df):,} attack samples")
        if "attack_type" in attack_df.columns:
            print(f"  Attack types: {attack_df['attack_type'].value_counts().to_dict()}")

    # ── Feature Engineering ──────────────────────────────────────────────
    normal_df = encode_protocol(normal_df)
    X_normal = normal_df[FEATURE_COLS].values

    if attack_df is not None:
        attack_df = encode_protocol(attack_df)
        X_attack = attack_df[FEATURE_COLS].values
    else:
        X_attack = None

    print(f"\n  Features: {FEATURE_COLS}")
    print(f"  Normal shape: {X_normal.shape}")
    if X_attack is not None:
        print(f"  Attack shape: {X_attack.shape}")

    # ── Feature Scaling ──────────────────────────────────────────────────
    print("\n  Fitting StandardScaler on normal data...")
    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)
    if X_attack is not None:
        X_attack_scaled = scaler.transform(X_attack)

    print(f"  Feature means: {np.round(scaler.mean_, 2)}")
    print(f"  Feature stds: {np.round(scaler.scale_, 2)}")

    # Save scaler
    joblib.dump(scaler, SCALER_PATH)
    print(f"  Scaler saved to: {SCALER_PATH}")

    # ── Cross-Validation ─────────────────────────────────────────────────
    cv_results = cross_validate_isolation_forest(X_normal_scaled, n_splits=5)

    # ── Train Primary Model (Isolation Forest) ───────────────────────────
    print("\n  Training Isolation Forest (primary model)...")
    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=0.03,
        max_samples="auto",
        max_features=1.0,
        random_state=42,
        n_jobs=-1,
    )
    iso_forest.fit(X_normal_scaled)

    # Save primary model
    joblib.dump(iso_forest, MODEL_PATH)
    print(f"  Model saved to: {MODEL_PATH}")

    # ── Evaluate Primary Model ───────────────────────────────────────────
    all_metrics = {}
    if X_attack is not None:
        iso_metrics = evaluate_model(iso_forest, X_normal_scaled, X_attack_scaled, "Isolation Forest")
        all_metrics["isolation_forest"] = iso_metrics

    # ── Model Comparison ─────────────────────────────────────────────────
    if X_attack is not None:
        print(f"\n{'=' * 60}")
        print(f"  Model Comparison")
        print(f"{'=' * 60}")

        # One-Class SVM
        print("\n  Training One-Class SVM...")
        oc_svm = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
        oc_svm.fit(X_normal_scaled)
        svm_metrics = evaluate_model(oc_svm, X_normal_scaled, X_attack_scaled, "One-Class SVM")
        all_metrics["one_class_svm"] = svm_metrics

        # Local Outlier Factor
        print("\n  Training Local Outlier Factor...")
        lof = LocalOutlierFactor(n_neighbors=20, contamination=0.05, novelty=True, n_jobs=-1)
        lof.fit(X_normal_scaled)
        lof_metrics = evaluate_model(lof, X_normal_scaled, X_attack_scaled, "Local Outlier Factor")
        all_metrics["local_outlier_factor"] = lof_metrics

        # Comparison summary
        print(f"\n{'=' * 60}")
        print(f"  Summary Comparison")
        print(f"{'=' * 60}")
        print(f"  {'Model':<25} {'F1':>8} {'Recall':>8} {'AUC':>8} {'FPR':>8}")
        print(f"  {'─' * 55}")
        for name, m in all_metrics.items():
            print(f"  {m['model']:<25} {m['f1_score']:>8.4f} {m['recall']:>8.4f} {m['roc_auc']:>8.4f} {m['false_positive_rate']:>8.4f}")

    # ── Feature Importance (permutation-based approximation) ─────────────
    print(f"\n{'=' * 60}")
    print(f"  Feature Importance Analysis")
    print(f"{'=' * 60}")

    base_scores = iso_forest.decision_function(X_normal_scaled)
    base_mean = base_scores.mean()

    importance = {}
    for i, feat in enumerate(FEATURE_COLS):
        X_perm = X_normal_scaled.copy()
        np.random.shuffle(X_perm[:, i])
        perm_scores = iso_forest.decision_function(X_perm)
        importance[feat] = abs(base_mean - perm_scores.mean())

    total_imp = sum(importance.values()) or 1.0
    print(f"  {'Feature':<20} {'Importance':>12} {'Relative':>10}")
    print(f"  {'─' * 45}")
    for feat, imp in sorted(importance.items(), key=lambda x: -x[1]):
        pct = imp / total_imp * 100
        print(f"  {feat:<20} {imp:>12.6f} {pct:>9.1f}%")

    # ── Save All Metrics ─────────────────────────────────────────────────
    metrics_output = {
        "training_samples": len(normal_df),
        "attack_samples": len(attack_df) if attack_df is not None else 0,
        "features": FEATURE_COLS,
        "scaler_means": scaler.mean_.tolist(),
        "scaler_stds": scaler.scale_.tolist(),
        "cross_validation": cv_results,
        "model_metrics": all_metrics,
        "feature_importance": {k: round(v / total_imp, 4) for k, v in importance.items()},
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics_output, f, indent=2)

    print(f"\n  Full metrics saved to: {METRICS_PATH}")
    print(f"\n{'=' * 60}")
    print(f"  Training Pipeline Complete!")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    train()
