"""
Train Isolation Forest model on normal traffic data.
Anti-overfitting pipeline with:
  - Proper train / validation / test split (70/15/15)
  - Hyperparameter grid search with validation set
  - Per-attack-type detection evaluation
  - Learning curve analysis
  - Feature importance with confidence intervals
  - Model comparison (IF vs One-Class SVM vs LOF)
  - Full metrics report saved to JSON
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
import time

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
ML_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(ML_DIR, "model.pkl")
SCALER_PATH = os.path.join(ML_DIR, "scaler.pkl")
METRICS_PATH = os.path.join(ML_DIR, "training_metrics.json")

# ── Feature columns used for training ───────────────────────────────────────
RAW_FEATURES = ["packet_rate", "unique_ports", "avg_packet_size", "duration", "protocol_flag"]
DERIVED_FEATURES = ["bytes_per_second", "port_scan_ratio", "size_rate_ratio"]
FEATURE_COLS = RAW_FEATURES + DERIVED_FEATURES


def encode_protocol(df: pd.DataFrame) -> pd.DataFrame:
    """Encode protocol string to numeric flag."""
    protocol_map = {"TCP": 0, "UDP": 1, "ICMP": 2}
    df = df.copy()
    df["protocol_flag"] = df["protocol"].map(protocol_map).fillna(3)
    return df


def add_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add engineered features that capture relationships between raw features."""
    df = df.copy()
    # Bytes per second: packet_rate × avg_packet_size (captures bandwidth usage)
    df["bytes_per_second"] = (df["packet_rate"] * df["avg_packet_size"]).round(1)
    # Port scan ratio: unique_ports / duration (how fast ports are being probed)
    df["port_scan_ratio"] = (df["unique_ports"] / df["duration"].clip(lower=0.1)).round(4)
    # Size-rate ratio: avg_packet_size / packet_rate (small packets + high rate = flood)
    df["size_rate_ratio"] = (df["avg_packet_size"] / df["packet_rate"].clip(lower=0.1)).round(4)
    return df


def split_data(X, test_frac=0.15, val_frac=0.15, seed=42):
    """Split data into train/validation/test sets."""
    rng = np.random.RandomState(seed)
    n = len(X)
    indices = rng.permutation(n)
    n_test = int(n * test_frac)
    n_val = int(n * val_frac)
    test_idx = indices[:n_test]
    val_idx = indices[n_test:n_test + n_val]
    train_idx = indices[n_test + n_val:]
    return X[train_idx], X[val_idx], X[test_idx]


def evaluate_model(model, X_normal, X_attack, model_name="Model"):
    """Evaluate a model on normal + attack data and return metrics."""
    normal_preds = model.predict(X_normal)
    attack_preds = model.predict(X_attack)

    y_true = np.concatenate([np.zeros(len(X_normal)), np.ones(len(X_attack))])
    y_pred = np.concatenate([
        (normal_preds == -1).astype(int),
        (attack_preds == -1).astype(int),
    ])

    if hasattr(model, "decision_function"):
        normal_scores = model.decision_function(X_normal)
        attack_scores = model.decision_function(X_attack)
        all_scores = np.concatenate([-normal_scores, -attack_scores])
        try:
            auc = roc_auc_score(y_true, all_scores)
        except ValueError:
            auc = 0.0
    else:
        auc = 0.0

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    cm = confusion_matrix(y_true, y_pred)

    normal_correct = (normal_preds == 1).sum()
    attack_detected = (attack_preds == -1).sum()
    false_positives = (normal_preds == -1).sum()

    print(f"\n{'─' * 55}")
    print(f"  {model_name}")
    print(f"{'─' * 55}")
    print(f"  Normal correct:   {normal_correct}/{len(X_normal)} ({normal_correct/len(X_normal)*100:.1f}%)")
    print(f"  False positives:  {false_positives}/{len(X_normal)} ({false_positives/len(X_normal)*100:.1f}%)")
    print(f"  Attacks detected: {attack_detected}/{len(X_attack)} ({attack_detected/len(X_attack)*100:.1f}%)")
    print(f"  Missed attacks:   {len(X_attack) - attack_detected}/{len(X_attack)}")
    print(f"\n  Precision: {precision:.4f}  Recall: {recall:.4f}  F1: {f1:.4f}  AUC: {auc:.4f}")
    print(f"  Confusion Matrix:  TN={cm[0][0]}  FP={cm[0][1]}  FN={cm[1][0]}  TP={cm[1][1]}")

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


def per_attack_evaluation(model, attack_df_scaled, attack_types):
    """Break down detection rates per attack type."""
    results = {}
    print(f"\n  Per-Attack-Type Detection Rates:")
    print(f"  {'Attack Type':<25} {'Detected':>10} {'Total':>8} {'Rate':>8}")
    print(f"  {'─' * 55}")

    for atype in sorted(attack_types.unique()):
        mask = attack_types == atype
        X_sub = attack_df_scaled[mask]
        preds = model.predict(X_sub)
        detected = (preds == -1).sum()
        total = len(X_sub)
        rate = detected / total if total > 0 else 0
        results[atype] = {"detected": int(detected), "total": int(total), "rate": round(rate, 4)}
        status = "✓" if rate > 0.8 else "△" if rate > 0.5 else "✗"
        print(f"  {atype:<25} {detected:>10} {total:>8} {rate:>7.1%}  {status}")

    return results


def hyperparameter_search(X_train, X_val, X_attack_val):
    """Grid search over Isolation Forest hyperparameters using validation set."""
    print(f"\n{'=' * 60}")
    print(f"  Hyperparameter Search (Validation Set)")
    print(f"{'=' * 60}")

    param_grid = {
        "n_estimators": [100, 200, 300],
        "contamination": [0.01, 0.03, 0.05],
        "max_features": [0.5, 0.75, 1.0],
        "max_samples": [0.5, 0.75, "auto"],
    }

    best_f1 = -1
    best_params = {}
    results = []

    for n_est in param_grid["n_estimators"]:
        for contam in param_grid["contamination"]:
            for max_feat in param_grid["max_features"]:
                for max_samp in param_grid["max_samples"]:
                    model = IsolationForest(
                        n_estimators=n_est,
                        contamination=contam,
                        max_features=max_feat,
                        max_samples=max_samp,
                        random_state=42,
                        n_jobs=-1,
                    )
                    model.fit(X_train)

                    val_normal_preds = model.predict(X_val)
                    val_attack_preds = model.predict(X_attack_val)

                    y_true = np.concatenate([np.zeros(len(X_val)), np.ones(len(X_attack_val))])
                    y_pred = np.concatenate([
                        (val_normal_preds == -1).astype(int),
                        (val_attack_preds == -1).astype(int),
                    ])

                    f1 = f1_score(y_true, y_pred, zero_division=0)
                    fpr = (val_normal_preds == -1).sum() / len(X_val)
                    recall_val = recall_score(y_true, y_pred, zero_division=0)

                    result = {
                        "n_estimators": n_est,
                        "contamination": contam,
                        "max_features": max_feat,
                        "max_samples": str(max_samp),
                        "f1": round(f1, 4),
                        "recall": round(recall_val, 4),
                        "fpr": round(fpr, 4),
                    }
                    results.append(result)

                    if f1 > best_f1:
                        best_f1 = f1
                        best_params = {
                            "n_estimators": n_est,
                            "contamination": contam,
                            "max_features": max_feat,
                            "max_samples": max_samp,
                        }

    print(f"\n  Searched {len(results)} combinations")
    print(f"  Best F1 on validation: {best_f1:.4f}")
    print(f"  Best params: {best_params}")

    # Show top 5
    top5 = sorted(results, key=lambda x: -x["f1"])[:5]
    print(f"\n  Top 5 Configurations:")
    print(f"  {'n_est':>6} {'contam':>8} {'max_feat':>10} {'max_samp':>10} {'F1':>8} {'Recall':>8} {'FPR':>8}")
    for r in top5:
        print(f"  {r['n_estimators']:>6} {r['contamination']:>8} {r['max_features']:>10} {r['max_samples']:>10} {r['f1']:>8.4f} {r['recall']:>8.4f} {r['fpr']:>8.4f}")

    return best_params, results


def learning_curve_analysis(X_train, X_test_normal, X_test_attack, best_params):
    """Train with increasing data sizes to detect overfitting."""
    print(f"\n{'=' * 60}")
    print(f"  Learning Curve Analysis")
    print(f"{'=' * 60}")

    fractions = [0.1, 0.2, 0.3, 0.5, 0.7, 0.85, 1.0]
    curve_data = []

    for frac in fractions:
        n_samples = int(len(X_train) * frac)
        X_sub = X_train[:n_samples]

        model = IsolationForest(**best_params, random_state=42, n_jobs=-1)
        model.fit(X_sub)

        # Training score (on the data used for training)
        train_preds = model.predict(X_sub)
        train_fpr = (train_preds == -1).sum() / len(X_sub)

        # Test score
        test_normal_preds = model.predict(X_test_normal)
        test_attack_preds = model.predict(X_test_attack)
        y_true = np.concatenate([np.zeros(len(X_test_normal)), np.ones(len(X_test_attack))])
        y_pred = np.concatenate([
            (test_normal_preds == -1).astype(int),
            (test_attack_preds == -1).astype(int),
        ])
        test_f1 = f1_score(y_true, y_pred, zero_division=0)
        test_fpr = (test_normal_preds == -1).sum() / len(X_test_normal)
        test_recall = recall_score(y_true, y_pred, zero_division=0)

        point = {
            "fraction": frac,
            "n_samples": n_samples,
            "train_fpr": round(train_fpr, 4),
            "test_f1": round(test_f1, 4),
            "test_fpr": round(test_fpr, 4),
            "test_recall": round(test_recall, 4),
        }
        curve_data.append(point)
        print(f"  {frac:>5.0%} ({n_samples:>6} samples) → test F1={test_f1:.4f}  FPR={test_fpr:.4f}  Recall={test_recall:.4f}  train_FPR={train_fpr:.4f}")

    # Check for overfitting signal
    if len(curve_data) >= 2:
        final_f1 = curve_data[-1]["test_f1"]
        mid_f1 = curve_data[len(curve_data) // 2]["test_f1"]
        if final_f1 < mid_f1 - 0.02:
            print(f"\n  ⚠ WARNING: Possible overfitting detected (F1 drops with more data)")
        elif final_f1 >= mid_f1 - 0.005:
            print(f"\n  ✓ No overfitting detected (F1 stable or improving with more data)")

    return curve_data


def cross_validate(X, n_splits=5, params=None):
    """K-Fold cross-validation on normal data."""
    print(f"\n  {n_splits}-Fold Cross-Validation:")
    kf = KFold(n_splits=n_splits, shuffle=True, random_state=42)
    fp_rates = []

    for fold, (train_idx, val_idx) in enumerate(kf.split(X)):
        X_train, X_val = X[train_idx], X[val_idx]
        model = IsolationForest(**(params or {}), random_state=42, n_jobs=-1)
        model.fit(X_train)
        preds = model.predict(X_val)
        fp_rate = (preds == -1).sum() / len(preds)
        fp_rates.append(fp_rate)
        print(f"    Fold {fold+1}: FP rate = {fp_rate:.4f}")

    avg_fp = np.mean(fp_rates)
    std_fp = np.std(fp_rates)
    print(f"    Average: {avg_fp:.4f} ± {std_fp:.4f}")
    return {"avg_fp_rate": round(avg_fp, 4), "std_fp_rate": round(std_fp, 4), "fold_fp_rates": [round(f, 4) for f in fp_rates]}


def feature_importance_with_ci(model, X, n_repeats=10):
    """Permutation feature importance with confidence intervals."""
    print(f"\n{'=' * 60}")
    print(f"  Feature Importance (Permutation, {n_repeats} repeats)")
    print(f"{'=' * 60}")

    base_scores = model.decision_function(X)
    base_mean = base_scores.mean()

    importance = {feat: [] for feat in FEATURE_COLS}
    rng = np.random.RandomState(42)

    for rep in range(n_repeats):
        for i, feat in enumerate(FEATURE_COLS):
            X_perm = X.copy()
            rng.shuffle(X_perm[:, i])
            perm_scores = model.decision_function(X_perm)
            importance[feat].append(abs(base_mean - perm_scores.mean()))

    results = {}
    total_imp = sum(np.mean(v) for v in importance.values()) or 1.0

    print(f"  {'Feature':<22} {'Mean':>10} {'±Std':>10} {'Relative':>10}")
    print(f"  {'─' * 55}")
    for feat in sorted(importance.keys(), key=lambda f: -np.mean(importance[f])):
        vals = importance[feat]
        mean_imp = np.mean(vals)
        std_imp = np.std(vals)
        pct = mean_imp / total_imp * 100
        results[feat] = {
            "mean": round(mean_imp, 6),
            "std": round(std_imp, 6),
            "relative": round(pct, 2),
        }
        print(f"  {feat:<22} {mean_imp:>10.6f} {std_imp:>10.6f} {pct:>9.1f}%")

    return results


def train():
    """Full anti-overfitting training pipeline."""
    start_time = time.time()

    print("=" * 60)
    print("  ML Training Pipeline — Anti-Overfitting Edition")
    print("=" * 60)

    # ── Load Data ────────────────────────────────────────────────────────
    normal_path = os.path.join(DATA_DIR, "normal_traffic.csv")
    attack_path = os.path.join(DATA_DIR, "attack_traffic.csv")

    if not os.path.exists(normal_path):
        print(f"  ERROR: Training data not found at {normal_path}")
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
    normal_df = add_derived_features(normal_df)
    X_normal_all = normal_df[FEATURE_COLS].values

    attack_types = None
    if attack_df is not None:
        attack_df = encode_protocol(attack_df)
        attack_df = add_derived_features(attack_df)
        X_attack_all = attack_df[FEATURE_COLS].values
        attack_types = attack_df["attack_type"]

    print(f"\n  Features ({len(FEATURE_COLS)}): {FEATURE_COLS}")
    print(f"  Raw: {RAW_FEATURES}")
    print(f"  Derived: {DERIVED_FEATURES}")

    # ── Train / Validation / Test Split ──────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  Data Split (70% train / 15% val / 15% test)")
    print(f"{'=' * 60}")

    X_train_raw, X_val_raw, X_test_raw = split_data(X_normal_all, test_frac=0.15, val_frac=0.15)
    print(f"  Normal — Train: {len(X_train_raw):,}  Val: {len(X_val_raw):,}  Test: {len(X_test_raw):,}")

    # Split attack data too (for validation-based hyperparameter tuning)
    if attack_df is not None:
        rng = np.random.RandomState(42)
        atk_indices = rng.permutation(len(X_attack_all))
        n_atk_test = int(len(X_attack_all) * 0.15)
        n_atk_val = int(len(X_attack_all) * 0.15)
        X_attack_test = X_attack_all[atk_indices[:n_atk_test]]
        X_attack_val = X_attack_all[atk_indices[n_atk_test:n_atk_test + n_atk_val]]
        attack_types_test = attack_types.iloc[atk_indices[:n_atk_test]]
        print(f"  Attack — Val: {len(X_attack_val):,}  Test: {len(X_attack_test):,}")

    # ── Feature Scaling ──────────────────────────────────────────────────
    print(f"\n  Fitting StandardScaler on TRAINING data only...")
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train_raw)
    X_val = scaler.transform(X_val_raw)
    X_test = scaler.transform(X_test_raw)

    if attack_df is not None:
        X_attack_val_scaled = scaler.transform(X_attack_val)
        X_attack_test_scaled = scaler.transform(X_attack_test)

    print(f"  Feature means (train): {np.round(scaler.mean_, 2)}")
    print(f"  Feature stds  (train): {np.round(scaler.scale_, 2)}")

    joblib.dump(scaler, SCALER_PATH)
    print(f"  Scaler saved to: {SCALER_PATH}")

    # ── Hyperparameter Search on Validation Set ──────────────────────────
    best_params, search_results = hyperparameter_search(X_train, X_val, X_attack_val_scaled)

    # ── Cross-Validation with Best Params ────────────────────────────────
    cv_results = cross_validate(X_train, n_splits=5, params=best_params)

    # ── Train Final Model with Best Params ───────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  Training Final Model (Best Params)")
    print(f"{'=' * 60}")
    print(f"  Params: {best_params}")

    final_model = IsolationForest(**best_params, random_state=42, n_jobs=-1)
    final_model.fit(X_train)

    joblib.dump(final_model, MODEL_PATH)
    print(f"  Model saved to: {MODEL_PATH}")

    # ── Evaluate on HELD-OUT TEST SET (never seen during training/tuning) ─
    all_metrics = {}
    if attack_df is not None:
        print(f"\n{'=' * 60}")
        print(f"  Final Evaluation on HELD-OUT TEST SET")
        print(f"{'=' * 60}")

        iso_metrics = evaluate_model(final_model, X_test, X_attack_test_scaled, "Isolation Forest (tuned)")
        all_metrics["isolation_forest"] = iso_metrics

        # Per-attack-type evaluation
        attack_type_results = per_attack_evaluation(final_model, X_attack_test_scaled, attack_types_test)
        all_metrics["isolation_forest"]["per_attack_type"] = attack_type_results

    # ── Learning Curve ───────────────────────────────────────────────────
    learning_curve = learning_curve_analysis(X_train, X_test, X_attack_test_scaled, best_params)

    # ── Model Comparison (on test set) ───────────────────────────────────
    if attack_df is not None:
        print(f"\n{'=' * 60}")
        print(f"  Model Comparison (Test Set)")
        print(f"{'=' * 60}")

        # One-Class SVM
        print("\n  Training One-Class SVM...")
        oc_svm = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
        oc_svm.fit(X_train)
        svm_metrics = evaluate_model(oc_svm, X_test, X_attack_test_scaled, "One-Class SVM")
        all_metrics["one_class_svm"] = svm_metrics

        # Local Outlier Factor
        print("\n  Training Local Outlier Factor...")
        lof = LocalOutlierFactor(n_neighbors=20, contamination=0.05, novelty=True, n_jobs=-1)
        lof.fit(X_train)
        lof_metrics = evaluate_model(lof, X_test, X_attack_test_scaled, "Local Outlier Factor")
        all_metrics["local_outlier_factor"] = lof_metrics

        # Summary table
        print(f"\n{'=' * 60}")
        print(f"  Model Comparison Summary")
        print(f"{'=' * 60}")
        print(f"  {'Model':<30} {'F1':>8} {'Recall':>8} {'AUC':>8} {'FPR':>8}")
        print(f"  {'─' * 60}")
        for name, m in all_metrics.items():
            if "model" in m:
                print(f"  {m['model']:<30} {m['f1_score']:>8.4f} {m['recall']:>8.4f} {m['roc_auc']:>8.4f} {m['false_positive_rate']:>8.4f}")

    # ── Feature Importance ───────────────────────────────────────────────
    feat_importance = feature_importance_with_ci(final_model, X_test, n_repeats=10)

    # ── Save All Metrics ─────────────────────────────────────────────────
    elapsed = time.time() - start_time

    metrics_output = {
        "training_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "training_duration_seconds": round(elapsed, 1),
        "dataset": {
            "normal_total": len(normal_df),
            "attack_total": len(attack_df) if attack_df is not None else 0,
            "normal_train": len(X_train),
            "normal_val": len(X_val),
            "normal_test": len(X_test),
            "attack_val": len(X_attack_val) if attack_df is not None else 0,
            "attack_test": len(X_attack_test) if attack_df is not None else 0,
        },
        "features": {
            "all": FEATURE_COLS,
            "raw": RAW_FEATURES,
            "derived": DERIVED_FEATURES,
            "count": len(FEATURE_COLS),
        },
        "scaler": {
            "means": scaler.mean_.tolist(),
            "stds": scaler.scale_.tolist(),
        },
        "best_hyperparameters": {k: str(v) if not isinstance(v, (int, float)) else v for k, v in best_params.items()},
        "hyperparameter_search": {
            "total_combinations": len(search_results),
            "top_5": sorted(search_results, key=lambda x: -x["f1"])[:5],
        },
        "cross_validation": cv_results,
        "model_metrics": all_metrics,
        "learning_curve": learning_curve,
        "feature_importance": feat_importance,
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics_output, f, indent=2)

    print(f"\n{'=' * 60}")
    print(f"  Training Pipeline Complete! ({elapsed:.1f}s)")
    print(f"{'=' * 60}")
    print(f"  Model: {MODEL_PATH}")
    print(f"  Scaler: {SCALER_PATH}")
    print(f"  Metrics: {METRICS_PATH}")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    train()
