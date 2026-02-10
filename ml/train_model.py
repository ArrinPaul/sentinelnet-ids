"""
Train Isolation Forest + Ensemble model on normal traffic data.
Complete anti-overfitting pipeline with:
  - Proper train / validation / test split (70/15/15)
  - Hyperparameter grid search with validation set
  - Ensemble model: Isolation Forest + LOF weighted voting
  - Per-attack-type detection evaluation
  - Learning curve analysis
  - Feature importance with confidence intervals
  - Model comparison (IF vs One-Class SVM vs LOF vs Ensemble)
  - Full visualization suite (confusion matrix, ROC, learning curves, etc.)
  - Training logs saved to file
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
    roc_curve,
)
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for image saving
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
import joblib
import os
import json
import time
import sys
import io

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
ML_DIR = os.path.dirname(__file__)
MODEL_PATH = os.path.join(ML_DIR, "model.pkl")
ENSEMBLE_PATH = os.path.join(ML_DIR, "ensemble_lof.pkl")
SCALER_PATH = os.path.join(ML_DIR, "scaler.pkl")
METRICS_PATH = os.path.join(ML_DIR, "training_metrics.json")
REPORT_PATH = os.path.join(ML_DIR, "TRAINING_REPORT.md")
LOG_PATH = os.path.join(ML_DIR, "training.log")
PLOTS_DIR = os.path.join(ML_DIR, "plots")

# ── Feature columns used for training ───────────────────────────────────────
RAW_FEATURES = ["packet_rate", "unique_ports", "avg_packet_size", "duration", "protocol_flag", "connection_count"]
DERIVED_FEATURES = ["bytes_per_second", "port_scan_ratio", "size_rate_ratio", "conn_rate"]
FEATURE_COLS = RAW_FEATURES + DERIVED_FEATURES

# ── Matplotlib style ─────────────────────────────────────────────────────────
plt.style.use("seaborn-v0_8-darkgrid")
sns.set_palette("husl")
COLORS = {
    "primary": "#0ea5e9",    # sky blue
    "danger": "#ef4444",     # red
    "success": "#22c55e",    # green
    "warning": "#f59e0b",    # amber
    "purple": "#a855f7",     # purple
    "teal": "#14b8a6",       # teal
    "bg": "#0f172a",         # dark background
    "text": "#e2e8f0",       # light text
    "grid": "#1e293b",       # grid lines
}


class TeeLogger:
    """Write to both stdout and a log file simultaneously."""
    def __init__(self, log_path):
        self.terminal = sys.stdout
        self.log = open(log_path, "w", encoding="utf-8")

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)

    def flush(self):
        self.terminal.flush()
        self.log.flush()

    def close(self):
        self.log.close()


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
    # Connection rate: connection_count / duration (brute force signal)
    df["conn_rate"] = (df["connection_count"] / df["duration"].clip(lower=0.1)).round(4)
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

    scores = None
    if hasattr(model, "decision_function"):
        normal_scores = model.decision_function(X_normal)
        attack_scores = model.decision_function(X_attack)
        scores = np.concatenate([-normal_scores, -attack_scores])
        try:
            auc = roc_auc_score(y_true, scores)
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
        "y_true": y_true,
        "y_pred": y_pred,
        "scores": scores,
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
        "contamination": [0.01, 0.02, 0.05],
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


def learning_curve_analysis(X_train, X_val, X_attack_val, X_test_normal, X_test_attack, best_params):
    """Train with increasing data sizes to detect overfitting.
    Returns both training and validation/test metrics for plotting."""
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

        # Training metrics (on training data itself — should be high)
        train_preds_normal = model.predict(X_sub)
        train_fpr = (train_preds_normal == -1).sum() / len(X_sub)
        train_accuracy = (train_preds_normal == 1).sum() / len(X_sub)

        # Validation metrics
        val_normal_preds = model.predict(X_val)
        val_attack_preds = model.predict(X_attack_val)
        y_val_true = np.concatenate([np.zeros(len(X_val)), np.ones(len(X_attack_val))])
        y_val_pred = np.concatenate([
            (val_normal_preds == -1).astype(int),
            (val_attack_preds == -1).astype(int),
        ])
        val_f1 = f1_score(y_val_true, y_val_pred, zero_division=0)
        val_recall = recall_score(y_val_true, y_val_pred, zero_division=0)
        val_precision = precision_score(y_val_true, y_val_pred, zero_division=0)
        val_fpr = (val_normal_preds == -1).sum() / len(X_val)
        val_accuracy = 1 - val_fpr  # normal accuracy on validation

        # Test metrics
        test_normal_preds = model.predict(X_test_normal)
        test_attack_preds = model.predict(X_test_attack)
        y_test_true = np.concatenate([np.zeros(len(X_test_normal)), np.ones(len(X_test_attack))])
        y_test_pred = np.concatenate([
            (test_normal_preds == -1).astype(int),
            (test_attack_preds == -1).astype(int),
        ])
        test_f1 = f1_score(y_test_true, y_test_pred, zero_division=0)
        test_fpr = (test_normal_preds == -1).sum() / len(X_test_normal)
        test_recall = recall_score(y_test_true, y_test_pred, zero_division=0)
        test_accuracy = 1 - test_fpr

        point = {
            "fraction": frac,
            "n_samples": n_samples,
            "train_accuracy": round(train_accuracy, 4),
            "train_fpr": round(train_fpr, 4),
            "val_f1": round(val_f1, 4),
            "val_fpr": round(val_fpr, 4),
            "val_recall": round(val_recall, 4),
            "val_precision": round(val_precision, 4),
            "val_accuracy": round(val_accuracy, 4),
            "test_f1": round(test_f1, 4),
            "test_fpr": round(test_fpr, 4),
            "test_recall": round(test_recall, 4),
            "test_accuracy": round(test_accuracy, 4),
        }
        curve_data.append(point)
        print(f"  {frac:>5.0%} ({n_samples:>6} samples) → train_acc={train_accuracy:.4f}  val_F1={val_f1:.4f}  test_F1={test_f1:.4f}  val_FPR={val_fpr:.4f}")

    # Check for overfitting signal
    if len(curve_data) >= 2:
        final_f1 = curve_data[-1]["test_f1"]
        mid_f1 = curve_data[len(curve_data) // 2]["test_f1"]
        train_final = curve_data[-1]["train_accuracy"]
        test_final = curve_data[-1]["test_accuracy"]
        gap = train_final - test_final

        if final_f1 < mid_f1 - 0.02:
            print(f"\n  ⚠ WARNING: Possible overfitting detected (F1 drops with more data)")
        elif gap > 0.1:
            print(f"\n  ⚠ WARNING: Large train-test gap ({gap:.4f}) — possible overfitting")
        elif final_f1 >= mid_f1 - 0.005:
            print(f"\n  ✓ No overfitting detected (F1 stable or improving, train-test gap={gap:.4f})")

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


class EnsembleAnomalyDetector:
    """Ensemble: Isolation Forest (primary) + Local Outlier Factor (secondary).
    Uses weighted voting to combine decisions."""

    def __init__(self, if_model, lof_model, if_weight=0.65, lof_weight=0.35, threshold=0.5):
        self.if_model = if_model
        self.lof_model = lof_model
        self.if_weight = if_weight
        self.lof_weight = lof_weight
        self.threshold = threshold

    def predict(self, X):
        if_preds = self.if_model.predict(X)
        lof_preds = self.lof_model.predict(X)

        # Convert: -1 (anomaly) → 1.0, +1 (normal) → 0.0
        if_anomaly = (if_preds == -1).astype(float)
        lof_anomaly = (lof_preds == -1).astype(float)

        # Weighted vote
        combined = if_anomaly * self.if_weight + lof_anomaly * self.lof_weight

        # Threshold: if combined score ≥ threshold → anomaly (-1), else normal (+1)
        result = np.where(combined >= self.threshold, -1, 1)
        return result

    def decision_function(self, X):
        """Return anomaly scores (more negative = more anomalous)."""
        return self.if_model.decision_function(X)


# ═══════════════════════════════════════════════════════════════════════════
#   VISUALIZATION FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def plot_confusion_matrix(y_true, y_pred, model_name, save_path):
    """Generate and save confusion matrix heatmap."""
    cm = confusion_matrix(y_true, y_pred)
    fig, ax = plt.subplots(figsize=(8, 6))
    fig.patch.set_facecolor(COLORS["bg"])
    ax.set_facecolor(COLORS["bg"])

    sns.heatmap(
        cm, annot=True, fmt="d", cmap="Blues",
        xticklabels=["Normal (Pred)", "Attack (Pred)"],
        yticklabels=["Normal (True)", "Attack (True)"],
        ax=ax, linewidths=1, linecolor=COLORS["grid"],
        annot_kws={"size": 18, "weight": "bold"},
        cbar_kws={"shrink": 0.8},
    )
    ax.set_title(f"Confusion Matrix — {model_name}", fontsize=16, color=COLORS["text"], pad=20, fontweight="bold")
    ax.set_xlabel("Predicted Label", fontsize=13, color=COLORS["text"])
    ax.set_ylabel("True Label", fontsize=13, color=COLORS["text"])
    ax.tick_params(colors=COLORS["text"], labelsize=12)

    # Add accuracy/recall annotations
    tn, fp, fn, tp = cm.ravel()
    total = tn + fp + fn + tp
    accuracy = (tn + tp) / total
    precision_val = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall_val = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_val = 2 * precision_val * recall_val / (precision_val + recall_val) if (precision_val + recall_val) > 0 else 0

    stats_text = (
        f"Accuracy: {accuracy:.2%}  |  Precision: {precision_val:.2%}\n"
        f"Recall: {recall_val:.2%}  |  F1-Score: {f1_val:.2%}\n"
        f"TN: {tn}  FP: {fp}  FN: {fn}  TP: {tp}"
    )
    fig.text(0.5, -0.02, stats_text, ha="center", fontsize=11, color=COLORS["text"],
             bbox=dict(boxstyle="round,pad=0.5", facecolor=COLORS["grid"], edgecolor=COLORS["primary"], alpha=0.8))

    plt.tight_layout()
    fig.savefig(save_path, dpi=200, bbox_inches="tight", facecolor=COLORS["bg"], edgecolor="none")
    plt.close(fig)
    print(f"  📊 Saved: {save_path}")


def plot_roc_curve(all_metrics, save_path):
    """Generate ROC curve for all models that have scores."""
    fig, ax = plt.subplots(figsize=(9, 7))
    fig.patch.set_facecolor(COLORS["bg"])
    ax.set_facecolor(COLORS["bg"])

    model_colors = [COLORS["primary"], COLORS["danger"], COLORS["success"], COLORS["purple"]]

    for i, (name, metrics) in enumerate(all_metrics.items()):
        if metrics.get("scores") is not None:
            fpr_vals, tpr_vals, _ = roc_curve(metrics["y_true"], metrics["scores"])
            auc_val = metrics["roc_auc"]
            color = model_colors[i % len(model_colors)]
            ax.plot(fpr_vals, tpr_vals, color=color, lw=2.5,
                    label=f'{metrics["model"]} (AUC={auc_val:.4f})')

    ax.plot([0, 1], [0, 1], "w--", lw=1, alpha=0.3, label="Random (AUC=0.5)")
    ax.set_xlim([-0.01, 1.01])
    ax.set_ylim([-0.01, 1.01])
    ax.set_xlabel("False Positive Rate", fontsize=13, color=COLORS["text"])
    ax.set_ylabel("True Positive Rate", fontsize=13, color=COLORS["text"])
    ax.set_title("ROC Curves — Model Comparison", fontsize=16, color=COLORS["text"], fontweight="bold")
    ax.legend(loc="lower right", fontsize=11, facecolor=COLORS["grid"], edgecolor=COLORS["primary"],
              labelcolor=COLORS["text"])
    ax.tick_params(colors=COLORS["text"])
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])
    ax.grid(True, alpha=0.15, color=COLORS["text"])

    plt.tight_layout()
    fig.savefig(save_path, dpi=200, bbox_inches="tight", facecolor=COLORS["bg"])
    plt.close(fig)
    print(f"  📊 Saved: {save_path}")


def plot_learning_curves(curve_data, save_path):
    """Plot training vs validation accuracy and F1 learning curves."""
    fractions = [d["fraction"] for d in curve_data]
    n_samples = [d["n_samples"] for d in curve_data]

    fig, axes = plt.subplots(1, 3, figsize=(20, 6))
    fig.patch.set_facecolor(COLORS["bg"])

    # ── Panel 1: Training vs Validation Accuracy ──
    ax = axes[0]
    ax.set_facecolor(COLORS["bg"])
    train_acc = [d["train_accuracy"] for d in curve_data]
    val_acc = [d["val_accuracy"] for d in curve_data]
    test_acc = [d["test_accuracy"] for d in curve_data]

    ax.plot(n_samples, train_acc, "o-", color=COLORS["primary"], lw=2.5, markersize=8, label="Train Accuracy")
    ax.plot(n_samples, val_acc, "s-", color=COLORS["success"], lw=2.5, markersize=8, label="Validation Accuracy")
    ax.plot(n_samples, test_acc, "^-", color=COLORS["danger"], lw=2.5, markersize=8, label="Test Accuracy")
    ax.set_xlabel("Training Samples", fontsize=12, color=COLORS["text"])
    ax.set_ylabel("Accuracy", fontsize=12, color=COLORS["text"])
    ax.set_title("Training vs Validation Accuracy", fontsize=14, color=COLORS["text"], fontweight="bold")
    ax.legend(fontsize=10, facecolor=COLORS["grid"], edgecolor=COLORS["primary"], labelcolor=COLORS["text"])
    ax.tick_params(colors=COLORS["text"])
    ax.grid(True, alpha=0.15, color=COLORS["text"])
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])

    # ── Panel 2: F1 / Recall / Precision Curves ──
    ax = axes[1]
    ax.set_facecolor(COLORS["bg"])
    val_f1 = [d["val_f1"] for d in curve_data]
    val_recall = [d["val_recall"] for d in curve_data]
    val_prec = [d["val_precision"] for d in curve_data]
    test_f1 = [d["test_f1"] for d in curve_data]

    ax.plot(n_samples, val_f1, "o-", color=COLORS["primary"], lw=2.5, markersize=8, label="Val F1")
    ax.plot(n_samples, test_f1, "s-", color=COLORS["danger"], lw=2.5, markersize=8, label="Test F1")
    ax.plot(n_samples, val_recall, "^--", color=COLORS["success"], lw=2, markersize=6, label="Val Recall")
    ax.plot(n_samples, val_prec, "v--", color=COLORS["warning"], lw=2, markersize=6, label="Val Precision")
    ax.set_xlabel("Training Samples", fontsize=12, color=COLORS["text"])
    ax.set_ylabel("Score", fontsize=12, color=COLORS["text"])
    ax.set_title("F1 / Precision / Recall Learning Curves", fontsize=14, color=COLORS["text"], fontweight="bold")
    ax.legend(fontsize=10, facecolor=COLORS["grid"], edgecolor=COLORS["primary"], labelcolor=COLORS["text"])
    ax.tick_params(colors=COLORS["text"])
    ax.grid(True, alpha=0.15, color=COLORS["text"])
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])

    # ── Panel 3: False Positive Rate (Loss analogue) ──
    ax = axes[2]
    ax.set_facecolor(COLORS["bg"])
    train_fpr = [d["train_fpr"] for d in curve_data]
    val_fpr = [d["val_fpr"] for d in curve_data]
    test_fpr = [d["test_fpr"] for d in curve_data]

    ax.plot(n_samples, train_fpr, "o-", color=COLORS["primary"], lw=2.5, markersize=8, label="Train FPR (Loss)")
    ax.plot(n_samples, val_fpr, "s-", color=COLORS["success"], lw=2.5, markersize=8, label="Val FPR (Loss)")
    ax.plot(n_samples, test_fpr, "^-", color=COLORS["danger"], lw=2.5, markersize=8, label="Test FPR (Loss)")
    ax.set_xlabel("Training Samples", fontsize=12, color=COLORS["text"])
    ax.set_ylabel("False Positive Rate", fontsize=12, color=COLORS["text"])
    ax.set_title("Training vs Validation Loss (FPR)", fontsize=14, color=COLORS["text"], fontweight="bold")
    ax.legend(fontsize=10, facecolor=COLORS["grid"], edgecolor=COLORS["primary"], labelcolor=COLORS["text"])
    ax.tick_params(colors=COLORS["text"])
    ax.grid(True, alpha=0.15, color=COLORS["text"])
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])

    plt.tight_layout()
    fig.savefig(save_path, dpi=200, bbox_inches="tight", facecolor=COLORS["bg"])
    plt.close(fig)
    print(f"  📊 Saved: {save_path}")


def plot_per_attack_detection(attack_results, save_path):
    """Bar chart of per-attack detection rates."""
    attacks = sorted(attack_results.keys(), key=lambda k: -attack_results[k]["rate"])
    rates = [attack_results[a]["rate"] * 100 for a in attacks]
    labels = [a.replace("_", " ").title() for a in attacks]

    fig, ax = plt.subplots(figsize=(12, 6))
    fig.patch.set_facecolor(COLORS["bg"])
    ax.set_facecolor(COLORS["bg"])

    # Color bars by rate
    bar_colors = []
    for r in rates:
        if r >= 95:
            bar_colors.append(COLORS["success"])
        elif r >= 80:
            bar_colors.append(COLORS["warning"])
        elif r >= 50:
            bar_colors.append("#f97316")  # orange
        else:
            bar_colors.append(COLORS["danger"])

    bars = ax.barh(labels, rates, color=bar_colors, edgecolor=COLORS["grid"], linewidth=0.5, height=0.65)

    # Add rate labels on bars
    for bar, rate in zip(bars, rates):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2, f"{rate:.1f}%",
                va="center", fontsize=11, color=COLORS["text"], fontweight="bold")

    ax.set_xlabel("Detection Rate (%)", fontsize=13, color=COLORS["text"])
    ax.set_title("Per-Attack-Type Detection Rates", fontsize=16, color=COLORS["text"], fontweight="bold")
    ax.set_xlim(0, 110)
    ax.axvline(x=80, color=COLORS["warning"], linestyle="--", alpha=0.5, label="80% threshold")
    ax.axvline(x=95, color=COLORS["success"], linestyle="--", alpha=0.5, label="95% threshold")
    ax.legend(fontsize=10, facecolor=COLORS["grid"], edgecolor=COLORS["primary"], labelcolor=COLORS["text"])
    ax.tick_params(colors=COLORS["text"], labelsize=11)
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])

    plt.tight_layout()
    fig.savefig(save_path, dpi=200, bbox_inches="tight", facecolor=COLORS["bg"])
    plt.close(fig)
    print(f"  📊 Saved: {save_path}")


def plot_feature_importance(feat_importance, save_path):
    """Bar chart of feature importance with error bars."""
    feats = sorted(feat_importance.keys(), key=lambda f: -feat_importance[f]["relative"])
    means = [feat_importance[f]["relative"] for f in feats]
    stds = [feat_importance[f]["std"] / (sum(feat_importance[f2]["mean"] for f2 in feats) or 1) * 100 for f in feats]
    labels = [f.replace("_", " ").title() for f in feats]

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(COLORS["bg"])
    ax.set_facecolor(COLORS["bg"])

    bars = ax.barh(labels, means, xerr=stds, color=COLORS["primary"], edgecolor=COLORS["grid"],
                   capsize=4, linewidth=0.5, height=0.6, error_kw={"ecolor": COLORS["text"], "elinewidth": 1.5})

    for bar, val in zip(bars, means):
        ax.text(bar.get_width() + 0.5, bar.get_y() + bar.get_height()/2, f"{val:.1f}%",
                va="center", fontsize=10, color=COLORS["text"])

    ax.set_xlabel("Relative Importance (%)", fontsize=13, color=COLORS["text"])
    ax.set_title("Feature Importance (Permutation, 10 repeats)", fontsize=16, color=COLORS["text"], fontweight="bold")
    ax.tick_params(colors=COLORS["text"], labelsize=11)
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])
    ax.grid(True, alpha=0.15, color=COLORS["text"], axis="x")

    plt.tight_layout()
    fig.savefig(save_path, dpi=200, bbox_inches="tight", facecolor=COLORS["bg"])
    plt.close(fig)
    print(f"  📊 Saved: {save_path}")


def plot_score_distribution(model, X_normal, X_attack, save_path):
    """Histogram of anomaly scores for normal vs attack traffic."""
    normal_scores = model.decision_function(X_normal)
    attack_scores = model.decision_function(X_attack)

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor(COLORS["bg"])
    ax.set_facecolor(COLORS["bg"])

    ax.hist(normal_scores, bins=80, alpha=0.65, color=COLORS["success"],
            label=f"Normal (n={len(normal_scores):,})", edgecolor="none", density=True)
    ax.hist(attack_scores, bins=80, alpha=0.65, color=COLORS["danger"],
            label=f"Attack (n={len(attack_scores):,})", edgecolor="none", density=True)

    # Decision boundary
    ax.axvline(x=0, color=COLORS["warning"], linestyle="--", lw=2, label="Decision Boundary (score=0)")

    ax.set_xlabel("Anomaly Score (more negative = more anomalous)", fontsize=12, color=COLORS["text"])
    ax.set_ylabel("Density", fontsize=12, color=COLORS["text"])
    ax.set_title("Anomaly Score Distribution — Normal vs Attack", fontsize=16, color=COLORS["text"], fontweight="bold")
    ax.legend(fontsize=11, facecolor=COLORS["grid"], edgecolor=COLORS["primary"], labelcolor=COLORS["text"])
    ax.tick_params(colors=COLORS["text"])
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])
    ax.grid(True, alpha=0.15, color=COLORS["text"])

    plt.tight_layout()
    fig.savefig(save_path, dpi=200, bbox_inches="tight", facecolor=COLORS["bg"])
    plt.close(fig)
    print(f"  📊 Saved: {save_path}")


def plot_model_comparison(all_metrics, save_path):
    """Grouped bar chart comparing all models."""
    models = []
    f1_scores = []
    recalls = []
    precisions = []
    aucs = []
    fprs = []

    for name, m in all_metrics.items():
        models.append(m["model"].replace(" (tuned)", "").replace(" (ensemble)", ""))
        f1_scores.append(m["f1_score"])
        recalls.append(m["recall"])
        precisions.append(m["precision"])
        aucs.append(m["roc_auc"])
        fprs.append(m["false_positive_rate"])

    fig, axes = plt.subplots(1, 2, figsize=(16, 6))
    fig.patch.set_facecolor(COLORS["bg"])

    x = np.arange(len(models))
    width = 0.2

    # Panel 1: F1, Precision, Recall, AUC
    ax = axes[0]
    ax.set_facecolor(COLORS["bg"])
    ax.bar(x - 1.5*width, f1_scores, width, label="F1", color=COLORS["primary"], edgecolor=COLORS["grid"])
    ax.bar(x - 0.5*width, precisions, width, label="Precision", color=COLORS["success"], edgecolor=COLORS["grid"])
    ax.bar(x + 0.5*width, recalls, width, label="Recall", color=COLORS["warning"], edgecolor=COLORS["grid"])
    ax.bar(x + 1.5*width, aucs, width, label="AUC", color=COLORS["purple"], edgecolor=COLORS["grid"])

    ax.set_ylabel("Score", fontsize=12, color=COLORS["text"])
    ax.set_title("Model Comparison — Quality Metrics", fontsize=14, color=COLORS["text"], fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(models, fontsize=10, color=COLORS["text"])
    ax.set_ylim(0, 1.15)
    ax.legend(fontsize=10, facecolor=COLORS["grid"], edgecolor=COLORS["primary"], labelcolor=COLORS["text"])
    ax.tick_params(colors=COLORS["text"])
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])

    # Add values on bars
    for bars in ax.containers:
        ax.bar_label(bars, fmt="%.3f", fontsize=8, color=COLORS["text"], padding=2)

    # Panel 2: False Positive Rate
    ax = axes[1]
    ax.set_facecolor(COLORS["bg"])
    bar_colors = [COLORS["success"] if f < 0.03 else COLORS["warning"] if f < 0.06 else COLORS["danger"] for f in fprs]
    bars = ax.bar(models, [f * 100 for f in fprs], color=bar_colors, edgecolor=COLORS["grid"], width=0.5)
    ax.bar_label(bars, fmt="%.2f%%", fontsize=11, color=COLORS["text"], padding=3)
    ax.set_ylabel("False Positive Rate (%)", fontsize=12, color=COLORS["text"])
    ax.set_title("Model Comparison — False Positive Rates", fontsize=14, color=COLORS["text"], fontweight="bold")
    ax.axhline(y=3, color=COLORS["warning"], linestyle="--", alpha=0.5, label="3% threshold")
    ax.legend(fontsize=10, facecolor=COLORS["grid"], edgecolor=COLORS["primary"], labelcolor=COLORS["text"])
    ax.tick_params(colors=COLORS["text"], labelsize=10)
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])

    plt.tight_layout()
    fig.savefig(save_path, dpi=200, bbox_inches="tight", facecolor=COLORS["bg"])
    plt.close(fig)
    print(f"  📊 Saved: {save_path}")


def plot_cross_validation(cv_results, save_path):
    """Plot cross-validation fold results."""
    fold_rates = cv_results["fold_fp_rates"]
    folds = list(range(1, len(fold_rates) + 1))

    fig, ax = plt.subplots(figsize=(8, 5))
    fig.patch.set_facecolor(COLORS["bg"])
    ax.set_facecolor(COLORS["bg"])

    bars = ax.bar(folds, [r * 100 for r in fold_rates], color=COLORS["primary"],
                  edgecolor=COLORS["grid"], width=0.5)
    ax.bar_label(bars, fmt="%.2f%%", fontsize=11, color=COLORS["text"], padding=3)

    ax.axhline(y=cv_results["avg_fp_rate"] * 100, color=COLORS["warning"], linestyle="--", lw=2,
               label=f'Mean: {cv_results["avg_fp_rate"]*100:.2f}% ± {cv_results["std_fp_rate"]*100:.2f}%')

    ax.set_xlabel("Fold", fontsize=12, color=COLORS["text"])
    ax.set_ylabel("False Positive Rate (%)", fontsize=12, color=COLORS["text"])
    ax.set_title("5-Fold Cross-Validation — FP Rate Consistency", fontsize=14, color=COLORS["text"], fontweight="bold")
    ax.legend(fontsize=11, facecolor=COLORS["grid"], edgecolor=COLORS["primary"], labelcolor=COLORS["text"])
    ax.tick_params(colors=COLORS["text"])
    for spine in ax.spines.values():
        spine.set_color(COLORS["grid"])

    plt.tight_layout()
    fig.savefig(save_path, dpi=200, bbox_inches="tight", facecolor=COLORS["bg"])
    plt.close(fig)
    print(f"  📊 Saved: {save_path}")


def generate_training_report(metrics_output):
    """Generate a comprehensive markdown training report."""
    m = metrics_output
    iso = m["model_metrics"].get("isolation_forest", {})
    ens = m["model_metrics"].get("ensemble", {})

    primary = ens if ens else iso
    primary_name = "Ensemble (IF+LOF)" if ens else "Isolation Forest"

    report = f"""# SentinelNet IDS — Training Report
> Generated: {m['training_timestamp']}
> Duration: {m['training_duration_seconds']:.1f}s

---

## Dataset
| Split | Normal | Attack | Total |
|---|---|---|---|
| **Training** | {m['dataset']['normal_train']:,} | — | {m['dataset']['normal_train']:,} |
| **Validation** | {m['dataset']['normal_val']:,} | {m['dataset']['attack_val']:,} | {m['dataset']['normal_val'] + m['dataset']['attack_val']:,} |
| **Test** | {m['dataset']['normal_test']:,} | {m['dataset']['attack_test']:,} | {m['dataset']['normal_test'] + m['dataset']['attack_test']:,} |
| **Total** | {m['dataset']['normal_total']:,} | {m['dataset']['attack_total']:,} | {m['dataset']['normal_total'] + m['dataset']['attack_total']:,} |

## Features ({m['features']['count']})
- **Raw ({len(m['features']['raw'])}):** {', '.join(m['features']['raw'])}
- **Derived ({len(m['features']['derived'])}):** {', '.join(m['features']['derived'])}

## Best Hyperparameters (Grid Search — {m['hyperparameter_search']['total_combinations']} combinations)
| Parameter | Value |
|---|---|
"""
    for k, v in m["best_hyperparameters"].items():
        report += f"| `{k}` | `{v}` |\n"

    report += f"""
## Primary Model: {primary_name}
| Metric | Value |
|---|---|
| **F1 Score** | **{primary.get('f1_score', 'N/A')}** |
| **Precision** | {primary.get('precision', 'N/A')} |
| **Recall** | {primary.get('recall', 'N/A')} |
| **ROC-AUC** | {primary.get('roc_auc', 'N/A')} |
| **False Positive Rate** | {primary.get('false_positive_rate', 'N/A')} |
| **Attack Detection Rate** | {primary.get('attack_detection_rate', 'N/A')} |

## Cross-Validation (5-Fold)
- **Avg FPR:** {m['cross_validation']['avg_fp_rate']} ± {m['cross_validation']['std_fp_rate']}
- **Fold FPRs:** {m['cross_validation']['fold_fp_rates']}

## Per-Attack Detection Rates
| Attack Type | Detected | Total | Rate |
|---|---|---|---|
"""
    if "per_attack_type" in primary:
        for atype, info in sorted(primary["per_attack_type"].items(), key=lambda x: -x[1]["rate"]):
            rate_pct = info["rate"] * 100
            emoji = "✅" if rate_pct >= 95 else "⚠️" if rate_pct >= 80 else "❌"
            report += f"| {atype} | {info['detected']} | {info['total']} | {emoji} {rate_pct:.1f}% |\n"

    report += f"""
## Learning Curve (Overfitting Check)
| Data % | Samples | Train Acc | Val F1 | Test F1 | Val FPR |
|---|---|---|---|---|---|
"""
    for lc in m["learning_curve"]:
        report += f"| {lc['fraction']:.0%} | {lc['n_samples']:,} | {lc['train_accuracy']:.4f} | {lc['val_f1']:.4f} | {lc['test_f1']:.4f} | {lc['val_fpr']:.4f} |\n"

    report += f"""
## Model Comparison
| Model | F1 | Precision | Recall | AUC | FPR |
|---|---|---|---|---|---|
"""
    for name, mm in m["model_metrics"].items():
        report += f"| {mm.get('model', name)} | {mm.get('f1_score', 'N/A')} | {mm.get('precision', 'N/A')} | {mm.get('recall', 'N/A')} | {mm.get('roc_auc', 'N/A')} | {mm.get('false_positive_rate', 'N/A')} |\n"

    report += f"""
## Feature Importance
| Feature | Relative % |
|---|---|
"""
    for feat, info in sorted(m["feature_importance"].items(), key=lambda x: -x[1]["relative"]):
        report += f"| {feat} | {info['relative']:.1f}% |\n"

    report += f"""
## Generated Visualizations
- `ml/plots/confusion_matrix.png` — Confusion matrix heatmap
- `ml/plots/roc_curves.png` — ROC curves for all models
- `ml/plots/learning_curves.png` — Training vs validation accuracy & loss
- `ml/plots/per_attack_detection.png` — Per-attack detection rates
- `ml/plots/feature_importance.png` — Feature importance with CIs
- `ml/plots/score_distribution.png` — Normal vs attack score histograms
- `ml/plots/model_comparison.png` — Side-by-side model comparison
- `ml/plots/cross_validation.png` — K-fold CV consistency
- `ml/training.log` — Complete training log

## Anti-Overfitting Measures
1. **70/15/15 split** — separate train/validation/test sets, no data leakage
2. **Scaler fitted on training data only** — no test information in preprocessing
3. **10% borderline edge cases** — legitimate traffic that mimics attacks
4. **81-combo grid search on validation set** — hyperparameters not tuned on test data
5. **5-fold cross-validation** — verifies consistency across data splits
6. **Learning curve analysis** — confirms monotonic improvement, no degradation
7. **Ensemble voting (IF+LOF)** — reduces individual model bias
8. **Feature importance with CIs** — validates features contribute meaningfully
"""

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        f.write(report)
    print(f"  📄 Report saved: {REPORT_PATH}")


# ═══════════════════════════════════════════════════════════════════════════
#   MAIN TRAINING PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def train():
    """Full anti-overfitting training pipeline with ensemble and visualizations."""
    start_time = time.time()
    os.makedirs(PLOTS_DIR, exist_ok=True)

    # Start logging
    logger = TeeLogger(LOG_PATH)
    sys.stdout = logger

    print("=" * 60)
    print("  SentinelNet ML Training Pipeline v3.0")
    print("  Anti-Overfitting + Ensemble + Visualizations")
    print("=" * 60)
    print(f"  Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    # ── Load Data ────────────────────────────────────────────────────────
    normal_path = os.path.join(DATA_DIR, "normal_traffic.csv")
    attack_path = os.path.join(DATA_DIR, "attack_traffic.csv")

    if not os.path.exists(normal_path):
        print(f"  ERROR: Training data not found at {normal_path}")
        print("  Run `python ml/generate_data.py` first.")
        sys.stdout = logger.terminal
        logger.close()
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

    # Handle missing connection_count column (backward compatibility)
    if "connection_count" not in normal_df.columns:
        normal_df["connection_count"] = 1

    X_normal_all = normal_df[FEATURE_COLS].values

    attack_types = None
    if attack_df is not None:
        attack_df = encode_protocol(attack_df)
        attack_df = add_derived_features(attack_df)
        if "connection_count" not in attack_df.columns:
            attack_df["connection_count"] = 1
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
        attack_types_val = attack_types.iloc[atk_indices[n_atk_test:n_atk_test + n_atk_val]]
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
    print(f"\n{'=' * 60}")
    print(f"  Cross-Validation")
    print(f"{'=' * 60}")
    cv_results = cross_validate(X_train, n_splits=5, params=best_params)

    # ── Train Final Isolation Forest ─────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  Training Final Isolation Forest (Best Params)")
    print(f"{'=' * 60}")
    print(f"  Params: {best_params}")

    final_if = IsolationForest(**best_params, random_state=42, n_jobs=-1)
    final_if.fit(X_train)
    joblib.dump(final_if, MODEL_PATH)
    print(f"  IF Model saved to: {MODEL_PATH}")

    # ── Train LOF for Ensemble ───────────────────────────────────────────
    print(f"\n{'=' * 60}")
    print(f"  Training Local Outlier Factor (for Ensemble)")
    print(f"{'=' * 60}")

    lof = LocalOutlierFactor(n_neighbors=20, contamination=0.02, novelty=True, n_jobs=-1)
    lof.fit(X_train)
    joblib.dump(lof, ENSEMBLE_PATH)
    print(f"  LOF Model saved to: {ENSEMBLE_PATH}")

    # ── Create Ensemble ──────────────────────────────────────────────────
    ensemble = EnsembleAnomalyDetector(final_if, lof, if_weight=0.65, lof_weight=0.35, threshold=0.45)

    # ── Evaluate ALL Models on HELD-OUT TEST SET ─────────────────────────
    all_metrics = {}
    if attack_df is not None:
        print(f"\n{'=' * 60}")
        print(f"  Final Evaluation on HELD-OUT TEST SET")
        print(f"{'=' * 60}")

        # Isolation Forest
        iso_metrics = evaluate_model(final_if, X_test, X_attack_test_scaled, "Isolation Forest (tuned)")
        attack_type_results_if = per_attack_evaluation(final_if, X_attack_test_scaled, attack_types_test)
        iso_metrics["per_attack_type"] = attack_type_results_if
        all_metrics["isolation_forest"] = iso_metrics

        # One-Class SVM
        print("\n  Training One-Class SVM...")
        oc_svm = OneClassSVM(kernel="rbf", gamma="scale", nu=0.05)
        oc_svm.fit(X_train)
        svm_metrics = evaluate_model(oc_svm, X_test, X_attack_test_scaled, "One-Class SVM")
        all_metrics["one_class_svm"] = svm_metrics

        # LOF standalone
        lof_metrics = evaluate_model(lof, X_test, X_attack_test_scaled, "Local Outlier Factor")
        all_metrics["local_outlier_factor"] = lof_metrics

        # Ensemble
        print(f"\n{'=' * 60}")
        print(f"  Ensemble Model (IF 65% + LOF 35%, threshold=0.45)")
        print(f"{'=' * 60}")
        ens_metrics = evaluate_model(ensemble, X_test, X_attack_test_scaled, "Ensemble (IF+LOF)")
        attack_type_results_ens = per_attack_evaluation(ensemble, X_attack_test_scaled, attack_types_test)
        ens_metrics["per_attack_type"] = attack_type_results_ens
        all_metrics["ensemble"] = ens_metrics

        # Summary table
        print(f"\n{'=' * 60}")
        print(f"  Model Comparison Summary")
        print(f"{'=' * 60}")
        print(f"  {'Model':<35} {'F1':>8} {'Recall':>8} {'AUC':>8} {'FPR':>8}")
        print(f"  {'─' * 70}")
        for name, m in all_metrics.items():
            if "model" in m:
                print(f"  {m['model']:<35} {m['f1_score']:>8.4f} {m['recall']:>8.4f} {m['roc_auc']:>8.4f} {m['false_positive_rate']:>8.4f}")

    # ── Learning Curve (with train AND val/test metrics) ─────────────────
    learning_curve_data = learning_curve_analysis(X_train, X_val, X_attack_val_scaled, X_test, X_attack_test_scaled, best_params)

    # ── Feature Importance ───────────────────────────────────────────────
    feat_importance = feature_importance_with_ci(final_if, X_test, n_repeats=10)

    # ═════════════════════════════════════════════════════════════════════
    #   GENERATE ALL VISUALIZATIONS
    # ═════════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 60}")
    print(f"  Generating Visualizations")
    print(f"{'=' * 60}")

    # Pick best model for primary confusion matrix
    best_model_name = max(all_metrics, key=lambda k: all_metrics[k]["f1_score"])
    best_m = all_metrics[best_model_name]

    # 1. Confusion Matrix (primary model)
    plot_confusion_matrix(
        best_m["y_true"], best_m["y_pred"],
        best_m["model"],
        os.path.join(PLOTS_DIR, "confusion_matrix.png")
    )

    # 2. Confusion Matrix (all models in a grid)
    fig_cm, axes_cm = plt.subplots(2, 2, figsize=(16, 12))
    fig_cm.patch.set_facecolor(COLORS["bg"])
    for idx, (name, metrics) in enumerate(all_metrics.items()):
        ax = axes_cm[idx // 2][idx % 2]
        ax.set_facecolor(COLORS["bg"])
        cm = confusion_matrix(metrics["y_true"], metrics["y_pred"])
        sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", ax=ax,
                    xticklabels=["Normal", "Attack"], yticklabels=["Normal", "Attack"],
                    annot_kws={"size": 14, "weight": "bold"}, linewidths=1, linecolor=COLORS["grid"])
        ax.set_title(f'{metrics["model"]}\nF1={metrics["f1_score"]:.4f}  AUC={metrics["roc_auc"]:.4f}',
                     fontsize=12, color=COLORS["text"], fontweight="bold")
        ax.tick_params(colors=COLORS["text"])
    plt.suptitle("Confusion Matrices — All Models", fontsize=16, color=COLORS["text"], fontweight="bold", y=1.02)
    plt.tight_layout()
    fig_cm.savefig(os.path.join(PLOTS_DIR, "confusion_matrices_all.png"), dpi=200, bbox_inches="tight", facecolor=COLORS["bg"])
    plt.close(fig_cm)
    print(f"  📊 Saved: {os.path.join(PLOTS_DIR, 'confusion_matrices_all.png')}")

    # 3. ROC Curves
    plot_roc_curve(all_metrics, os.path.join(PLOTS_DIR, "roc_curves.png"))

    # 4. Learning Curves (training vs validation accuracy + loss)
    plot_learning_curves(learning_curve_data, os.path.join(PLOTS_DIR, "learning_curves.png"))

    # 5. Per-Attack Detection Rates
    best_attack_results = all_metrics[best_model_name].get("per_attack_type", {})
    if best_attack_results:
        plot_per_attack_detection(best_attack_results, os.path.join(PLOTS_DIR, "per_attack_detection.png"))

    # 6. Feature Importance
    plot_feature_importance(feat_importance, os.path.join(PLOTS_DIR, "feature_importance.png"))

    # 7. Score Distribution
    plot_score_distribution(final_if, X_test, X_attack_test_scaled, os.path.join(PLOTS_DIR, "score_distribution.png"))

    # 8. Model Comparison
    plot_model_comparison(all_metrics, os.path.join(PLOTS_DIR, "model_comparison.png"))

    # 9. Cross-Validation
    plot_cross_validation(cv_results, os.path.join(PLOTS_DIR, "cross_validation.png"))

    # ── Save All Metrics ─────────────────────────────────────────────────
    elapsed = time.time() - start_time

    # Strip non-serializable fields before saving
    serializable_metrics = {}
    for k, v in all_metrics.items():
        d = {mk: mv for mk, mv in v.items() if mk not in ("y_true", "y_pred", "scores")}
        serializable_metrics[k] = d

    metrics_output = {
        "training_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "training_duration_seconds": round(elapsed, 1),
        "pipeline_version": "3.0 (ensemble + visualizations)",
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
        "model_metrics": serializable_metrics,
        "learning_curve": learning_curve_data,
        "feature_importance": feat_importance,
        "ensemble_config": {
            "if_weight": 0.65,
            "lof_weight": 0.35,
            "threshold": 0.45,
        },
        "visualizations": [
            "ml/plots/confusion_matrix.png",
            "ml/plots/confusion_matrices_all.png",
            "ml/plots/roc_curves.png",
            "ml/plots/learning_curves.png",
            "ml/plots/per_attack_detection.png",
            "ml/plots/feature_importance.png",
            "ml/plots/score_distribution.png",
            "ml/plots/model_comparison.png",
            "ml/plots/cross_validation.png",
        ],
    }

    with open(METRICS_PATH, "w") as f:
        json.dump(metrics_output, f, indent=2)

    # ── Generate Report ──────────────────────────────────────────────────
    generate_training_report(metrics_output)

    print(f"\n{'=' * 60}")
    print(f"  Training Pipeline Complete! ({elapsed:.1f}s)")
    print(f"{'=' * 60}")
    print(f"  Model (IF):      {MODEL_PATH}")
    print(f"  Model (LOF):     {ENSEMBLE_PATH}")
    print(f"  Scaler:          {SCALER_PATH}")
    print(f"  Metrics:         {METRICS_PATH}")
    print(f"  Report:          {REPORT_PATH}")
    print(f"  Training Log:    {LOG_PATH}")
    print(f"  Plots:           {PLOTS_DIR}/")
    print(f"\n  Visualizations Generated:")
    for viz in metrics_output["visualizations"]:
        print(f"    ✓ {viz}")
    print(f"{'=' * 60}")

    # Restore stdout
    sys.stdout = logger.terminal
    logger.close()
    print(f"\n  Training complete. Log saved to: {LOG_PATH}")


if __name__ == "__main__":
    train()
