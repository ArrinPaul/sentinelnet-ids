# ML Model Comparison: Simple vs Realistic Datasets

## Executive Summary

SentinelNet IDS now supports **two difficulty modes** to balance learning demonstration vs real-world accuracy:

| Mode | F1 Score | Use Case | Brute Force Detection | FPR |
|------|----------|----------|----------------------|-----|
| **Simple** | 98.51% | Proof of concept, learning pipeline | 100% | 1.0% |
| **Realistic** | 91.31% | Production testing, real-world eval | 49.6% | 2.33% |

---

## Dataset Comparison

### Feature Distribution Overlap

| Feature | Simple Mode | Realistic Mode |
|---------|-------------|----------------|
| **packet_rate** | 12.0% overlap | 16.7% overlap |
| **unique_ports** | 4.6% overlap | 6.6% overlap |
| **connection_count** | 3.6% overlap | **23.7% overlap** ✓ |
| **duration** | 33.3% overlap | 33.3% overlap |

### Attacks Within Normal Ranges

| Feature | Simple Mode | Realistic Mode |
|---------|-------------|----------------|
| **packet_rate** | 50.5% | 60.1% |
| **unique_ports** | 72.6% | 76.1% |
| **connection_count** | **14.3%** | **72.2%** ✓ |
| **duration** | 87.0% | 93.0% |

### Simple Rule Detection

| Mode | Detectable by `connection_count > threshold` | Verdict |
|------|---------------------------------------------|---------|
| **Simple** | 91.5% (threshold = 13) | ⚠️ TOO EASY |
| **Realistic** | 68.4% (threshold = 33) | ✓ REALISTIC |

---

## Model Performance

### Overall Metrics

| Metric | Simple Mode | Realistic Mode | Change |
|--------|-------------|----------------|--------|
| **F1 Score** | 0.9851 | 0.9131 | **-7.2%** |
| **Precision** | 0.9755 | 0.9384 | -3.7% |
| **Recall** | 0.9950 | 0.8892 | **-10.6%** |
| **AUC** | 0.9991 | 0.9805 | -1.9% |
| **False Positive Rate** | 1.0% | 2.33% | +133% |

### Per-Attack Type Detection

| Attack Type | Simple Mode | Realistic Mode | Change |
|-------------|-------------|----------------|--------|
| **brute_force** | 100.0% | **49.6%** | **-50.4%** ✗ |
| **stealth_probe** | 99.3% | **76.4%** | **-23.0%** △ |
| **slowloris** | 100.0% | 82.9% | -17.1% △ |
| **protocol_anomaly** | 96.6% | 94.0% | -2.6% ✓ |
| **http_flood** | 99.2% | 89.8% | -9.4% ✓ |
| **dns_amplification** | 100.0% | 97.0% | -3.0% ✓ |
| **port_scan** | 100.0% | 100.0% | 0.0% ✓ |
| **syn_flood** | 100.0% | 100.0% | 0.0% ✓ |
| **udp_flood** | 100.0% | 100.0% | 0.0% ✓ |
| **icmp_flood** | 100.0% | 100.0% | 0.0% ✓ |

---

## Key Differences in Data Generation

### Normal Traffic Changes (Realistic Mode)

**Edge Cases Profile (10% of normal traffic):**
- Added high connection counts: **20-120 connections** (vs 1-20 in simple)
- Higher packet rates: **up to 2,500 pkt/s** (vs 1,800 in simple)
- Simulates: Bulk operations, automated systems, server tasks, microservices

### Attack Traffic Changes (Realistic Mode)

**Brute Force:**
- Simple: 50-500 connections (always detectable)
- Realistic: **Mix of aggressive (50-400) + stealthy (8-50)**
  - 50% of brute force attacks now overlap with normal traffic!

**Slowloris:**
- Simple: 30-200 connections
- Realistic: **15-100 connections** (overlaps with normal edge cases)

**Stealth Probe:**
- Simple: 5-60 unique ports
- Realistic: **5-100 ports** with wider packet_rate range
- Now mimics normal traffic more closely

**Protocol Anomaly:**
- Simple: 2-200 unique ports
- Realistic: **1-120 ports** (some very low, harder to detect)

---

## Training Pipeline Differences

### Hyperparameter Search Results

| Parameter | Simple Mode | Realistic Mode |
|-----------|-------------|----------------|
| **contamination** | 0.01 (1%) | **0.02 (2%)** |
| **n_estimators** | 100 | 100 |
| **max_features** | 0.75 | **1.0** |
| **max_samples** | 0.5 | **0.75** |

**Insight:** Realistic mode requires higher contamination and more features/samples to capture subtle patterns.

### Cross-Validation FPR

| Mode | Average FPR | Std Dev |
|------|-------------|---------|
| Simple | 1.08% | ±0.24% |
| Realistic | **2.39%** | ±0.20% |

### Feature Importance Changes

**Simple Mode Top 3:**
1. bytes_per_second (15.6%)
2. packet_rate (13.7%)
3. avg_packet_size (12.7%)

**Realistic Mode Top 3:**
1. bytes_per_second (17.4%)
2. packet_rate (16.2%)
3. avg_packet_size (13.3%)

**Change:** Higher importance on derived features in realistic mode.

---

## File Structure

```
data/
├── simple/                          # Original dataset (98.5% F1)
│   ├── normal_traffic.csv
│   └── attack_traffic.csv
└── realistic/                       # New realistic dataset (91.3% F1)
    ├── normal_traffic.csv
    └── attack_traffic.csv

ml/
├── generate_data.py                 # Updated with difficulty modes
├── train_model.py                   # Updated with difficulty modes
├── compare_datasets.py              # Comparative analysis script
└── results/
    ├── simple/                      # Simple mode results
    │   ├── model.pkl
    │   ├── ensemble_lof.pkl
    │   ├── scaler.pkl
    │   ├── training_metrics.json
    │   ├── TRAINING_REPORT.md
    │   ├── training.log
    │   └── plots/                   # 9 visualization PNGs
    └── realistic/                   # Realistic mode results
        ├── model.pkl
        ├── ensemble_lof.pkl
        ├── scaler.pkl
        ├── training_metrics.json
        ├── TRAINING_REPORT.md
        ├── training.log
        └── plots/                   # 9 visualization PNGs
```

---

## Usage

### Generate Data

```bash
# Simple mode (default)
python ml/generate_data.py

# Realistic mode
python ml/generate_data.py realistic
```

### Train Model

```bash
# Simple mode (default)
python ml/train_model.py

# Realistic mode
python ml/train_model.py realistic
```

### Compare Datasets

```bash
python ml/compare_datasets.py
```

---

## Recommendations

### Use **Simple Mode** when:
- ✓ Learning the ML pipeline
- ✓ Demonstrating proof of concept
- ✓ Teaching IDS fundamentals
- ✓ Rapid prototyping
- ✓ Verifying code changes work

### Use **Realistic Mode** when:
- ✓ Production deployment preparation
- ✓ Real-world performance evaluation
- ✓ Stress-testing detection algorithms
- ✓ Benchmarking improvements
- ✓ Academic research / publications

---

## Honest Assessment

### Simple Mode Issues
- **91.5% of attacks** detectable by trivial rule: `connection_count > 13`
- Problem is **too clean** for real-world scenarios
- High accuracy is **artificial** due to clear feature separation
- Still valuable as a **learning tool** and **pipeline demonstration**

### Realistic Mode Improvements
- **Only 68.4%** easily detectable (down from 91.5%)
- **72.2%** of attacks have connection_counts overlapping normal range
- **Brute force attacks** now genuinely challenging (50% stealthy variants)
- **Stealth probes** blend in with normal microservice traffic
- Accuracy drop (~7%) reflects **real-world difficulty**

---

## Future Work

### Possible Enhancements
1. **Add "hard" difficulty mode**: Even more overlap, adversarial attacks
2. **Time-series features**: Detect patterns over time windows
3. **Ensemble improvements**: Try XGBoost, Random Forest for comparison
4. **Online learning**: Adapt to evolving attack patterns
5. **Explainability**: SHAP values for per-prediction explanations

---

**Generated:** 2026-02-10  
**Version:** v3.0 (Dual-Mode)  
**Training Time:** Simple (72.8s) | Realistic (106.2s)
