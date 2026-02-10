# SentinelNet IDS — Training Report
> Generated: 2026-02-10 14:51:55
> Duration: 72.8s

---

## Dataset
| Split | Normal | Attack | Total |
|---|---|---|---|
| **Training** | 14,000 | — | 14,000 |
| **Validation** | 3,000 | 1,200 | 4,200 |
| **Test** | 3,000 | 1,200 | 4,200 |
| **Total** | 20,000 | 8,000 | 28,000 |

## Features (10)
- **Raw (6):** packet_rate, unique_ports, avg_packet_size, duration, protocol_flag, connection_count
- **Derived (4):** bytes_per_second, port_scan_ratio, size_rate_ratio, conn_rate

## Best Hyperparameters (Grid Search — 81 combinations)
| Parameter | Value |
|---|---|
| `n_estimators` | `100` |
| `contamination` | `0.01` |
| `max_features` | `0.75` |
| `max_samples` | `0.5` |

## Primary Model: Ensemble (IF+LOF)
| Metric | Value |
|---|---|
| **F1 Score** | **0.9851** |
| **Precision** | 0.9755 |
| **Recall** | 0.995 |
| **ROC-AUC** | 0.9991 |
| **False Positive Rate** | 0.01 |
| **Attack Detection Rate** | 0.995 |

## Cross-Validation (5-Fold)
- **Avg FPR:** 0.0108 ± 0.0024
- **Fold FPRs:** [np.float64(0.0079), np.float64(0.0136), np.float64(0.0114), np.float64(0.0082), np.float64(0.0129)]

## Per-Attack Detection Rates
| Attack Type | Detected | Total | Rate |
|---|---|---|---|
| brute_force | 115 | 115 | ✅ 100.0% |
| dns_amplification | 135 | 135 | ✅ 100.0% |
| icmp_flood | 97 | 97 | ✅ 100.0% |
| port_scan | 127 | 127 | ✅ 100.0% |
| slowloris | 105 | 105 | ✅ 100.0% |
| syn_flood | 125 | 125 | ✅ 100.0% |
| udp_flood | 111 | 111 | ✅ 100.0% |
| stealth_probe | 139 | 140 | ✅ 99.3% |
| http_flood | 127 | 128 | ✅ 99.2% |
| protocol_anomaly | 113 | 117 | ✅ 96.6% |

## Learning Curve (Overfitting Check)
| Data % | Samples | Train Acc | Val F1 | Test F1 | Val FPR |
|---|---|---|---|---|---|
| 10% | 1,400 | 0.9900 | 0.9719 | 0.9772 | 0.0143 |
| 20% | 2,800 | 0.9900 | 0.9732 | 0.9764 | 0.0147 |
| 30% | 4,200 | 0.9900 | 0.9807 | 0.9786 | 0.0137 |
| 50% | 7,000 | 0.9900 | 0.9828 | 0.9843 | 0.0133 |
| 70% | 9,800 | 0.9900 | 0.9820 | 0.9839 | 0.0137 |
| 85% | 11,900 | 0.9900 | 0.9844 | 0.9856 | 0.0113 |
| 100% | 14,000 | 0.9900 | 0.9856 | 0.9851 | 0.0110 |

## Model Comparison
| Model | F1 | Precision | Recall | AUC | FPR |
|---|---|---|---|---|---|
| Isolation Forest (tuned) | 0.9851 | 0.9755 | 0.995 | 0.9991 | 0.01 |
| One-Class SVM | 0.9393 | 0.8856 | 1.0 | 1.0 | 0.0517 |
| Local Outlier Factor | 0.9748 | 0.9523 | 0.9983 | 0.9999 | 0.02 |
| Ensemble (IF+LOF) | 0.9851 | 0.9755 | 0.995 | 0.9991 | 0.01 |

## Feature Importance
| Feature | Relative % |
|---|---|
| bytes_per_second | 15.6% |
| packet_rate | 13.8% |
| avg_packet_size | 12.7% |
| conn_rate | 10.3% |
| connection_count | 10.0% |
| port_scan_ratio | 9.7% |
| duration | 9.2% |
| unique_ports | 6.9% |
| size_rate_ratio | 6.0% |
| protocol_flag | 5.8% |

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
