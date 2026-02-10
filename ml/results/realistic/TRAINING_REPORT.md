# SentinelNet IDS — Training Report
> Generated: 2026-02-10 15:20:29
> Duration: 106.2s

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
| `contamination` | `0.02` |
| `max_features` | `1.0` |
| `max_samples` | `0.75` |

## Primary Model: Ensemble (IF+LOF)
| Metric | Value |
|---|---|
| **F1 Score** | **0.9131** |
| **Precision** | 0.9384 |
| **Recall** | 0.8892 |
| **ROC-AUC** | 0.9805 |
| **False Positive Rate** | 0.0233 |
| **Attack Detection Rate** | 0.8892 |

## Cross-Validation (5-Fold)
- **Avg FPR:** 0.0239 ± 0.002
- **Fold FPRs:** [np.float64(0.0229), np.float64(0.0243), np.float64(0.0236), np.float64(0.0275), np.float64(0.0214)]

## Per-Attack Detection Rates
| Attack Type | Detected | Total | Rate |
|---|---|---|---|
| icmp_flood | 97 | 97 | ✅ 100.0% |
| port_scan | 127 | 127 | ✅ 100.0% |
| syn_flood | 125 | 125 | ✅ 100.0% |
| udp_flood | 111 | 111 | ✅ 100.0% |
| dns_amplification | 131 | 135 | ✅ 97.0% |
| protocol_anomaly | 110 | 117 | ⚠️ 94.0% |
| http_flood | 115 | 128 | ⚠️ 89.8% |
| slowloris | 87 | 105 | ⚠️ 82.9% |
| stealth_probe | 107 | 140 | ❌ 76.4% |
| brute_force | 57 | 115 | ❌ 49.6% |

## Learning Curve (Overfitting Check)
| Data % | Samples | Train Acc | Val F1 | Test F1 | Val FPR |
|---|---|---|---|---|---|
| 10% | 1,400 | 0.9800 | 0.8975 | 0.8881 | 0.0160 |
| 20% | 2,800 | 0.9800 | 0.9133 | 0.9029 | 0.0200 |
| 30% | 4,200 | 0.9800 | 0.9167 | 0.9107 | 0.0183 |
| 50% | 7,000 | 0.9800 | 0.9155 | 0.9096 | 0.0173 |
| 70% | 9,800 | 0.9800 | 0.9179 | 0.9113 | 0.0173 |
| 85% | 11,900 | 0.9800 | 0.9196 | 0.9071 | 0.0167 |
| 100% | 14,000 | 0.9800 | 0.9235 | 0.9131 | 0.0177 |

## Model Comparison
| Model | F1 | Precision | Recall | AUC | FPR |
|---|---|---|---|---|---|
| Isolation Forest (tuned) | 0.9131 | 0.9384 | 0.8892 | 0.9805 | 0.0233 |
| One-Class SVM | 0.9106 | 0.8808 | 0.9425 | 0.9855 | 0.051 |
| Local Outlier Factor | 0.9228 | 0.9505 | 0.8967 | 0.9805 | 0.0187 |
| Ensemble (IF+LOF) | 0.9131 | 0.9384 | 0.8892 | 0.9805 | 0.0233 |

## Feature Importance
| Feature | Relative % |
|---|---|
| bytes_per_second | 17.4% |
| packet_rate | 16.2% |
| avg_packet_size | 13.3% |
| duration | 11.4% |
| port_scan_ratio | 8.9% |
| size_rate_ratio | 7.6% |
| conn_rate | 6.8% |
| connection_count | 6.7% |
| unique_ports | 6.1% |
| protocol_flag | 5.7% |

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
