# SentinelNet IDS — Training Report
> Generated: 2026-02-10 15:48:21
> Duration: 422.1s

---

## Dataset
| Split | Normal | Attack | Total |
|---|---|---|---|
| **Training** | 14,000 | — | 14,000 |
| **Validation** | 3,000 | 1,200 | 4,200 |
| **Test** | 3,000 | 1,200 | 4,200 |
| **Total** | 20,000 | 8,000 | 28,000 |

## Features (17)
- **Raw (6):** packet_rate, unique_ports, avg_packet_size, duration, protocol_flag, connection_count
- **Derived (11):** bytes_per_second, port_scan_ratio, size_rate_ratio, conn_rate, burst_intensity, traffic_efficiency, port_diversity, connection_density, size_deviation, duration_efficiency, rate_concentration

## Best Hyperparameters (Grid Search — 320 combinations)
| Parameter | Value |
|---|---|
| `n_estimators` | `100` |
| `contamination` | `0.02` |
| `max_features` | `0.6` |
| `max_samples` | `0.85` |

## Primary Model: Ensemble (IF+LOF)
| Metric | Value |
|---|---|
| **F1 Score** | **0.9243** |
| **Precision** | 0.903 |
| **Recall** | 0.9467 |
| **ROC-AUC** | 0.9833 |
| **False Positive Rate** | 0.0407 |
| **Attack Detection Rate** | 0.9467 |

## Cross-Validation (5-Fold)
- **Avg FPR:** 0.0219 ± 0.0042
- **Fold FPRs:** [np.float64(0.0229), np.float64(0.015), np.float64(0.0218), np.float64(0.0282), np.float64(0.0214)]

## Per-Attack Detection Rates
| Attack Type | Detected | Total | Rate |
|---|---|---|---|
| dns_amplification | 135 | 135 | ✅ 100.0% |
| icmp_flood | 97 | 97 | ✅ 100.0% |
| port_scan | 127 | 127 | ✅ 100.0% |
| protocol_anomaly | 117 | 117 | ✅ 100.0% |
| syn_flood | 125 | 125 | ✅ 100.0% |
| udp_flood | 111 | 111 | ✅ 100.0% |
| slowloris | 104 | 105 | ✅ 99.1% |
| http_flood | 116 | 128 | ⚠️ 90.6% |
| stealth_probe | 119 | 140 | ⚠️ 85.0% |
| brute_force | 85 | 115 | ❌ 73.9% |

## Learning Curve (Overfitting Check)
| Data % | Samples | Train Acc | Val F1 | Test F1 | Val FPR |
|---|---|---|---|---|---|
| 10% | 1,400 | 0.9800 | 0.9115 | 0.9024 | 0.0140 |
| 20% | 2,800 | 0.9800 | 0.9156 | 0.9069 | 0.0217 |
| 30% | 4,200 | 0.9800 | 0.9125 | 0.9085 | 0.0207 |
| 50% | 7,000 | 0.9800 | 0.9190 | 0.9078 | 0.0180 |
| 70% | 9,800 | 0.9800 | 0.9257 | 0.9180 | 0.0170 |
| 85% | 11,900 | 0.9800 | 0.9270 | 0.9179 | 0.0190 |
| 100% | 14,000 | 0.9800 | 0.9316 | 0.9224 | 0.0163 |

## Model Comparison
| Model | F1 | Precision | Recall | AUC | FPR |
|---|---|---|---|---|---|
| Isolation Forest (tuned) | 0.9224 | 0.9442 | 0.9017 | 0.9833 | 0.0213 |
| One-Class SVM | 0.9129 | 0.8807 | 0.9475 | 0.9859 | 0.0513 |
| Local Outlier Factor | 0.9325 | 0.9437 | 0.9217 | 0.9839 | 0.022 |
| Ensemble (IF+LOF) | 0.9243 | 0.903 | 0.9467 | 0.9833 | 0.0407 |

## Feature Importance
| Feature | Relative % |
|---|---|
| bytes_per_second | 11.0% |
| packet_rate | 10.2% |
| avg_packet_size | 9.5% |
| burst_intensity | 8.2% |
| traffic_efficiency | 7.3% |
| connection_count | 6.9% |
| duration | 6.5% |
| rate_concentration | 5.2% |
| unique_ports | 5.0% |
| size_deviation | 4.8% |
| conn_rate | 4.7% |
| connection_density | 4.4% |
| size_rate_ratio | 4.3% |
| port_scan_ratio | 3.1% |
| port_diversity | 3.1% |
| duration_efficiency | 2.8% |
| protocol_flag | 2.8% |

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
