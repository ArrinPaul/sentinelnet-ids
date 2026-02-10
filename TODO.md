# TODO.md — Implementation & Improvement Checklist
## SentinelNet IDS — Intelligent Traffic Control and Intrusion Prevention Network

> Track implementation progress and improvements phase by phase.  
> Mark items with `[x]` when completed.  
> Last updated: **2026-02-10**

---

## Project Stats

| Component | Status | Key Metric |
|---|---|---|
| **ML Dataset** | ✅ Complete | 20,000 normal + 8,000 attack (28K total) |
| **ML Model** | ✅ v3.0 | F1=0.9851, AUC=0.9991, FPR=1.0% |
| **Ensemble** | ✅ IF+LOF | Weighted voting (65/35), all attacks ≥96.6% |
| **Rule IDS** | ✅ Enhanced | 6 detection rules, configurable thresholds |
| **Fusion Engine** | ✅ Enhanced | Weighted scoring, alert deduplication |
| **Backend API** | ✅ Enhanced | 12 endpoints, config/clear/stats |
| **Frontend** | ✅ Redesigned | NOC aesthetic, 4 pages, motion animations |
| **Visualizations** | ✅ Complete | 9 PNG plots in ml/plots/ |
| **Training Logs** | ✅ Complete | ml/training.log |
| **GitHub** | ✅ Pushed | All artifacts tracked (model, data, metrics, plots) |

---

## PHASE 1: Project Setup & Architecture ✅
- [x] Create full folder structure as per ROADMAP
- [x] Initialize Python virtual environment
- [x] Create `requirements.txt` with all backend/ML dependencies
- [x] Initialize React app with Vite
- [x] Install frontend dependencies (axios, recharts, tailwindcss, motion, lucide-react)
- [x] Create `__init__.py` files for all Python packages
- [x] Define traffic feature schema (JSON)
- [x] Define alert severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
- [x] GitHub repository configured and all code pushed
- [ ] Create architecture diagram (Mermaid in README)

---

## PHASE 2: Traffic Data Ingestion Module ✅
- [x] Create `backend/main.py` — FastAPI app with CORS
- [x] Pydantic models with validation (IP, positive numbers, protocols)
- [x] `POST /traffic/ingest` endpoint
- [x] In-memory traffic store with max capacity
- [x] `GET /traffic/recent` — return last N records
- [x] Logging for ingested traffic
- [x] `connection_count` field added to traffic model

---

## PHASE 3: Rule-Based IDS ✅
- [x] Configurable thresholds for port scan, flood, protocol anomaly
- [x] `detect_port_scan()`, `detect_flood()`, `detect_protocol_anomaly()`
- [x] `detect_syn_flood()` — TCP + high rate + tiny packets + short duration
- [x] `detect_slowloris()` — TCP + low rate + very long duration
- [x] `detect_dns_amplification()` — UDP + high rate + large packets
- [x] Combined `analyze()` returning highest severity alert + all_rules_triggered
- [x] Thresholds configurable via API (GET/PUT `/system/config`)
- [ ] Add brute force detection (many connections to same dst, same port)
- [ ] Add rate-based sliding window (track per-IP rates over time)
- [ ] Write unit tests for each detection rule

---

## PHASE 4: ML-Based Anomaly Detection ✅

### Dataset (v3.0 — Anti-Overfitting)
- [x] **20,000 normal rows** across 7 traffic profiles
  - Web browsing (45%), Streaming (18%), DNS (12%), ICMP (5%)
  - **Edge cases (10%)** — borderline traffic that looks suspicious but is legitimate
  - IoT/Sensor (5%), Database/API (5%)
- [x] **8,000 attack rows** across 10 subtypes (800 each)
  - Port Scan, SYN Flood, UDP Flood, Slowloris, DNS Amplification
  - Protocol Anomaly, Brute Force, ICMP Flood, HTTP Flood, Stealthy Probe
- [x] **connection_count** feature added — differentiates brute force attacks
- [x] Datasets saved as CSV and tracked in git (`data/`)

### Training Pipeline (v3.0 — Ensemble + Visualizations)
- [x] **10 features**: 6 raw + 4 derived (`bytes_per_second`, `port_scan_ratio`, `size_rate_ratio`, `conn_rate`)
- [x] **StandardScaler** fitted on training data only (saved to `ml/scaler.pkl`)
- [x] **Proper train/validation/test split** — 70/15/15 (14K train, 3K val, 3K test)
- [x] **Hyperparameter grid search** — 81 combinations on validation set
  - Best: `n_estimators=100, contamination=0.01, max_features=0.75, max_samples=0.5`
- [x] **5-fold cross-validation** — FPR: 0.0108 ± 0.0024
- [x] **Learning curve analysis** — F1 stable/improving, no overfitting (train-test gap=0.0)
- [x] **Feature importance** with confidence intervals (10 permutation repeats)
- [x] **Model comparison**: Isolation Forest vs One-Class SVM vs LOF vs Ensemble
- [x] **Ensemble model**: IF (65%) + LOF (35%) weighted voting
- [x] **Training logs** saved to `ml/training.log`

### Test Results (Held-Out Test Set — v3.0)
- [x] **F1 Score: 0.9851** | Precision: 0.9755 | Recall: 0.9950
- [x] **ROC-AUC: 0.9991** | FPR: 1.0%
- [x] **Per-attack detection rates** (ALL ≥ 96.6%):
  - Brute Force: **100%** ✅ (was 0% in v2.0, now fixed with connection_count + conn_rate)
  - Port Scan: 100% | ICMP Flood: 100% | DNS Amplification: 100%
  - SYN Flood: 100% | UDP Flood: 100% | Slowloris: 100%
  - Stealth Probe: 99.3% | HTTP Flood: 99.2% | Protocol Anomaly: 96.6%

### Visualizations (9 images in `ml/plots/`)
- [x] `confusion_matrix.png` — Primary model confusion matrix heatmap
- [x] `confusion_matrices_all.png` — All 4 models side-by-side
- [x] `roc_curves.png` — ROC curves for all models
- [x] `learning_curves.png` — Training vs validation accuracy + F1/loss curves
- [x] `per_attack_detection.png` — Per-attack detection rate bar chart
- [x] `feature_importance.png` — Feature importance with error bars
- [x] `score_distribution.png` — Normal vs attack anomaly score histograms
- [x] `model_comparison.png` — Grouped bar chart of all metrics
- [x] `cross_validation.png` — 5-fold CV FPR consistency

### Inference
- [x] Loads model + LOF + scaler from disk
- [x] Computes all 10 features (raw + derived) matching training pipeline
- [x] Ensemble voting (IF+LOF) with fallback to IF-only
- [x] Calibrated confidence scoring

### Artifacts (all tracked in git)
- [x] `ml/model.pkl` — trained Isolation Forest
- [x] `ml/ensemble_lof.pkl` — trained LOF for ensemble
- [x] `ml/scaler.pkl` — StandardScaler
- [x] `ml/training_metrics.json` — full metrics + hyperparams + learning curve
- [x] `ml/TRAINING_REPORT.md` — human-readable training report
- [x] `ml/training.log` — complete training log
- [x] `ml/plots/` — 9 visualization images
- [x] `data/normal_traffic.csv` — 20,000 normal traffic samples
- [x] `data/attack_traffic.csv` — 8,000 attack traffic samples

### Future Improvements
- [ ] Add temporal/sequential features (sliding window aggregation per-IP)
- [ ] Implement online learning / model drift detection
- [ ] Collect real-world traffic data for fine-tuning

---

## PHASE 5: Decision Fusion Engine ✅
- [x] Severity mapping logic (Rule + ML combinations)
- [x] Structured `FusionDecision` output
- [x] Weighted scoring (configurable rule vs ML weight)
- [x] Alert deduplication (10-second sliding window per IP + attack_type)
- [x] Returns `duplicate` flag and `rules_matched` count
- [ ] Add historical pattern matching (repeated alerts from same IP)
- [ ] Write unit tests for all severity combinations

---

## PHASE 6: Policy Generation Engine ✅
- [x] ACL generator with severity-based rules (BLOCK/RESTRICT/MONITOR)
- [x] Routing engine with OSPF cost recommendations
- [x] Cisco IOS-compatible ACL command output
- [ ] Add ACL rule conflict detection (duplicate/overlapping rules)
- [ ] Add policy expiration (auto-remove after configurable TTL)

---

## PHASE 7: Backend REST API Layer ✅

### Endpoints Implemented
| Endpoint | Method | Description |
|---|---|---|
| `/traffic/ingest` | POST | Ingest traffic record → IDS pipeline |
| `/traffic/recent` | GET | Recent traffic records |
| `/traffic/simulate` | POST | Simulate traffic (9 modes) |
| `/alerts/current` | GET | Current active alerts |
| `/alerts/history` | GET | Alert history with limit |
| `/policies/generated` | GET | Generated security policies |
| `/policies/latest` | GET | Latest policy |
| `/system/status` | GET | System health status |
| `/system/stats` | GET | Stats + attack breakdown + top offending IPs |
| `/system/config` | GET | IDS threshold configuration |
| `/system/config` | PUT | Update IDS thresholds at runtime |
| `/system/clear` | POST | Clear all in-memory stores (demo reset) |

### Future Improvements
- [ ] Add `/export/alerts` endpoint (CSV/JSON export)
- [ ] Add API error handling middleware (consistent error format)
- [ ] Add request logging middleware
- [ ] Add proper pagination (offset + limit + total)

---

## PHASE 8: React Dashboard ✅

### Design System
- [x] NOC/command-center aesthetic (midnight blue + electric teal)
- [x] Outfit font (display) + JetBrains Mono (data/code)
- [x] CSS custom properties for theming
- [x] Custom SVG favicon (hexagon shield)
- [x] Motion (framer-motion) for animations

### Components
- [x] `Sidebar` — animated nav indicator with spring animation, shield logo
- [x] `Header` — live clock, connection status indicator, security mode badge
- [x] `KPICard` — 5 color variants, staggered entrance, radial gradient accent
- [x] `AlertTable` — expandable detail rows, confidence bars, severity coloring
- [x] `TrafficChart` — area chart with gradient fill, custom tooltip
- [x] `PolicyBlock` — severity gradient, two-column ACL/routing layout, copy button
- [x] `Panel` — shared wrapper with consistent styling + motion entrance

### Pages
- [x] `Dashboard` — KPIs, simulation buttons, security mode, severity/protocol/attack breakdowns, top IPs, recent alerts
- [x] `Traffic` — simulation control (9 modes dropdown), packet rate chart, protocol chart, traffic table with protocol badges
- [x] `Alerts` — severity summary cards (clickable filters), filter bar, expandable alert table, clear button
- [x] `Policies` — summary stats, active policies list, empty state

### Frontend API Service
- [x] All backend endpoints covered
- [x] Added: `getAlerts`, `getPolicies`, `clearSystem`, `getSystemConfig`, `updateSystemConfig`

### Future Improvements
- [ ] Dark/light mode toggle
- [ ] Loading skeletons (not just spinner)
- [ ] Error boundary components (graceful API failure handling)
- [ ] WebSocket for real-time updates (replace polling)
- [ ] Responsive mobile layout

---

## PHASE 9: Traffic Simulator ✅
- [x] 7 specific attack generators: normal, port_scan, flood, syn_flood, slowloris, dns_amplification, anomaly
- [x] 2 meta modes: `random` (65% normal, 35% attacks), `mixed_attack` (uniform random)
- [x] Each generator uses distinct IP subnet ranges
- [x] `connection_count` included in all generators
- [x] Wired to `/traffic/simulate?mode=X&count=N`
- [ ] Add burst mode (rapid-fire many packets for DDoS simulation)
- [ ] Add auto-simulate mode (continuous background traffic for demo)

---

## PHASE 10: Cisco Packet Tracer Integration ⏳
- [ ] Design network topology in Packet Tracer
- [ ] Configure OSPF dynamic routing between routers
- [ ] Document integration steps with screenshots

---

## PHASE 11: Documentation & Presentation 📝
- [ ] Write project report
- [ ] Create PowerPoint presentation
- [ ] Create README.md with full setup instructions
- [ ] Prepare viva Q&A document

---

## Version History

| Version | Date | Changes |
|---|---|---|
| v1.0 | 2026-02-09 | Initial implementation (5K data, 5 features, basic IDS) |
| v2.0 | 2026-02-10 | Anti-overfitting overhaul (20K+8K data, 8 features, grid search, per-attack eval) |
| v3.0 | 2026-02-10 | Ensemble (IF+LOF), 10 features, 9 visualizations, training logs, brute force fix (0%→100%) |

## Git Repository

**URL:** https://github.com/ArrinPaul/sentinelnet-ids

### What's Tracked
- All source code (backend, frontend, ML scripts)
- Trained ML models (`ml/model.pkl`, `ml/ensemble_lof.pkl`, `ml/scaler.pkl`)
- Training metrics (`ml/training_metrics.json`)
- Training report (`ml/TRAINING_REPORT.md`)
- Training log (`ml/training.log`)
- Visualization images (`ml/plots/*.png`)
- Datasets (`data/normal_traffic.csv`, `data/attack_traffic.csv`)

### What's Ignored
- `__pycache__/`, `.venv/`, `node_modules/`, `frontend/dist/`
- IDE files (`.vscode/`, `.idea/`)
- OS files (`.DS_Store`, `Thumbs.db`)

---

## Quick Start

```bash
# Backend
cd "CN Final Project"
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python ml/generate_data.py       # Generate dataset (28K rows)
python ml/train_model.py         # Train model + generate plots (~70 seconds)
uvicorn backend.main:app --port 8000

# Frontend
cd frontend
npm install
npm run dev                      # http://localhost:5173
```
