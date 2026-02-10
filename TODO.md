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
| **ML Model** | ✅ Trained | F1=0.9102, AUC=0.9626, FPR=1.47% |
| **Rule IDS** | ✅ Enhanced | 6 detection rules, configurable thresholds |
| **Fusion Engine** | ✅ Enhanced | Weighted scoring, alert deduplication |
| **Backend API** | ✅ Enhanced | 12 endpoints, config/clear/stats |
| **Frontend** | ✅ Redesigned | NOC aesthetic, 4 pages, motion animations |
| **GitHub** | ✅ Pushed | All artifacts tracked (model, data, metrics) |

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

### Dataset (v2.0 — Anti-Overfitting)
- [x] **20,000 normal rows** across 7 traffic profiles
  - Web browsing (45%), Streaming (18%), DNS (12%), ICMP (5%)
  - **Edge cases (10%)** — borderline traffic that looks suspicious but is legitimate
  - IoT/Sensor (5%), Database/API (5%)
- [x] **8,000 attack rows** across 10 subtypes (800 each)
  - Port Scan, SYN Flood, UDP Flood, Slowloris, DNS Amplification
  - Protocol Anomaly, Brute Force, ICMP Flood, HTTP Flood, Stealthy Probe
- [x] Datasets saved as CSV and tracked in git (`data/`)

### Training Pipeline (v2.0)
- [x] **8 features**: 5 raw + 3 derived (`bytes_per_second`, `port_scan_ratio`, `size_rate_ratio`)
- [x] **StandardScaler** fitted on training data only (saved to `ml/scaler.pkl`)
- [x] **Proper train/validation/test split** — 70/15/15 (14K train, 3K val, 3K test)
- [x] **Hyperparameter grid search** — 81 combinations on validation set
  - Best: `n_estimators=300, contamination=0.01, max_features=0.75, max_samples=0.75`
- [x] **5-fold cross-validation** — FPR: 0.0115 ± 0.0023
- [x] **Learning curve analysis** — F1 improves monotonically (no overfitting)
- [x] **Feature importance** with confidence intervals (10 permutation repeats)
- [x] **Model comparison**: Isolation Forest vs One-Class SVM vs LOF

### Test Results (Held-Out Test Set)
- [x] **F1 Score: 0.9102** | Precision: 0.9594 | Recall: 0.8658
- [x] **ROC-AUC: 0.9626** | FPR: 1.47%
- [x] **Per-attack detection rates**:
  - Port Scan: 100% | ICMP Flood: 100% | DNS Amplification: 99.3%
  - Protocol Anomaly: 99.1% | Stealth Probe: 98.6% | SYN Flood: 97.6%
  - UDP Flood: 95.5% | HTTP Flood: 87.5% | Slowloris: 82.9%
  - Brute Force: 0% (handled by rule-based IDS)

### Inference
- [x] Loads model + scaler from disk
- [x] Computes all 8 features (raw + derived) matching training pipeline
- [x] Calibrated confidence scoring

### Artifacts (all tracked in git)
- [x] `ml/model.pkl` — trained Isolation Forest (~59 MB)
- [x] `ml/scaler.pkl` — StandardScaler (~1 KB)
- [x] `ml/training_metrics.json` — full metrics + hyperparams + learning curve
- [x] `ml/TRAINING_REPORT.md` — human-readable training report
- [x] `data/normal_traffic.csv` — 20,000 normal traffic samples
- [x] `data/attack_traffic.csv` — 8,000 attack traffic samples

### Future Improvements
- [ ] Add temporal/sequential features (sliding window aggregation)
- [ ] Implement online learning / model drift detection
- [ ] Collect real-world traffic data for fine-tuning
- [ ] Add ensemble voting (combine IF + LOF decisions)

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

## Git Repository

**URL:** https://github.com/ArrinPaul/sentinelnet-ids

### What's Tracked
- All source code (backend, frontend, ML scripts)
- Trained ML model (`ml/model.pkl`, `ml/scaler.pkl`)
- Training metrics (`ml/training_metrics.json`)
- Training report (`ml/TRAINING_REPORT.md`)
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
python ml/train_model.py         # Train model (~60 seconds)
uvicorn backend.main:app --port 8000

# Frontend
cd frontend
npm install
npm run dev                      # http://localhost:5173
```
