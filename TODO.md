# TODO.md — Implementation & Improvement Checklist
## Intelligent Traffic Control and Intrusion Prevention Network

> Track implementation progress and improvements phase by phase.  
> Mark items with `[x]` when completed.

---

## PHASE 1: Project Setup & Architecture ✅
- [x] Create full folder structure as per ROADMAP
- [x] Initialize Python virtual environment
- [x] Create `requirements.txt` with all backend/ML dependencies
- [x] Initialize React app with Vite
- [x] Install frontend dependencies (axios, recharts, tailwindcss)
- [x] Create `__init__.py` files for all Python packages
- [x] Define traffic feature schema (JSON)
- [x] Define alert severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`
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

## PHASE 3: Rule-Based IDS ✅ → IMPROVEMENTS NEEDED
- [x] Configurable thresholds for port scan, flood, protocol anomaly
- [x] `detect_port_scan()`, `detect_flood()`, `detect_protocol_anomaly()`
- [x] Combined `analyze()` returning highest severity alert
- [ ] **Add SYN flood detection** (high packet rate + TCP + small packets + short duration)
- [ ] **Add brute force detection** (many connections to same dst, same port)
- [ ] **Add DDoS amplification detection** (high rate + UDP + DNS/NTP patterns)
- [ ] **Make thresholds configurable via API** (GET/PUT `/system/config`)
- [ ] **Add rate-based sliding window** (track per-IP rates over time)
- [ ] Write unit tests for each detection rule

---

## PHASE 4: ML-Based Anomaly Detection ✅ → MAJOR IMPROVEMENTS NEEDED
### Current Issues
- Only 500 normal + 120 attack rows (far too small)
- No feature scaling/normalization
- No proper evaluation metrics (precision, recall, F1)
- Single model with no comparison
- Simplistic confidence calculation

### Training Pipeline Improvements
- [ ] **Expand dataset to 5000+ normal, 1500+ attack rows**
- [ ] **Add diverse attack subtypes**: SYN flood, slowloris, DNS amplification, brute force
- [ ] **Add feature scaling** (StandardScaler saved with model)
- [ ] **Add proper evaluation metrics**: accuracy, precision, recall, F1, ROC-AUC
- [ ] **Add confusion matrix output during training**
- [ ] **Add cross-validation** (5-fold on normal data)
- [ ] **Compare multiple models**: Isolation Forest vs One-Class SVM vs LOF
- [ ] **Save scaler alongside model** (`ml/scaler.pkl`)
- [ ] **Add feature importance analysis**

### Inference Improvements
- [ ] **Use saved scaler in inference pipeline**
- [ ] **Improve confidence calculation** (calibrated probabilities)
- [ ] **Add anomaly score histogram thresholds**

---

## PHASE 5: Decision Fusion Engine ✅ → MINOR IMPROVEMENTS
- [x] Severity mapping logic (Rule + ML combinations)
- [x] Structured `FusionDecision` output
- [ ] **Add weighted scoring** (configurable rule vs ML weight)
- [ ] **Add historical pattern matching** (repeated alerts from same IP)
- [ ] **Add alert deduplication** (prevent flooding same alert)
- [ ] Write unit tests for all severity combinations

---

## PHASE 6: Policy Generation Engine ✅
- [x] ACL generator with severity-based rules
- [x] Routing engine with OSPF recommendations
- [x] Cisco IOS-compatible command output
- [ ] **Add ACL rule conflict detection** (duplicate/overlapping rules)
- [ ] **Add policy expiration** (auto-remove after configurable time)

---

## PHASE 7: Backend REST API Layer ✅ → IMPROVEMENTS NEEDED
- [x] All core endpoints implemented
- [x] CORS middleware for React frontend
- [ ] **Add `/system/config` endpoint** (GET/PUT IDS thresholds)
- [ ] **Add `/traffic/clear` endpoint** (reset for demo)
- [ ] **Add `/alerts/clear` endpoint** (reset for demo)
- [ ] **Add `/export/alerts` endpoint** (CSV/JSON export)
- [ ] **Add API error handling middleware** (consistent error format)
- [ ] **Add request logging middleware**
- [ ] **Add proper pagination** (offset + limit + total)

---

## PHASE 8: React Dashboard ✅ → COMPLETE REDESIGN NEEDED
### Current Issues
- Generic AI-generated dark theme aesthetic
- Same emerald/gray palette throughout
- No distinctive design character
- Basic charts with no interaction depth
- No proper error/empty states
- Loading spinner only (no skeletons)
- Title says "frontend" in browser tab

### Complete Frontend Redesign
- [ ] **New design language**: Distinctive NOC/command-center aesthetic
- [ ] **Custom typography**: Unique font pairing (not Inter/system-ui)
- [ ] **Rich animations**: Page transitions, staggered reveals, micro-interactions
- [ ] **Improved charts**: Area charts with gradients, animated transitions
- [ ] **Alert detail expandable rows** (click to see full fusion data)
- [ ] **Dark/light mode toggle**
- [ ] **Proper loading skeletons** (not just spinner)
- [ ] **Error boundary components** (graceful API failure handling)
- [ ] **Proper browser tab title and favicon**
- [ ] **Real-time connection status indicator**

---

## PHASE 9: Traffic Simulator ✅ → MINOR IMPROVEMENTS
- [x] Normal, port scan, flood, protocol anomaly generators
- [x] Wired to `/traffic/simulate` with mode parameter
- [ ] **Add burst mode** (rapid-fire many packets to simulate DDoS)
- [ ] **Add mixed attack scenario** (combined multi-vector attack)
- [ ] **Add auto-simulate mode** (continuous background traffic for demo)

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

## Implementation Priority Order

```
1. [CRITICAL] Expand ML dataset + add scaling + metrics
2. [CRITICAL] Enhance rule-based IDS with more attack types
3. [HIGH]     Backend API improvements (config, clear, export)
4. [HIGH]     Decision fusion improvements (dedup, weighting)
5. [HIGH]     Complete frontend redesign
6. [MEDIUM]   Traffic simulator enhancements
7. [MEDIUM]   Documentation
```
