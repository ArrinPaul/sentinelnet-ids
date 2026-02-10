# TODO.md — Implementation Checklist
## Intelligent Traffic Control and Intrusion Prevention Network

> Use this file to track implementation progress phase by phase.  
> Mark items with `[x]` when completed.

---

## PHASE 1: Project Setup & Architecture ✅
> **Priority:** 🔴 Critical — Everything depends on this

- [x] Create full folder structure as per ROADMAP
- [x] Initialize Python virtual environment
- [x] Create `requirements.txt` with all backend/ML dependencies
- [x] Initialize React app with Vite (`npm create vite@latest frontend -- --template react`)
- [x] Install frontend dependencies (axios, recharts, tailwindcss)
- [x] Create `__init__.py` files for all Python packages
- [x] Set up `.gitignore` for Python, Node, and Cisco Packet Tracer files
- [ ] Create architecture diagram (draw.io / Mermaid)
- [x] Define and document traffic feature schema (JSON)
- [x] Define alert severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

---

## PHASE 2: Traffic Data Ingestion Module ✅
> **Priority:** 🔴 Critical — Entry point for all data

- [x] Create `backend/main.py` — FastAPI app initialization with CORS middleware
- [x] Create Pydantic models in `backend/api/traffic.py`:
  - `TrafficInput` — src_ip, dst_ip, packet_rate, unique_ports, avg_packet_size, protocol, duration
  - `TrafficRecord` — TrafficInput + timestamp + id
- [x] Implement `POST /traffic/ingest` endpoint
- [x] Implement in-memory traffic store (list-based with max capacity)
- [x] Implement `GET /traffic/recent` — return last N traffic records
- [x] Add input validation (IP format, positive numbers, valid protocols)
- [x] Test endpoint with sample JSON using Postman or curl
- [x] Add logging for ingested traffic

---

## PHASE 3: Rule-Based IDS ✅
> **Priority:** 🔴 Critical — Core detection logic

- [x] Create `backend/ids/rule_ids.py`
- [x] Implement configurable thresholds:
  - `PORT_SCAN_THRESHOLD` = 15 unique ports
  - `FLOOD_THRESHOLD` = 1000 packets/sec
  - `SMALL_PACKET_THRESHOLD` = 100 bytes avg (flood signature)
- [x] Implement detection functions:
  - `detect_port_scan(traffic)` → alert if unique_ports > threshold
  - `detect_flood(traffic)` → alert if packet_rate > threshold AND avg_packet_size < threshold
  - `detect_protocol_anomaly(traffic)` → alert on non-standard protocols (not TCP/UDP/ICMP)
- [x] Implement `analyze(traffic) → RuleAlert` combining all rules
- [x] Return structured alert: `{alert, type, severity, reason}`
- [ ] Write unit tests for each detection rule
- [x] Test with normal + attack traffic samples

---

## PHASE 4: ML-Based Anomaly Detection ✅
> **Priority:** 🟡 High — Differentiating feature of the project

### Training Pipeline
- [x] Create `data/normal_traffic.csv` — 500+ rows of normal traffic features
- [x] Create `data/attack_traffic.csv` — 120 rows of attack traffic for validation
- [x] Create `ml/train_model.py`:
  - Load `normal_traffic.csv`
  - Feature engineering: encode protocol to numeric flag
  - Train Isolation Forest with `contamination=0.05`
  - Save model to `ml/model.pkl` using joblib
  - Print training metrics (number of samples, feature names)
- [x] Run training and verify `model.pkl` is generated

### Inference Integration
- [x] Create `ml/inference.py` — load model, expose `predict(features)` function
- [x] Create `backend/ids/ml_ids.py` — wrapper that:
  - Loads model on startup
  - Converts `TrafficInput` → feature vector
  - Calls inference and returns `{anomaly: bool, score: float}`
- [x] Test with normal traffic (should return anomaly=false)
- [x] Test with attack traffic (should return anomaly=true)

---

## PHASE 5: Decision Fusion Engine ✅
> **Priority:** 🟡 High — Combines both IDS systems

- [x] Create `backend/decision/fusion_engine.py`
- [x] Implement severity mapping logic:
  - Rule HIGH + ML Anomaly → `CRITICAL`
  - Rule MEDIUM + ML Anomaly → `HIGH`
  - ML Anomaly only → `MEDIUM`
  - Rule alert only → `MEDIUM`
  - Neither → `SAFE`
- [x] Implement `fuse(rule_result, ml_result) → FusionDecision`
- [x] FusionDecision fields: `intrusion_detected, severity, attack_type, confidence, recommended_action`
- [x] Store alert history in memory (with timestamps)
- [ ] Write unit tests for all severity combinations

---

## PHASE 6: Policy Generation Engine ✅
> **Priority:** 🟡 High — Key output of the system

### ACL Generator
- [x] Create `backend/policies/acl_generator.py`
- [x] Implement `generate_acl(alert) → ACLPolicy`:
  - CRITICAL → `deny ip host {src_ip} any` (full block)
  - HIGH → `deny tcp host {src_ip} any eq {port}` (port-specific block)
  - MEDIUM → `permit ip host {src_ip} any log` (allow but log)
- [x] Generate numbered ACL list with implicit `permit ip any any` at end
- [x] Store generated policies with timestamps

### Routing Engine
- [x] Create `backend/policies/routing_engine.py`
- [x] Implement `generate_routing_policy(alert) → RoutingPolicy`:
  - CRITICAL → Recommend OSPF cost increase to 1000 on affected interface
  - HIGH → Recommend reroute via backup path
  - MEDIUM → No routing change, monitor only
- [x] Generate Cisco IOS-compatible routing commands

---

## PHASE 7: Backend REST API Layer ✅
> **Priority:** 🔴 Critical — Frontend depends on this

- [x] Implement all API endpoints in `backend/api/`:
  - `POST /traffic/ingest` — accept and analyze traffic (Phase 2)
  - `POST /traffic/simulate` — generate and ingest random traffic for demo
  - `GET /traffic/recent` — last 50 traffic records
  - `GET /alerts/current` — current active alerts
  - `GET /alerts/history` — all past alerts with timestamps
  - `GET /policies/generated` — all generated ACL + routing policies
  - `GET /policies/latest` — most recent policy set
  - `GET /system/status` — system health, uptime, counts
  - `GET /system/stats` — aggregate statistics (total traffic, alerts, etc.)
- [x] Add proper HTTP status codes and error responses
- [x] Add CORS middleware for React frontend (allow localhost:5173)
- [x] Create `backend/api/detection.py` — wire up rule IDS + ML IDS + fusion
- [x] Create `backend/api/policies.py` — wire up policy generation
- [x] Test all endpoints with Postman / curl
- [x] Document API responses (can use FastAPI auto-docs at `/docs`)

---

## PHASE 8: React Dashboard ✅
> **Priority:** 🟡 High — Visual presentation layer

### Project Setup
- [x] Set up Tailwind CSS in Vite React project
- [x] Set up React Router for page navigation
- [x] Create Axios API service layer (`frontend/src/services/api.js`)
- [x] Set up auto-refresh polling (every 3 seconds)

### Dashboard Overview Page (`/`)
- [x] Traffic KPI cards: total packets, avg packet rate, active connections
- [x] Active alerts count with severity breakdown (color coded)
- [x] System security mode indicator (SAFE / WARNING / CRITICAL)
- [x] Recent activity log (last 10 events)

### Traffic Monitoring Page (`/traffic`)
- [x] Line chart: packet rate over time (Recharts)
- [x] Bar chart: protocol distribution (TCP/UDP/ICMP/Other)
- [x] Table: recent traffic records with sortable columns
- [x] "Simulate Traffic" button (calls `/traffic/simulate`)

### Intrusion Alerts Page (`/alerts`)
- [x] Alert table with columns: timestamp, src_ip, dst_ip, attack_type, severity, status
- [x] Severity color coding: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue
- [x] Filter by severity level
- [ ] Alert detail expandable row

### Policy Visualization Page (`/policies`)
- [x] Generated ACL rules displayed as code blocks
- [x] Routing recommendations displayed as cards
- [x] Policy timeline: when each policy was generated
- [x] "Copy to clipboard" button for ACL rules

### Layout & Navigation
- [x] Sidebar navigation with icons
- [x] Header with project title and system status badge
- [x] Responsive layout for different screen sizes
- [ ] Dark/light mode toggle (optional but nice for demo)

---

## PHASE 9: Traffic Simulator & End-to-End Testing ✅
> **Priority:** 🟡 High — Demo readiness

### Traffic Simulator
- [x] Create `backend/utils/traffic_simulator.py`
- [x] Implement normal traffic generator (randomized within safe ranges)
- [x] Implement attack traffic generator:
  - Port scan: high unique_ports, low packet size
  - Flood: very high packet_rate, small avg_packet_size
  - Protocol anomaly: unusual protocol values
- [x] Wire simulator to `/traffic/simulate` endpoint with mode parameter

### End-to-End Tests
- [x] Test: Normal traffic → system shows SAFE status, no alerts
- [x] Test: Port scan traffic → rule IDS triggers, alert generated, ACL created
- [x] Test: Flood traffic → rule IDS triggers, alert generated, routing policy created
- [x] Test: Subtle anomaly → ML IDS catches it, fusion reports MEDIUM
- [x] Test: Combined attack → CRITICAL severity, full block ACL generated
- [x] Test: Dashboard reflects all of the above in real-time
- [ ] Capture screenshots for each test scenario
- [ ] Record demo walkthrough video (optional)

---

## PHASE 10: Cisco Packet Tracer Integration ⏳
> **Priority:** 🟢 Medium — Logical integration (manual)

- [ ] Design network topology in Packet Tracer:
  - 3+ routers with OSPF configured
  - 2+ subnets with PCs
  - 1 server acting as "monitored host"
- [ ] Configure OSPF dynamic routing between routers
- [ ] Simulate an attack scenario in Packet Tracer (e.g., flood pings)
- [ ] Manually feed equivalent traffic metrics to backend via API
- [ ] Show generated ACL rules from dashboard
- [ ] Manually apply generated ACLs on Packet Tracer router
- [ ] Verify that blocked traffic is denied after ACL application
- [ ] Verify alternative routing via OSPF cost changes
- [ ] Save topology as `packet_tracer/topology.pkt`
- [ ] Document the integration steps with screenshots

---

## PHASE 11: Documentation & Presentation 📝
> **Priority:** 🟢 Medium — Final deliverables

- [ ] Write project report (Introduction, Architecture, Implementation, Results, Conclusion)
- [ ] Create PowerPoint presentation (15-20 slides)
- [ ] Prepare viva Q&A document with expected questions and answers
- [ ] Create README.md with setup instructions
- [ ] Record final demo video
- [ ] Package all code and submit

---

## Quick Reference: Dependency Order

```
Phase 1 (Setup)
    ↓
Phase 2 (Traffic Ingestion)
    ↓
Phase 3 (Rule IDS) ←→ Phase 4 (ML IDS)  [parallel]
    ↓                      ↓
Phase 5 (Decision Fusion)
    ↓
Phase 6 (Policy Generation)
    ↓
Phase 7 (Full API Layer)
    ↓
Phase 8 (React Dashboard)
    ↓
Phase 9 (Testing + Simulator)
    ↓
Phase 10 (Packet Tracer)
    ↓
Phase 11 (Documentation)
```

---

## Files to Create (Complete List)

```
d:\CN Final Project\
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── traffic.py
│   │   ├── detection.py
│   │   └── policies.py
│   ├── ids/
│   │   ├── __init__.py
│   │   ├── rule_ids.py
│   │   └── ml_ids.py
│   ├── decision/
│   │   ├── __init__.py
│   │   └── fusion_engine.py
│   ├── policies/
│   │   ├── __init__.py
│   │   ├── acl_generator.py
│   │   └── routing_engine.py
│   └── utils/
│       ├── __init__.py
│       └── traffic_simulator.py
├── ml/
│   ├── train_model.py
│   ├── inference.py
│   └── model.pkl  (generated)
├── data/
│   ├── normal_traffic.csv
│   └── attack_traffic.csv
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   ├── src/
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── Traffic.jsx
│   │   │   ├── Alerts.jsx
│   │   │   └── Policies.jsx
│   │   ├── components/
│   │   │   ├── Sidebar.jsx
│   │   │   ├── Header.jsx
│   │   │   ├── KPICard.jsx
│   │   │   ├── AlertTable.jsx
│   │   │   ├── TrafficChart.jsx
│   │   │   └── PolicyBlock.jsx
│   │   └── services/
│   │       └── api.js
│   └── public/
├── packet_tracer/
│   └── topology.pkt
├── requirements.txt
├── ROADMAP.md
├── TODO.md
└── README.md
```

---

## Key Dependencies

### `requirements.txt`
```
fastapi==0.109.0
uvicorn==0.27.0
pydantic==2.5.3
pandas==2.1.4
numpy==1.26.3
scikit-learn==1.4.0
joblib==1.3.2
python-multipart==0.0.6
```

### Frontend (`package.json` key deps)
```
react, react-dom, react-router-dom
axios
recharts
tailwindcss, @tailwindcss/forms
lucide-react (icons)
```
