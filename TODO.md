# TODO.md — Implementation Checklist
## Intelligent Traffic Control and Intrusion Prevention Network

> Use this file to track implementation progress phase by phase.  
> Mark items with `[x]` when completed.

---

## PHASE 1: Project Setup & Architecture ⏳
> **Priority:** 🔴 Critical — Everything depends on this

- [ ] Create full folder structure as per ROADMAP
- [ ] Initialize Python virtual environment
- [ ] Create `requirements.txt` with all backend/ML dependencies
- [ ] Initialize React app with Vite (`npm create vite@latest frontend -- --template react`)
- [ ] Install frontend dependencies (axios, recharts, tailwindcss)
- [ ] Create `__init__.py` files for all Python packages
- [ ] Set up `.gitignore` for Python, Node, and Cisco Packet Tracer files
- [ ] Create architecture diagram (draw.io / Mermaid)
- [ ] Define and document traffic feature schema (JSON)
- [ ] Define alert severity levels: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`

---

## PHASE 2: Traffic Data Ingestion Module ⏳
> **Priority:** 🔴 Critical — Entry point for all data

- [ ] Create `backend/main.py` — FastAPI app initialization with CORS middleware
- [ ] Create Pydantic models in `backend/api/traffic.py`:
  - `TrafficInput` — src_ip, dst_ip, packet_rate, unique_ports, avg_packet_size, protocol, duration
  - `TrafficRecord` — TrafficInput + timestamp + id
- [ ] Implement `POST /traffic/ingest` endpoint
- [ ] Implement in-memory traffic store (list-based with max capacity)
- [ ] Implement `GET /traffic/recent` — return last N traffic records
- [ ] Add input validation (IP format, positive numbers, valid protocols)
- [ ] Test endpoint with sample JSON using Postman or curl
- [ ] Add logging for ingested traffic

---

## PHASE 3: Rule-Based IDS ⏳
> **Priority:** 🔴 Critical — Core detection logic

- [ ] Create `backend/ids/rule_ids.py`
- [ ] Implement configurable thresholds:
  - `PORT_SCAN_THRESHOLD` = 15 unique ports
  - `FLOOD_THRESHOLD` = 1000 packets/sec
  - `SMALL_PACKET_THRESHOLD` = 100 bytes avg (flood signature)
- [ ] Implement detection functions:
  - `detect_port_scan(traffic)` → alert if unique_ports > threshold
  - `detect_flood(traffic)` → alert if packet_rate > threshold AND avg_packet_size < threshold
  - `detect_protocol_anomaly(traffic)` → alert on non-standard protocols (not TCP/UDP/ICMP)
- [ ] Implement `analyze(traffic) → RuleAlert` combining all rules
- [ ] Return structured alert: `{alert, type, severity, reason}`
- [ ] Write unit tests for each detection rule
- [ ] Test with normal + attack traffic samples

---

## PHASE 4: ML-Based Anomaly Detection ⏳
> **Priority:** 🟡 High — Differentiating feature of the project

### Training Pipeline
- [ ] Create `data/normal_traffic.csv` — 500+ rows of normal traffic features
- [ ] Create `data/attack_traffic.csv` — 100+ rows of attack traffic for validation
- [ ] Create `ml/train_model.py`:
  - Load `normal_traffic.csv`
  - Feature engineering: encode protocol to numeric flag
  - Train Isolation Forest with `contamination=0.05`
  - Save model to `ml/model.pkl` using joblib
  - Print training metrics (number of samples, feature names)
- [ ] Run training and verify `model.pkl` is generated

### Inference Integration
- [ ] Create `ml/inference.py` — load model, expose `predict(features)` function
- [ ] Create `backend/ids/ml_ids.py` — wrapper that:
  - Loads model on startup
  - Converts `TrafficInput` → feature vector
  - Calls inference and returns `{anomaly: bool, score: float}`
- [ ] Test with normal traffic (should return anomaly=false)
- [ ] Test with attack traffic (should return anomaly=true)

---

## PHASE 5: Decision Fusion Engine ⏳
> **Priority:** 🟡 High — Combines both IDS systems

- [ ] Create `backend/decision/fusion_engine.py`
- [ ] Implement severity mapping logic:
  - Rule HIGH + ML Anomaly → `CRITICAL`
  - Rule MEDIUM + ML Anomaly → `HIGH`
  - ML Anomaly only → `MEDIUM`
  - Rule alert only → `MEDIUM`
  - Neither → `SAFE`
- [ ] Implement `fuse(rule_result, ml_result) → FusionDecision`
- [ ] FusionDecision fields: `intrusion_detected, severity, attack_type, confidence, recommended_action`
- [ ] Store alert history in memory (with timestamps)
- [ ] Write unit tests for all severity combinations

---

## PHASE 6: Policy Generation Engine ⏳
> **Priority:** 🟡 High — Key output of the system

### ACL Generator
- [ ] Create `backend/policies/acl_generator.py`
- [ ] Implement `generate_acl(alert) → ACLPolicy`:
  - CRITICAL → `deny ip host {src_ip} any` (full block)
  - HIGH → `deny tcp host {src_ip} any eq {port}` (port-specific block)
  - MEDIUM → `permit ip host {src_ip} any log` (allow but log)
- [ ] Generate numbered ACL list with implicit `permit ip any any` at end
- [ ] Store generated policies with timestamps

### Routing Engine
- [ ] Create `backend/policies/routing_engine.py`
- [ ] Implement `generate_routing_policy(alert) → RoutingPolicy`:
  - CRITICAL → Recommend OSPF cost increase to 1000 on affected interface
  - HIGH → Recommend reroute via backup path
  - MEDIUM → No routing change, monitor only
- [ ] Generate Cisco IOS-compatible routing commands

---

## PHASE 7: Backend REST API Layer ⏳
> **Priority:** 🔴 Critical — Frontend depends on this

- [ ] Implement all API endpoints in `backend/api/`:
  - `POST /traffic/ingest` — accept and analyze traffic (Phase 2)
  - `POST /traffic/simulate` — generate and ingest random traffic for demo
  - `GET /traffic/recent` — last 50 traffic records
  - `GET /alerts/current` — current active alerts
  - `GET /alerts/history` — all past alerts with timestamps
  - `GET /policies/generated` — all generated ACL + routing policies
  - `GET /policies/latest` — most recent policy set
  - `GET /system/status` — system health, uptime, counts
  - `GET /system/stats` — aggregate statistics (total traffic, alerts, etc.)
- [ ] Add proper HTTP status codes and error responses
- [ ] Add CORS middleware for React frontend (allow localhost:5173)
- [ ] Create `backend/api/detection.py` — wire up rule IDS + ML IDS + fusion
- [ ] Create `backend/api/policies.py` — wire up policy generation
- [ ] Test all endpoints with Postman / curl
- [ ] Document API responses (can use FastAPI auto-docs at `/docs`)

---

## PHASE 8: React Dashboard ⏳
> **Priority:** 🟡 High — Visual presentation layer

### Project Setup
- [ ] Set up Tailwind CSS in Vite React project
- [ ] Set up React Router for page navigation
- [ ] Create Axios API service layer (`frontend/src/services/api.js`)
- [ ] Set up auto-refresh polling (every 3 seconds)

### Dashboard Overview Page (`/`)
- [ ] Traffic KPI cards: total packets, avg packet rate, active connections
- [ ] Active alerts count with severity breakdown (color coded)
- [ ] System security mode indicator (SAFE / WARNING / CRITICAL)
- [ ] Recent activity log (last 10 events)

### Traffic Monitoring Page (`/traffic`)
- [ ] Line chart: packet rate over time (Recharts)
- [ ] Bar chart: protocol distribution (TCP/UDP/ICMP/Other)
- [ ] Table: recent traffic records with sortable columns
- [ ] "Simulate Traffic" button (calls `/traffic/simulate`)

### Intrusion Alerts Page (`/alerts`)
- [ ] Alert table with columns: timestamp, src_ip, dst_ip, attack_type, severity, status
- [ ] Severity color coding: CRITICAL=red, HIGH=orange, MEDIUM=yellow, LOW=blue
- [ ] Filter by severity level
- [ ] Alert detail expandable row

### Policy Visualization Page (`/policies`)
- [ ] Generated ACL rules displayed as code blocks
- [ ] Routing recommendations displayed as cards
- [ ] Policy timeline: when each policy was generated
- [ ] "Copy to clipboard" button for ACL rules

### Layout & Navigation
- [ ] Sidebar navigation with icons
- [ ] Header with project title and system status badge
- [ ] Responsive layout for different screen sizes
- [ ] Dark/light mode toggle (optional but nice for demo)

---

## PHASE 9: Traffic Simulator & End-to-End Testing ⏳
> **Priority:** 🟡 High — Demo readiness

### Traffic Simulator
- [ ] Create `backend/utils/traffic_simulator.py`
- [ ] Implement normal traffic generator (randomized within safe ranges)
- [ ] Implement attack traffic generator:
  - Port scan: high unique_ports, low packet size
  - Flood: very high packet_rate, small avg_packet_size
  - Protocol anomaly: unusual protocol values
- [ ] Wire simulator to `/traffic/simulate` endpoint with mode parameter

### End-to-End Tests
- [ ] Test: Normal traffic → system shows SAFE status, no alerts
- [ ] Test: Port scan traffic → rule IDS triggers, alert generated, ACL created
- [ ] Test: Flood traffic → rule IDS triggers, alert generated, routing policy created
- [ ] Test: Subtle anomaly → ML IDS catches it, fusion reports MEDIUM
- [ ] Test: Combined attack → CRITICAL severity, full block ACL generated
- [ ] Test: Dashboard reflects all of the above in real-time
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
