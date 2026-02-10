# ROADMAP.md
## Intelligent Traffic Control and Intrusion Prevention Network
### Using Dynamic Routing, Adaptive ACL Policies, and Machine Learning

---

## 1. Project Overview

This project implements an **SDN-inspired Intelligent Network Security System** that separates the **control plane** from the **data plane**.  
The system is designed to monitor network traffic, detect intrusions using both rule-based and machine-learning techniques, and dynamically generate network security policies.

The **control plane and dashboard are developed independently of Cisco Packet Tracer** and later logically integrated to demonstrate enforcement of generated policies.

---

## 2. Objectives

- Design an intelligent traffic monitoring system
- Detect intrusions using rule-based IDS
- Detect unknown anomalies using ML-based IDS
- Generate adaptive ACL and routing policies
- Visualize network state and alerts using a modern dashboard
- Demonstrate integration with Cisco Packet Tracer

---

## 3. System Architecture

### Architectural Layers

- **Presentation Plane**
  - React Dashboard
  - Charts, alerts, and policy visualization

- **Control Plane**
  - Backend Controller (FastAPI)
  - Rule-Based IDS
  - ML-Based Anomaly Detection
  - Decision Fusion Engine
  - Policy Generation Engine

- **Data Plane**
  - Cisco Packet Tracer Network
  - Dynamic Routing (OSPF/RIP)
  - ACL Enforcement

---

## 4. Technology Stack

### Frontend
- React.js (via Vite)
- React Router DOM
- Axios
- Recharts
- Tailwind CSS
- Lucide React (icons)

### Backend
- Python 3.10+
- FastAPI (with CORS Middleware)
- Uvicorn (ASGI server)
- Pydantic v2
- Pandas
- NumPy

### Machine Learning
- Scikit-learn
- Isolation Forest (Primary Model)

### Network Simulation
- Cisco Packet Tracer

---

## 5. Repository Structure

```
intelligent-network-system/
│
├── frontend/                     # Presentation Plane (React + Vite)
│   ├── package.json
│   ├── vite.config.js
│   ├── tailwind.config.js
│   └── src/
│       ├── App.jsx
│       ├── main.jsx
│       ├── pages/
│       │   ├── Dashboard.jsx
│       │   ├── Traffic.jsx
│       │   ├── Alerts.jsx
│       │   └── Policies.jsx
│       ├── components/
│       │   ├── Sidebar.jsx
│       │   ├── Header.jsx
│       │   ├── KPICard.jsx
│       │   ├── AlertTable.jsx
│       │   ├── TrafficChart.jsx
│       │   └── PolicyBlock.jsx
│       └── services/
│           └── api.js
│
├── backend/                      # Control Plane (FastAPI)
│   ├── __init__.py
│   ├── main.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── traffic.py
│   │   ├── detection.py
│   │   └── policies.py
│   ├── ids/
│   │   ├── __init__.py
│   │   ├── rule_ids.py           # Rule-based IDS (runtime)
│   │   └── ml_ids.py             # ML IDS wrapper (runtime inference)
│   ├── decision/
│   │   ├── __init__.py
│   │   └── fusion_engine.py
│   ├── policies/
│   │   ├── __init__.py
│   │   ├── acl_generator.py
│   │   └── routing_engine.py
│   └── utils/
│       ├── __init__.py
│       └── traffic_simulator.py  # Simulates traffic for demo
│
├── ml/                           # ML Training Pipeline (offline)
│   ├── train_model.py            # Train Isolation Forest model
│   ├── inference.py              # Model loading & prediction logic
│   └── model.pkl                 # Saved trained model (generated)
│
├── data/
│   ├── normal_traffic.csv
│   └── attack_traffic.csv
│
├── packet_tracer/
│   └── topology.pkt
│
├── requirements.txt              # Python dependencies
├── README.md                     # Setup & usage instructions
├── TODO.md                       # Implementation tracking
└── ROADMAP.md
```


---

## 6. Phase-wise Detailed Implementation

---

## PHASE 1: Architecture and Feature Definition

### Goals
- Finalize system architecture
- Define feature scope
- Lock traffic features and attack types

### Implementation Details
- Define control-plane and data-plane separation
- Identify supported attack types:
  - Port scanning
  - Flooding (DoS-like)
  - Abnormal protocol usage
- Define traffic feature schema
- Define alert severity levels

### Deliverables
- Architecture diagram
- Feature specification
- Traffic feature list

---

## PHASE 2: Traffic Data Ingestion Module

### Goals
- Accept traffic metrics
- Validate and preprocess input data

### Implementation
- FastAPI endpoint `/traffic/ingest`
- JSON-based traffic input
- Pydantic validation models
- Temporary in-memory storage

### Input Format
```json
{
  "src_ip": "192.168.1.10",
  "dst_ip": "10.0.0.1",
  "packet_rate": 850,
  "unique_ports": 20,
  "avg_packet_size": 220,
  "protocol": "TCP",
  "duration": 5
}
Output
Structured traffic object forwarded to IDS modules

Completion Criteria
API accepts traffic data

Data validated and logged successfully

PHASE 3: Rule-Based Intrusion Detection System
Goals
Detect known attack patterns using deterministic rules

Detection Rules
Port Scan Detection:

Trigger when unique_ports > threshold

Flood Detection:

Trigger when packet_rate > threshold

Unauthorized Access Detection:

Trigger on abnormal protocol usage

Implementation
Rules implemented in rule_ids.py

Output includes alert flag, attack type, and severity

Output Format
{
  "alert": true,
  "type": "Port Scan",
  "severity": "High"
}
Completion Criteria
Known attack traffic triggers alerts

Normal traffic passes without alerts

PHASE 4: Machine Learning-Based Anomaly Detection
Goals
Detect unknown or zero-day attacks

Model Selection
Isolation Forest (Unsupervised)

Feature Vector
Feature	Description
packet_rate	Traffic intensity
unique_ports	Port scanning behavior
avg_packet_size	Flood signature
duration	Connection persistence
protocol_flag	Protocol anomaly
Training
Train using normal_traffic.csv

Save trained model as model.pkl

Inference
Load trained model

Generate anomaly score

Classify traffic as normal or anomalous

Completion Criteria
Anomalous traffic detected

Anomaly scores generated successfully

PHASE 5: Decision Fusion Engine
Goals
Combine rule-based and ML-based outputs

Decision Logic
IF rule_alert == TRUE OR ml_anomaly == TRUE
→ Intrusion Confirmed
Severity Mapping
Rule High + ML Anomaly → CRITICAL

Rule Medium + ML Anomaly → HIGH

ML Anomaly only → MEDIUM

Rule alert only → MEDIUM

Neither → SAFE

Implementation
Implemented in fusion_engine.py

Completion Criteria
Single unified decision per traffic window

PHASE 6: Policy Generation Engine
Goals
Generate adaptive security policies

ACL Policy Generation
Generate Cisco-compatible ACL rules

Based on source IP and severity

Example:

deny ip host 192.168.1.10 any
permit ip any any
Routing Policy Generation
Recommend OSPF cost increase

Suggest alternate routing paths

Completion Criteria
Policies generated automatically

Policies logged and retrievable via API

## PHASE 7: Backend REST API Layer
### APIs
| Endpoint | Method | Description |
|---|---|---|
| `/traffic/ingest` | POST | Accept and analyze traffic data |
| `/traffic/simulate` | POST | Generate simulated traffic for demo |
| `/traffic/recent` | GET | Return last 50 traffic records |
| `/alerts/current` | GET | Active alerts |
| `/alerts/history` | GET | All past alerts with timestamps |
| `/policies/generated` | GET | All generated ACL + routing policies |
| `/policies/latest` | GET | Most recent policy set |
| `/system/status` | GET | System health, uptime, counts |
| `/system/stats` | GET | Aggregate statistics |

### Purpose
Serve data to frontend

Decouple UI from core logic

CORS middleware enabled for frontend origin (localhost:5173)

### Completion Criteria
APIs tested using Postman or FastAPI Swagger UI (`/docs`)

API responses stable and documented

## PHASE 8: React Dashboard Implementation (Vite + Tailwind CSS)
### Pages
### Dashboard Overview (`/`)
Traffic KPI cards (total packets, avg rate, active connections)

Active alerts count with severity breakdown (color coded)

Security mode indicator (SAFE / WARNING / CRITICAL)

### Traffic Monitoring (`/traffic`)
Line charts for packet rate over time (Recharts)

Bar charts for protocol distribution

"Simulate Traffic" button for demo purposes

### Intrusion Alerts (`/alerts`)
Table view with severity, timestamp, source IP, attack type

Severity color coding (CRITICAL=red, HIGH=orange, MEDIUM=yellow)

Filter by severity level

### Policy Visualization (`/policies`)
Generated ACL rules displayed as code blocks with copy button

Routing recommendations as cards

Policy generation timeline

### Completion Criteria
Dashboard reflects backend state

Real-time updates via polling (every 3 seconds)

## PHASE 9: Traffic Simulator & End-to-End Testing
### Goals
Build traffic simulator for demo mode

Validate full control plane without Cisco

### Traffic Simulator
- Create `backend/utils/traffic_simulator.py`
- Normal traffic generator (randomized within safe ranges)
- Attack traffic generators: port scan, flood, protocol anomaly
- Wire to `POST /traffic/simulate` with mode parameter (`normal`, `port_scan`, `flood`, `anomaly`, `random`)

### Tests
Normal traffic → System shows SAFE status, no alerts

Port scan traffic → Rule IDS triggers, ACL generated

Flood traffic → Rule IDS + ML triggers, routing policy generated

Subtle anomaly → ML catches it, fusion reports MEDIUM

Combined attack → CRITICAL severity, full block ACL

### Completion Criteria
Successful demo without Packet Tracer

All test scenarios verified via dashboard

Screenshots captured for each scenario

PHASE 10: Cisco Packet Tracer Integration
Goals
Demonstrate enforcement of generated policies

Integration Method
Simulate attacks in Packet Tracer

Feed equivalent traffic metrics to backend

Apply generated ACLs manually

Verify traffic mitigation and rerouting

Completion Criteria
Closed-loop demonstration

Working Packet Tracer topology

7. Evaluation Metrics
Detection accuracy

False positive rate

Response time

Policy effectiveness

System scalability (logical)

8. Limitations
Packet Tracer lacks programmatic APIs

Traffic data is simulated

Policy enforcement is manual

9. Future Enhancements
Mininet with OpenFlow

Real packet capture

Deep learning IDS

Automated router configuration

Cloud-based deployment

## PHASE 11: Documentation & Presentation
### Goals
- Write project report
- Create presentation
- Prepare for viva

### Deliverables
- [ ] Project report (Introduction, Architecture, Implementation, Results, Conclusion)
- [ ] PowerPoint presentation (15-20 slides)
- [ ] Viva Q&A document
- [ ] README.md with setup instructions
- [ ] Final demo video

---

## 10. Project Completion Checklist
- [ ] Backend implemented and all APIs working
- [ ] ML model trained and integrated
- [ ] Dashboard functional with all 4 pages
- [ ] Traffic simulator working for demo
- [ ] Cisco topology working with manual ACL enforcement
- [ ] End-to-end demo prepared
- [ ] Report and PPT completed
- [ ] Viva-ready explanations prepared
- [ ] Code packaged and submitted

