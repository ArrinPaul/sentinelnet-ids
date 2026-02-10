"""
Intelligent Network Security System — FastAPI Backend
Control Plane: Traffic ingestion, IDS, decision fusion, policy generation
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import logging
from datetime import datetime

from backend.api import traffic, detection, policies

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("network-ids")

# ── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Intelligent Network Security System",
    description="SDN-inspired IDS with rule-based + ML anomaly detection",
    version="1.0.0",
)

# ── CORS (allow React dev server) ────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Startup timestamp ───────────────────────────────────────────────────────
STARTUP_TIME = datetime.now()

# ── Include routers ─────────────────────────────────────────────────────────
app.include_router(traffic.router, prefix="/traffic", tags=["Traffic"])
app.include_router(detection.router, prefix="/alerts", tags=["Alerts"])
app.include_router(policies.router, prefix="/policies", tags=["Policies"])


# ── System endpoints ────────────────────────────────────────────────────────
@app.get("/system/status")
def system_status():
    """System health check and basic info."""
    from backend.api.traffic import traffic_store
    from backend.api.detection import alert_store

    uptime = (datetime.now() - STARTUP_TIME).total_seconds()
    return {
        "status": "running",
        "uptime_seconds": round(uptime, 1),
        "total_traffic_records": len(traffic_store),
        "total_alerts": len(alert_store),
        "started_at": STARTUP_TIME.isoformat(),
    }


@app.get("/system/stats")
def system_stats():
    """Aggregate statistics for dashboard KPIs."""
    from backend.api.traffic import traffic_store
    from backend.api.detection import alert_store
    from backend.api.policies import policy_store

    total_traffic = len(traffic_store)
    avg_packet_rate = 0
    protocol_counts = {}

    for t in traffic_store:
        avg_packet_rate += t["packet_rate"]
        proto = t["protocol"]
        protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

    if total_traffic > 0:
        avg_packet_rate = round(avg_packet_rate / total_traffic, 1)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in alert_store:
        sev = a.get("severity", "LOW")
        if sev in severity_counts:
            severity_counts[sev] += 1

    # Determine security mode
    if severity_counts["CRITICAL"] > 0:
        security_mode = "CRITICAL"
    elif severity_counts["HIGH"] > 0:
        security_mode = "WARNING"
    else:
        security_mode = "SAFE"

    return {
        "total_traffic": total_traffic,
        "avg_packet_rate": avg_packet_rate,
        "protocol_distribution": protocol_counts,
        "total_alerts": len(alert_store),
        "severity_breakdown": severity_counts,
        "security_mode": security_mode,
        "total_policies": len(policy_store),
    }


@app.get("/")
def root():
    return {"message": "Intelligent Network Security System — Control Plane API"}
