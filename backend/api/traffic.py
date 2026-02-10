"""
Traffic Data Ingestion Module
Accepts, validates, and stores network traffic metrics.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator
from typing import Literal
from datetime import datetime
import uuid
import logging
import re

logger = logging.getLogger("network-ids.traffic")

router = APIRouter()

# ── In-memory traffic store (max 1000 records) ──────────────────────────────
MAX_STORE_SIZE = 1000
traffic_store: list[dict] = []


# ── Pydantic Models ─────────────────────────────────────────────────────────
class TrafficInput(BaseModel):
    """Incoming traffic data from the network."""
    src_ip: str
    dst_ip: str = "10.0.0.1"
    packet_rate: float
    unique_ports: int
    avg_packet_size: float
    protocol: str
    duration: float

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
        if not re.match(pattern, v):
            raise ValueError(f"Invalid IP address format: {v}")
        parts = v.split(".")
        for part in parts:
            if int(part) > 255:
                raise ValueError(f"Invalid IP address octet: {part}")
        return v

    @field_validator("packet_rate", "avg_packet_size", "duration")
    @classmethod
    def validate_positive(cls, v: float) -> float:
        if v < 0:
            raise ValueError("Value must be non-negative")
        return v

    @field_validator("unique_ports")
    @classmethod
    def validate_ports(cls, v: int) -> int:
        if v < 0 or v > 65535:
            raise ValueError("unique_ports must be between 0 and 65535")
        return v

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        return v.upper()


class TrafficRecord(BaseModel):
    """Stored traffic record with metadata."""
    id: str
    src_ip: str
    dst_ip: str
    packet_rate: float
    unique_ports: int
    avg_packet_size: float
    protocol: str
    duration: float
    timestamp: str


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/ingest")
def ingest_traffic(data: TrafficInput):
    """Accept and store a traffic record, then run IDS analysis."""
    record = {
        "id": str(uuid.uuid4())[:8],
        "src_ip": data.src_ip,
        "dst_ip": data.dst_ip,
        "packet_rate": data.packet_rate,
        "unique_ports": data.unique_ports,
        "avg_packet_size": data.avg_packet_size,
        "protocol": data.protocol,
        "duration": data.duration,
        "timestamp": datetime.now().isoformat(),
    }

    # Store with size limit
    traffic_store.append(record)
    if len(traffic_store) > MAX_STORE_SIZE:
        traffic_store.pop(0)

    logger.info(
        f"Traffic ingested: {data.src_ip} → {data.dst_ip} | "
        f"rate={data.packet_rate} ports={data.unique_ports} proto={data.protocol}"
    )

    # Run IDS analysis pipeline
    from backend.ids.rule_ids import analyze as rule_analyze
    from backend.ids.ml_ids import analyze as ml_analyze
    from backend.decision.fusion_engine import fuse
    from backend.policies.acl_generator import generate_acl
    from backend.policies.routing_engine import generate_routing_policy
    from backend.api.detection import alert_store
    from backend.api.policies import policy_store

    rule_result = rule_analyze(record)
    ml_result = ml_analyze(record)
    fusion_result = fuse(rule_result, ml_result, record)

    # If intrusion detected, generate policies and store alert
    if fusion_result["intrusion_detected"]:
        alert_entry = {
            **fusion_result,
            "src_ip": data.src_ip,
            "dst_ip": data.dst_ip,
            "timestamp": record["timestamp"],
            "traffic_id": record["id"],
        }
        alert_store.append(alert_entry)

        acl = generate_acl(alert_entry)
        routing = generate_routing_policy(alert_entry)
        policy_entry = {
            "id": str(uuid.uuid4())[:8],
            "timestamp": record["timestamp"],
            "trigger_alert": fusion_result["severity"],
            "src_ip": data.src_ip,
            "acl_rules": acl,
            "routing_policy": routing,
        }
        policy_store.append(policy_entry)

        logger.warning(
            f"🚨 INTRUSION DETECTED: {fusion_result['severity']} — "
            f"{fusion_result['attack_type']} from {data.src_ip}"
        )

    return {
        "status": "ingested",
        "record_id": record["id"],
        "rule_ids": rule_result,
        "ml_ids": ml_result,
        "fusion": fusion_result,
    }


@router.get("/recent")
def get_recent_traffic(limit: int = 50):
    """Return the most recent traffic records."""
    return {
        "count": min(limit, len(traffic_store)),
        "records": traffic_store[-limit:][::-1],  # newest first
    }


@router.post("/simulate")
def simulate_traffic(mode: str = "random", count: int = 1):
    """
    Generate and ingest simulated traffic for demo purposes.
    Modes: normal, port_scan, flood, anomaly, random
    """
    from backend.utils.traffic_simulator import generate_traffic

    if count < 1 or count > 50:
        raise HTTPException(status_code=400, detail="count must be between 1 and 50")

    results = []
    for _ in range(count):
        traffic_data = generate_traffic(mode)
        # Re-use the ingest logic
        data = TrafficInput(**traffic_data)
        result = ingest_traffic(data)
        results.append(result)

    return {
        "simulated": count,
        "mode": mode,
        "results": results,
    }
