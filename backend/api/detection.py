"""
Detection API — Alert endpoints
Serves intrusion alert data to the frontend.
"""

from fastapi import APIRouter
import logging

logger = logging.getLogger("network-ids.api.detection")

router = APIRouter()

# ── In-memory alert store ────────────────────────────────────────────────────
alert_store: list[dict] = []


@router.get("/current")
def get_current_alerts():
    """Return current active alerts (last 20)."""
    recent = alert_store[-20:][::-1]
    return {
        "count": len(recent),
        "alerts": recent,
    }


@router.get("/history")
def get_alert_history(limit: int = 100):
    """Return full alert history."""
    return {
        "total": len(alert_store),
        "count": min(limit, len(alert_store)),
        "alerts": alert_store[-limit:][::-1],
    }
