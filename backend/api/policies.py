"""
Policies API — Generated ACL and routing policy endpoints
"""

from fastapi import APIRouter
import logging

logger = logging.getLogger("network-ids.api.policies")

router = APIRouter()

# ── In-memory policy store ───────────────────────────────────────────────────
policy_store: list[dict] = []


@router.get("/generated")
def get_generated_policies(limit: int = 50):
    """Return all generated policies."""
    return {
        "total": len(policy_store),
        "count": min(limit, len(policy_store)),
        "policies": policy_store[-limit:][::-1],
    }


@router.get("/latest")
def get_latest_policy():
    """Return the most recently generated policy."""
    if not policy_store:
        return {"policy": None, "message": "No policies generated yet"}
    return {"policy": policy_store[-1]}
