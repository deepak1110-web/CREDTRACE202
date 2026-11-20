"""
CREDTRACE V2 - Investigator SOC & Forensics Command Centre API (Module B)
- Real database-backed statistics & telemetry
- Cryptographic hash-chain audit verification
- Server-enforced credential containment and revocation
- Room reset and multi-source correlation engine
"""
from typing import Dict, Any, List
from fastapi import APIRouter, Query, HTTPException, Request

from app.config import settings
from app.models import (
    OverviewStatistics,
    RevocationRequest,
    RevocationResponse,
    RoomResetRequest,
    RoomResetResponse
)
from app.database import (
    get_overview_statistics,
    get_security_events,
    get_threat_alerts,
    get_credential,
    revoke_credential,
    reset_room_state
)
from app.security import verify_hash_chain
from app.rules import build_correlation_matrix
from app.routes.ws import manager

router = APIRouter(prefix="/api/investigator", tags=["Investigator SOC"])

@router.get("/overview", response_model=OverviewStatistics)
async def get_overview(room: str = Query(settings.DEFAULT_ROOM_ID)):
    """Returns database-backed metrics, risk scores, and chart telemetry."""
    return get_overview_statistics(room)

@router.get("/events")
async def get_events(
    room: str = Query(settings.DEFAULT_ROOM_ID),
    limit: int = Query(100),
    since_id: int = Query(None)
):
    """Retrieves chronologically ordered security events for live monitoring."""
    return get_security_events(room, limit=limit, since_id=since_id)

@router.get("/alerts")
async def get_alerts(
    room: str = Query(settings.DEFAULT_ROOM_ID),
    limit: int = Query(50)
):
    """Retrieves triggered threat detection alerts."""
    return get_threat_alerts(room, limit=limit)

@router.get("/correlations")
async def get_correlations(room: str = Query(settings.DEFAULT_ROOM_ID)):
    """Computes explainable multi-source technical correlation matrix."""
    events = get_security_events(room, limit=200)
    alerts = get_threat_alerts(room, limit=50)
    cred = get_credential(room) or {}
    return build_correlation_matrix(events, alerts, cred)

@router.get("/credentials")
async def get_credentials_status(room: str = Query(settings.DEFAULT_ROOM_ID)):
    """Returns credential intelligence for primary credential bvk-7f3a."""
    cred = get_credential(room, settings.PRIMARY_CREDENTIAL_ID)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential record not found.")
    return cred

@router.post("/revoke", response_model=RevocationResponse)
async def revoke_active_credential(req: RevocationRequest):
    """
    Executes formal containment: revokes bvk-7f3a on the server,
    records a tamper-evident audit event, and broadcasts containment to both laptops.
    """
    result = revoke_credential(
        room_id=req.room_id,
        credential_id=req.credential_id,
        reason=req.reason,
        investigator_id=req.investigator_id
    )
    
    # Broadcast containment update immediately to room
    updated_cred = get_credential(req.room_id, req.credential_id)
    stats = get_overview_statistics(req.room_id)
    
    await manager.broadcast_to_room(req.room_id, {
        "type": "CONTAINMENT_ENFORCED",
        "credential_id": req.credential_id,
        "status": "REVOKED",
        "reason": req.reason,
        "revoked_at": result["revoked_at"],
        "event_id": result["event_id"],
        "statistics": stats,
        "credential": updated_cred
    })
    
    return RevocationResponse(
        success=True,
        credential_id=req.credential_id,
        status="REVOKED",
        revoked_at=result["revoked_at"],
        event_id=result["event_id"],
        message=f"Credential {req.credential_id} successfully revoked and contained."
    )

@router.get("/verify-audit")
async def verify_tamper_evident_audit(room: str = Query(settings.DEFAULT_ROOM_ID)):
    """
    Verifies the SHA-256 hash chain across all recorded security events in the room.
    Confirms ledger integrity and detects any manipulation.
    """
    events = get_security_events(room, limit=1000)
    verification = verify_hash_chain(events)
    return {
        "room_id": room,
        "verification": verification,
        "total_events_in_chain": len(events)
    }

@router.post("/reset", response_model=RoomResetResponse)
async def reset_simulation_room(req: RoomResetRequest):
    """Resets simulation room events and alerts for clean judge demonstrations."""
    if not req.admin_code or req.admin_code != settings.ADMIN_RESET_KEY:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Valid administrator authorization code required to reset simulation state."
        )
    res = reset_room_state(req.room_id)
    
    # Broadcast reset to all clients in the room
    await manager.broadcast_to_room(req.room_id, {
        "type": "ROOM_RESET",
        "room_id": req.room_id,
        "message": "Room state reset by investigator."
    })
    
    return RoomResetResponse(
        success=True,
        room_id=req.room_id,
        message="Room simulation state reset to clean baseline.",
        cleared_events=0,
        cleared_alerts=0
    )
