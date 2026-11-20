"""
CREDTRACE V2 - Company Portal API (Module A)
Harbor & Finch Freight Pvt. Ltd.
"""
from typing import List, Dict, Any
from fastapi import APIRouter, Query, HTTPException, Request

from app.config import settings
from app.models import TicketCreate, TicketResponse, CredentialDetail
from app.database import (
    list_support_tickets,
    create_support_ticket,
    get_credential,
    update_credential_secret,
    record_security_event
)
from app.security import generate_synthetic_secret
from app.routes.ws import manager

router = APIRouter(prefix="/api/portal", tags=["Company Portal"])

@router.get("/dashboard")
async def get_portal_dashboard():
    """Returns logistics dashboard metrics and active container movements."""
    return {
        "company": settings.COMPANY_NAME,
        "case_id": settings.CASE_ID,
        "active_vessels": 14,
        "containers_in_transit": 4820,
        "active_edi_integrations": 6,
        "recent_shipments": [
            {
                "shipment_id": "SHP-7819-SEA",
                "origin": "Rotterdam Terminal 4",
                "destination": "Port of Singapore Hub 2",
                "status": "In Transit (Vessel Ocean Wave)",
                "cargo": "Automotive Electronic Components",
                "weight_mt": 1420.5
            },
            {
                "shipment_id": "SHP-9021-AIR",
                "origin": "Frankfurt Cargo City",
                "destination": "Mumbai Air Freight Complex",
                "status": "Customs Cleared",
                "cargo": "Pharmaceutical Temperature Controlled",
                "weight_mt": 84.2
            },
            {
                "shipment_id": "SHP-3312-RAIL",
                "origin": "Chicago Intermodal Yard",
                "destination": "Long Beach Port Terminal",
                "status": "Manifest Verified",
                "cargo": "Industrial Machinery Hardware",
                "weight_mt": 960.0
            }
        ]
    }

@router.get("/tickets", response_model=List[Dict[str, Any]])
async def get_tickets(room: str = Query(settings.DEFAULT_ROOM_ID)):
    """Retrieves all support tickets for the company portal."""
    return list_support_tickets(room)

@router.post("/tickets/create", response_model=Dict[str, Any])
async def submit_ticket(req: TicketCreate, room: str = Query(settings.DEFAULT_ROOM_ID)):
    """Creates a new employee vendor support ticket."""
    ticket = create_support_ticket(
        room_id=room,
        title=req.title,
        category=req.category,
        priority=req.priority,
        description=req.description,
        author="sarah.chen"
    )
    return ticket

@router.get("/credential", response_model=CredentialDetail)
async def get_portal_credential(room: str = Query(settings.DEFAULT_ROOM_ID)):
    """
    Exposes credential details for the investigation starting point.
    Demonstrates credential identifier bvk-7f3a and separate random synthetic secret.
    """
    cred = get_credential(room, settings.PRIMARY_CREDENTIAL_ID)
    if not cred:
        raise HTTPException(status_code=404, detail="Credential not found.")
    
    return CredentialDetail(
        credential_id=cred["credential_id"],
        case_id=cred["case_id"],
        secret_display=cred["synthetic_secret"],
        status=cred["status"],
        created_at=cred["created_at"],
        expires_at=cred["expires_at"],
        ticket_ref=cred["ticket_ref"],
        is_revoked=bool(cred["is_revoked"]),
        revoked_at=cred.get("revoked_at"),
        revocation_reason=cred.get("revocation_reason")
    )

@router.post("/credential/generate-new")
async def generate_new_synthetic_secret(
    request: Request,
    room: str = Query(settings.DEFAULT_ROOM_ID)
):
    """
    Generates a new random synthetic secret for testing while maintaining
    the persistent credential identifier bvk-7f3a.
    """
    new_secret = generate_synthetic_secret()
    updated = update_credential_secret(room, settings.PRIMARY_CREDENTIAL_ID, new_secret)
    
    # Broadcast event so SOC and Attacker console update immediately
    client_ip = request.client.host if request.client else "127.0.0.1"
    evt, alerts = record_security_event(
        room_id=room,
        action="SYNTHETIC_TOKEN_REISSUED",
        resource=f"CREDENTIAL:{settings.PRIMARY_CREDENTIAL_ID}",
        decision="ALLOWED",
        http_status=200,
        ip_address=client_ip,
        user_agent="HarborFinch-Portal/2.0",
        credential_id=settings.PRIMARY_CREDENTIAL_ID,
        device_label="PORTAL-CLIENT",
        detection_tags=["TOKEN_GENERATION", "SYNTHETIC_TEST"]
    )
    
    await manager.broadcast_to_room(room, {
        "type": "NEW_SECURITY_EVENT",
        "event": evt,
        "alerts": alerts,
        "credential": updated
    })
    
    return {
        "success": True,
        "credential_id": settings.PRIMARY_CREDENTIAL_ID,
        "synthetic_secret": new_secret,
        "status": updated["status"],
        "message": "Fresh synthetic token generated and registered."
    }
