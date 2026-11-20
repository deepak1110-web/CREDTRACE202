"""
CREDTRACE V2 - Controlled Attacker Simulator API (Module A)
Calls real backend endpoints, enforces real server-side revocation,
and emits database-backed cryptographic events to the live WebSocket feed.
"""
import uuid
from typing import Dict, Any, List
from fastapi import APIRouter, HTTPException, Request, Query

from app.config import settings
from app.models import (
    SimulatorAuthRequest,
    SimulatorRequest,
    SimulatorExportRequest,
    SimulatorActionResponse
)
from app.database import (
    get_credential,
    record_security_event
)
from app.security import verify_secret
from app.routes.ws import manager

router = APIRouter(prefix="/api/simulator", tags=["Attacker Simulator"])

# Synthetic Data Repositories
SYNTHETIC_CUSTOMERS = [
    {
        "customer_id": "CUST-9041-DE",
        "name": "Bavarian Logistics AG",
        "jurisdiction": "Munich, Germany",
        "contracts_count": 8,
        "monthly_freight_teu": 420.0,
        "classification": "RESTRICTED COMMERCIAL"
    },
    {
        "customer_id": "CUST-3812-SG",
        "name": "Pacific Transshipment Corp",
        "jurisdiction": "Singapore Straits",
        "contracts_count": 14,
        "monthly_freight_teu": 1850.5,
        "classification": "CONFIDENTIAL ENTERPRISE"
    },
    {
        "customer_id": "CUST-5519-US",
        "name": "Midwest Intermodal Freight LLC",
        "jurisdiction": "Chicago, IL",
        "contracts_count": 5,
        "monthly_freight_teu": 610.2,
        "classification": "RESTRICTED COMMERCIAL"
    },
    {
        "customer_id": "CUST-1088-IN",
        "name": "Western Port Cargo Movers",
        "jurisdiction": "Mumbai, India",
        "contracts_count": 19,
        "monthly_freight_teu": 2100.0,
        "classification": "CONFIDENTIAL ENTERPRISE"
    }
]

SYNTHETIC_VENDORS = [
    {"vendor_id": "VND-101", "name": "BlueVault Secure Credential Store", "status": "Active Integration", "endpoint": "api.bluevault.local/v2"},
    {"vendor_id": "VND-102", "name": "OceanTrack AIS Telemetry Feed", "status": "Active Integration", "endpoint": "ais.oceantrack.net/stream"},
    {"vendor_id": "VND-103", "name": "CustomsPort EDI Automated Clearing", "status": "Active Integration", "endpoint": "edi.customsport.org/v1"},
    {"vendor_id": "VND-104", "name": "ColdChain Fleet Temperature Monitoring", "status": "Standby", "endpoint": "telemetry.coldchain.internal"},
]

@router.post("/auth", response_model=SimulatorActionResponse)
async def simulator_authenticate(req: SimulatorAuthRequest, request: Request):
    """
    Authenticates the adversary simulation device using the provided synthetic secret.
    Enforces real revocation and records event in the hash-chained ledger.
    """
    room_id = req.room_id
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "CREDTRACE-Simulator/2.0")
    session_id = req.session_id or f"sess_{uuid.uuid4().hex[:8]}"

    cred = get_credential(room_id, settings.PRIMARY_CREDENTIAL_ID)
    if not cred:
        raise HTTPException(status_code=404, detail="Primary credential record not found.")

    # 1. Check if credential has been REVOKED by investigator
    if cred.get("is_revoked"):
        evt, alerts = record_security_event(
            room_id=room_id,
            action="SIMULATOR_AUTH_REVOKED",
            resource=f"AUTH:{settings.PRIMARY_CREDENTIAL_ID}",
            decision="DENIED",
            http_status=403,
            ip_address=client_ip,
            user_agent=user_agent,
            credential_id=settings.PRIMARY_CREDENTIAL_ID,
            session_id=session_id,
            device_label=req.device_label,
            detection_tags=["POST_REVOCATION_ATTEMPT", "BLOCKED_BY_CONTAINMENT"]
        )
        
        await manager.broadcast_to_room(room_id, {
            "type": "NEW_SECURITY_EVENT",
            "event": evt,
            "alerts": alerts,
            "credential": cred
        })
        
        return SimulatorActionResponse(
            success=False,
            status_code=403,
            event_id=evt["event_id"],
            timestamp=evt["timestamp"],
            action="SIMULATOR_AUTH_REVOKED",
            resource=f"AUTH:{settings.PRIMARY_CREDENTIAL_ID}",
            decision="DENIED",
            message="ACCESS FORBIDDEN: Credential bvk-7f3a was REVOKED by investigator SOC.",
            alert_triggered=alerts[0] if alerts else None
        )

    # 2. Verify synthetic secret hash
    is_valid = verify_secret(req.secret.strip(), cred["secret_hash"])
    
    if not is_valid:
        evt, alerts = record_security_event(
            room_id=room_id,
            action="AUTH_FAILED",
            resource=f"AUTH:{settings.PRIMARY_CREDENTIAL_ID}",
            decision="DENIED",
            http_status=401,
            ip_address=client_ip,
            user_agent=user_agent,
            credential_id=settings.PRIMARY_CREDENTIAL_ID,
            session_id=session_id,
            device_label=req.device_label,
            detection_tags=["INVALID_SECRET_PRESENTED", "AUTHENTICATION_FAILED"]
        )
        
        await manager.broadcast_to_room(room_id, {
            "type": "NEW_SECURITY_EVENT",
            "event": evt,
            "alerts": alerts,
            "credential": cred
        })
        
        return SimulatorActionResponse(
            success=False,
            status_code=401,
            event_id=evt["event_id"],
            timestamp=evt["timestamp"],
            action="AUTH_FAILED",
            resource=f"AUTH:{settings.PRIMARY_CREDENTIAL_ID}",
            decision="DENIED",
            message="401 Unauthorized: Synthetic secret does not match registered token hash.",
            alert_triggered=alerts[0] if alerts else None
        )

    # 3. Successful authentication
    evt, alerts = record_security_event(
        room_id=room_id,
        action="SIMULATOR_AUTH_SUCCESS",
        resource=f"AUTH:{settings.PRIMARY_CREDENTIAL_ID}",
        decision="ALLOWED",
        http_status=200,
        ip_address=client_ip,
        user_agent=user_agent,
        credential_id=settings.PRIMARY_CREDENTIAL_ID,
        session_id=session_id,
        device_label=req.device_label,
        detection_tags=["AUTHENTICATED_ACCESS", "ADVERSARY_SESSION_ESTABLISHED"]
    )
    
    await manager.broadcast_to_room(room_id, {
        "type": "NEW_SECURITY_EVENT",
        "event": evt,
        "alerts": alerts,
        "credential": cred
    })
    
    return SimulatorActionResponse(
        success=True,
        status_code=200,
        event_id=evt["event_id"],
        timestamp=evt["timestamp"],
        action="SIMULATOR_AUTH_SUCCESS",
        resource=f"AUTH:{settings.PRIMARY_CREDENTIAL_ID}",
        decision="ALLOWED",
        message=f"Authentication successful for device '{req.device_label}'. Session token issued.",
        data={"session_id": session_id, "scope": "VENDOR_API_READ"}
    )

@router.get("/customers", response_model=SimulatorActionResponse)
async def query_customers(
    request: Request,
    room: str = Query(settings.DEFAULT_ROOM_ID),
    session_id: str = Query("sess_sim_01"),
    device_label: str = Query("LAPTOP-02-SIMULATOR"),
    credential_id: str = Query(settings.PRIMARY_CREDENTIAL_ID)
):
    """
    Simulated adversary requests synthetic customer freight records.
    Immediately blocked if credential is revoked.
    """
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "CREDTRACE-Simulator/2.0")
    
    cred = get_credential(room, credential_id)
    if cred and cred.get("is_revoked"):
        evt, alerts = record_security_event(
            room_id=room,
            action="CUSTOMER_DATA_QUERY",
            resource="DB:CUSTOMERS_GLOBAL_MANIFEST",
            decision="DENIED",
            http_status=403,
            ip_address=client_ip,
            user_agent=user_agent,
            credential_id=credential_id,
            session_id=session_id,
            device_label=device_label,
            detection_tags=["POST_REVOCATION_ATTEMPT", "BLOCKED_BY_CONTAINMENT"]
        )
        await manager.broadcast_to_room(room, {
            "type": "NEW_SECURITY_EVENT",
            "event": evt,
            "alerts": alerts,
            "credential": cred
        })
        return SimulatorActionResponse(
            success=False,
            status_code=403,
            event_id=evt["event_id"],
            timestamp=evt["timestamp"],
            action="CUSTOMER_DATA_QUERY",
            resource="DB:CUSTOMERS_GLOBAL_MANIFEST",
            decision="DENIED",
            message="403 Forbidden: Credential bvk-7f3a was REVOKED. Access to customer records terminated.",
            alert_triggered=alerts[0] if alerts else None
        )

    evt, alerts = record_security_event(
        room_id=room,
        action="CUSTOMER_DATA_QUERY",
        resource="DB:CUSTOMERS_GLOBAL_MANIFEST",
        decision="ALLOWED",
        http_status=200,
        ip_address=client_ip,
        user_agent=user_agent,
        credential_id=credential_id,
        session_id=session_id,
        device_label=device_label,
        detection_tags=["DATA_ACCESS", "CUSTOMER_RECORDS"]
    )
    
    await manager.broadcast_to_room(room, {
        "type": "NEW_SECURITY_EVENT",
        "event": evt,
        "alerts": alerts,
        "credential": cred
    })
    
    return SimulatorActionResponse(
        success=True,
        status_code=200,
        event_id=evt["event_id"],
        timestamp=evt["timestamp"],
        action="CUSTOMER_DATA_QUERY",
        resource="DB:CUSTOMERS_GLOBAL_MANIFEST",
        decision="ALLOWED",
        message=f"Retrieved {len(SYNTHETIC_CUSTOMERS)} synthetic customer records.",
        data=SYNTHETIC_CUSTOMERS
    )

@router.get("/vendors", response_model=SimulatorActionResponse)
async def query_vendors(
    request: Request,
    room: str = Query(settings.DEFAULT_ROOM_ID),
    session_id: str = Query("sess_sim_01"),
    device_label: str = Query("LAPTOP-02-SIMULATOR"),
    credential_id: str = Query(settings.PRIMARY_CREDENTIAL_ID)
):
    """Lists synthetic vendor integration records."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "CREDTRACE-Simulator/2.0")
    cred = get_credential(room, credential_id)

    if cred and cred.get("is_revoked"):
        evt, alerts = record_security_event(
            room_id=room,
            action="VENDOR_RECORDS_QUERY",
            resource="DB:VENDOR_CONFIGURATIONS",
            decision="DENIED",
            http_status=403,
            ip_address=client_ip,
            user_agent=user_agent,
            credential_id=credential_id,
            session_id=session_id,
            device_label=device_label,
            detection_tags=["POST_REVOCATION_ATTEMPT", "BLOCKED_BY_CONTAINMENT"]
        )
        await manager.broadcast_to_room(room, {
            "type": "NEW_SECURITY_EVENT",
            "event": evt,
            "alerts": alerts,
            "credential": cred
        })
        return SimulatorActionResponse(
            success=False,
            status_code=403,
            event_id=evt["event_id"],
            timestamp=evt["timestamp"],
            action="VENDOR_RECORDS_QUERY",
            resource="DB:VENDOR_CONFIGURATIONS",
            decision="DENIED",
            message="403 Forbidden: Credential bvk-7f3a was REVOKED.",
            alert_triggered=alerts[0] if alerts else None
        )

    evt, alerts = record_security_event(
        room_id=room,
        action="VENDOR_RECORDS_QUERY",
        resource="DB:VENDOR_CONFIGURATIONS",
        decision="ALLOWED",
        http_status=200,
        ip_address=client_ip,
        user_agent=user_agent,
        credential_id=credential_id,
        session_id=session_id,
        device_label=device_label,
        detection_tags=["RECONNAISSANCE", "VENDOR_RECORDS"]
    )
    
    await manager.broadcast_to_room(room, {
        "type": "NEW_SECURITY_EVENT",
        "event": evt,
        "alerts": alerts,
        "credential": cred
    })
    
    return SimulatorActionResponse(
        success=True,
        status_code=200,
        event_id=evt["event_id"],
        timestamp=evt["timestamp"],
        action="VENDOR_RECORDS_QUERY",
        resource="DB:VENDOR_CONFIGURATIONS",
        decision="ALLOWED",
        message=f"Retrieved {len(SYNTHETIC_VENDORS)} vendor integration records.",
        data=SYNTHETIC_VENDORS
    )

@router.post("/export", response_model=SimulatorActionResponse)
async def attempt_bulk_export(req: SimulatorExportRequest, request: Request):
    """
    Simulated adversary attempts an unauthorized bulk exfiltration of restricted customer records.
    Always blocked by security policy (HTTP 403) and triggers Critical Threat Alert!
    """
    room_id = req.room_id
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "CREDTRACE-Simulator/2.0")
    cred = get_credential(room_id, req.credential_id or settings.PRIMARY_CREDENTIAL_ID)

    tags = ["RESTRICTED_DATA_EXFILTRATION", "SECURITY_POLICY_VIOLATION", "HIGH_RISK_ACTION"]
    if cred and cred.get("is_revoked"):
        tags.append("POST_REVOCATION_ATTEMPT")

    evt, alerts = record_security_event(
        room_id=room_id,
        action="BULK_EXPORT_ATTEMPT",
        resource="RESTRICTED:ALL_GLOBAL_CUSTOMERS_AND_TRANSACTIONS",
        decision="DENIED",
        http_status=403,
        ip_address=client_ip,
        user_agent=user_agent,
        credential_id=req.credential_id or settings.PRIMARY_CREDENTIAL_ID,
        session_id=req.session_id,
        device_label=req.device_label,
        detection_tags=tags
    )
    
    await manager.broadcast_to_room(room_id, {
        "type": "NEW_SECURITY_EVENT",
        "event": evt,
        "alerts": alerts,
        "credential": cred
    })
    
    return SimulatorActionResponse(
        success=False,
        status_code=403,
        event_id=evt["event_id"],
        timestamp=evt["timestamp"],
        action="BULK_EXPORT_ATTEMPT",
        resource="RESTRICTED:ALL_GLOBAL_CUSTOMERS_AND_TRANSACTIONS",
        decision="DENIED",
        message="403 FORBIDDEN: Bulk data exfiltration intercepted by access control policy.",
        alert_triggered=alerts[0] if alerts else None
    )

@router.post("/test-invalid", response_model=SimulatorActionResponse)
async def test_invalid_credential(
    request: Request,
    room: str = Query(settings.DEFAULT_ROOM_ID),
    device_label: str = Query("LAPTOP-02-SIMULATOR")
):
    """Tests an invalid credential to generate failed authentication telemetry."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("user-agent", "CREDTRACE-Simulator/2.0")
    
    evt, alerts = record_security_event(
        room_id=room,
        action="AUTH_FAILED",
        resource=f"AUTH:{settings.PRIMARY_CREDENTIAL_ID}",
        decision="DENIED",
        http_status=401,
        ip_address=client_ip,
        user_agent=user_agent,
        credential_id=settings.PRIMARY_CREDENTIAL_ID,
        device_label=device_label,
        detection_tags=["INVALID_SECRET_PRESENTED", "AUTHENTICATION_FAILED"]
    )
    
    cred = get_credential(room, settings.PRIMARY_CREDENTIAL_ID)
    await manager.broadcast_to_room(room, {
        "type": "NEW_SECURITY_EVENT",
        "event": evt,
        "alerts": alerts,
        "credential": cred
    })
    
    return SimulatorActionResponse(
        success=False,
        status_code=401,
        event_id=evt["event_id"],
        timestamp=evt["timestamp"],
        action="AUTH_FAILED",
        resource=f"AUTH:{settings.PRIMARY_CREDENTIAL_ID}",
        decision="DENIED",
        message="401 Unauthorized: Invalid test secret presented.",
        alert_triggered=alerts[0] if alerts else None
    )
