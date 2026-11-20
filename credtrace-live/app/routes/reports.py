"""
CREDTRACE V2 - Forensic Report Endpoints (PDF & JSON)
"""
import json
from fastapi import APIRouter, Query, Response
from fastapi.responses import JSONResponse

from app.config import settings
from app.database import (
    get_overview_statistics,
    get_security_events,
    get_threat_alerts,
    get_credential
)
from app.reporting import generate_pdf_report, generate_json_report

router = APIRouter(prefix="/api/reports", tags=["Forensic Reports"])

@router.get("/pdf")
async def download_pdf_report(room: str = Query(settings.DEFAULT_ROOM_ID)):
    """Generates and streams downloadable ReportLab forensic investigation PDF."""
    stats = get_overview_statistics(room)
    events = get_security_events(room, limit=500)
    alerts = get_threat_alerts(room, limit=100)
    cred = get_credential(room) or {}
    
    pdf_bytes = generate_pdf_report(
        room_id=room,
        stats=stats,
        events=events,
        alerts=alerts,
        credential_record=cred
    )
    
    filename = f"CREDTRACE_FORENSIC_REPORT_{settings.CASE_ID}_{room}.pdf"
    
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Cache-Control": "no-cache"
        }
    )

@router.get("/json")
async def download_json_report(room: str = Query(settings.DEFAULT_ROOM_ID)):
    """Downloads structured forensic incident JSON export."""
    stats = get_overview_statistics(room)
    events = get_security_events(room, limit=500)
    alerts = get_threat_alerts(room, limit=100)
    cred = get_credential(room) or {}
    
    report_dict = generate_json_report(
        room_id=room,
        stats=stats,
        events=events,
        alerts=alerts,
        credential_record=cred
    )
    
    filename = f"CREDTRACE_FORENSIC_DATA_{settings.CASE_ID}_{room}.json"
    
    return Response(
        content=json.dumps(report_dict, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename={filename}",
            "Cache-Control": "no-cache"
        }
    )
