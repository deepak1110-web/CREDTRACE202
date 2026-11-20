"""
CREDTRACE V2 - Digital Forensics Report Generator
- ReportLab PDF Generation
- Structured JSON Forensics Export
- Case CR-26-047 | Harbor & Finch Freight Pvt. Ltd.
"""
import io
import json
from datetime import datetime, timezone
from typing import Dict, Any, List

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    HRFlowable,
    KeepTogether
)

from app.config import settings
from app.security import verify_hash_chain
from app.rules import build_correlation_matrix

def generate_pdf_report(
    room_id: str,
    stats: Dict[str, Any],
    events: List[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    credential_record: Dict[str, Any]
) -> bytes:
    """
    Builds a professional, comprehensive forensic investigation PDF report
    using ReportLab.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )
    
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a')
    )
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#0284c7')
    )
    h2_style = ParagraphStyle(
        'Heading2Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor('#0f172a'),
        spaceBefore=12,
        spaceAfter=6
    )
    body_style = ParagraphStyle(
        'BodyCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor('#334155')
    )
    mono_style = ParagraphStyle(
        'MonoCustom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor('#1e293b')
    )
    disclaimer_style = ParagraphStyle(
        'DisclaimerCustom',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#64748b')
    )

    story = []
    
    # 1. Header & Case Metadata
    story.append(Paragraph("CREDTRACE DIGITAL FORENSICS INCIDENT REPORT", title_style))
    story.append(Paragraph(f"OFFICIAL CASE RECORD // CASE ID: {settings.CASE_ID} // HARBOR & FINCH FREIGHT PVT. LTD.", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12))

    # Meta Table
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    meta_data = [
        [
            Paragraph("<b>Company:</b> " + settings.COMPANY_NAME, body_style),
            Paragraph("<b>Generated:</b> " + now_str, body_style)
        ],
        [
            Paragraph(f"<b>Case Reference:</b> {settings.CASE_ID}", body_style),
            Paragraph(f"<b>Simulation Room ID:</b> {room_id}", body_style)
        ],
        [
            Paragraph(f"<b>Primary Credential ID:</b> {settings.PRIMARY_CREDENTIAL_ID}", body_style),
            Paragraph(f"<b>Origin Ticket Ref:</b> {settings.PRIMARY_TICKET_REF}", body_style)
        ],
        [
            Paragraph(f"<b>Containment Status:</b> " + ("CONTAINED (REVOKED)" if credential_record.get("is_revoked") else "ACTIVE (MONITORING)"), body_style),
            Paragraph(f"<b>Calculated Risk Score:</b> {stats.get('risk_score', 0)} / 100", body_style)
        ]
    ]
    meta_table = Table(meta_data, colWidths=[270, 270])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # 2. Executive Summary
    story.append(Paragraph("1. EXECUTIVE INCIDENT SUMMARY", h2_style))
    is_rev = credential_record.get("is_revoked")
    rev_text = "The credential was formally revoked by the SOC investigator, effectively severing further access." if is_rev else "The credential currently remains under active real-time surveillance."
    summary_text = (
        f"On evaluation of telemetry in room <b>{room_id}</b>, a sequence of unauthorized operations was correlated with "
        f"synthetic API credential identifier <b>{settings.PRIMARY_CREDENTIAL_ID}</b>. Initial provenance traces to support "
        f"ticket <b>{settings.PRIMARY_TICKET_REF}</b> issued for freight partner integration. The credential was subsequently "
        f"observed executing data extraction and restricted bulk export attempts. {rev_text} "
        f"A total of {stats.get('total_events', 0)} technical events were logged to the tamper-evident cryptographic ledger."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 10))

    # 3. Cryptographic Hash Chain Audit Verification
    story.append(Paragraph("2. CRYPTOGRAPHIC TAMPER-EVIDENT AUDIT STATUS", h2_style))
    audit_res = verify_hash_chain(events)
    valid_status = "PASS - HASH CHAIN INTACT & VALID" if audit_res.get("valid") else "FAIL - INTEGRITY VIOLATION DETECTED"
    audit_data = [
        ["Audit Check", "Result", "Technical Details"],
        [
            "Chain Verification",
            valid_status,
            f"Verified {audit_res.get('total_verified', 0)} linked event blocks from Genesis."
        ],
        [
            "Genesis Hash",
            "CONFIRMED",
            "0000000000000000000000000000000000000000000000000000000000000000"
        ],
        [
            "Latest Head Hash",
            "ACTIVE",
            str(audit_res.get("latest_hash", "N/A"))[:36] + "..."
        ]
    ]
    audit_table = Table(audit_data, colWidths=[120, 160, 260])
    audit_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(audit_table)
    story.append(Spacer(1, 10))

    # 4. Multi-Source Technical Correlation Findings
    story.append(Paragraph("3. MULTI-SOURCE CORRELATION FINDINGS", h2_style))
    correlations = build_correlation_matrix(events, alerts, credential_record)
    corr_rows = [["Finding ID", "Confidence", "Assessment Title & Evidence"]]
    for c in correlations:
        points_str = "; ".join(c.get("evidence_points", []))
        cell_content = f"<b>{c.get('title')}</b><br/>{c.get('description')}<br/><i>Evidence: {points_str}</i>"
        corr_rows.append([
            c.get("finding_id"),
            c.get("confidence"),
            Paragraph(cell_content, body_style)
        ])
    corr_table = Table(corr_rows, colWidths=[90, 110, 340])
    corr_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(corr_table)
    story.append(Spacer(1, 10))

    # 5. Confirmed Technical Events Log
    story.append(Paragraph("4. CONFIRMED TECHNICAL EVENT TIMELINE (LATEST)", h2_style))
    evt_rows = [["Event ID", "Timestamp", "Action", "Decision", "HTTP", "Device"]]
    for e in events[-12:]:
        evt_rows.append([
            str(e.get("event_id"))[:12],
            str(e.get("timestamp"))[11:19],
            str(e.get("action"))[:22],
            str(e.get("decision")),
            str(e.get("http_status")),
            str(e.get("device_label", "N/A"))[:16]
        ])
    if len(evt_rows) == 1:
        evt_rows.append(["None", "-", "No events recorded", "-", "-", "-"])
    evt_table = Table(evt_rows, colWidths=[70, 60, 150, 70, 45, 145])
    evt_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 7),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#f8fafc')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(evt_table)
    story.append(Spacer(1, 12))

    # 6. Evidence Limitations & Boundaries
    story.append(Paragraph("5. FORENSIC EVIDENCE LIMITATIONS & METHODOLOGY", h2_style))
    story.append(Paragraph(settings.EVIDENCE_LIMITATIONS, disclaimer_style))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Notice: Credential bvk-7f3a is a test credential identifier. BlueVault production root secrets were never accessed or recovered. "
        "Network IP addresses indicate routing origin, not physical identity of a specific individual. "
        "SHA-256 hash chaining detects ledger modifications but does not prevent admin overwrite of physical storage without WORM controls.",
        disclaimer_style
    ))
    
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes

def generate_json_report(
    room_id: str,
    stats: Dict[str, Any],
    events: List[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    credential_record: Dict[str, Any]
) -> Dict[str, Any]:
    """Builds a structured JSON forensics export object."""
    audit_res = verify_hash_chain(events)
    correlations = build_correlation_matrix(events, alerts, credential_record)
    
    return {
        "report_metadata": {
            "case_id": settings.CASE_ID,
            "company_name": settings.COMPANY_NAME,
            "room_id": room_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "report_version": "2.0.0",
            "classification": "CONFIDENTIAL // LAW ENFORCEMENT & SOC FORENSICS"
        },
        "case_context": {
            "primary_credential_id": settings.PRIMARY_CREDENTIAL_ID,
            "primary_ticket_ref": settings.PRIMARY_TICKET_REF,
            "credential_status": credential_record.get("status", "UNKNOWN"),
            "is_revoked": bool(credential_record.get("is_revoked")),
            "revoked_at": credential_record.get("revoked_at"),
            "revocation_reason": credential_record.get("revocation_reason")
        },
        "overview_statistics": stats,
        "tamper_evident_audit": audit_res,
        "multi_source_correlations": correlations,
        "threat_alerts": alerts,
        "confirmed_events": events,
        "evidence_limitations": settings.EVIDENCE_LIMITATIONS
    }
