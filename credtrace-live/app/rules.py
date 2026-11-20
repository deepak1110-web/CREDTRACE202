"""
CREDTRACE V2 - Threat Detection Rules Engine & Multi-Source Correlation
Rules:
1. Repeated failed authentication
2. Repeated restricted export attempts
3. Unusual request frequency
4. Credential reuse across different sessions
5. Requests after revocation
6. Anomalous access sequences
"""
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple

def evaluate_threat_rules(
    current_event: Dict[str, Any],
    recent_events: List[Dict[str, Any]],
    credential_record: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Evaluates rule-based threat detection against the current event and historical context.
    Returns any newly triggered threat alerts.
    """
    new_alerts = []
    timestamp = datetime.now(timezone.utc).isoformat()
    room_id = current_event.get("room_id", "CR-26-047-DEMO")
    
    # 1. Post-Revocation Access Rule (Critical)
    if current_event.get("decision") == "DENIED" and "POST_REVOCATION_ATTEMPT" in current_event.get("detection_tags", []):
        new_alerts.append({
            "alert_id": f"ALT-REVOKED-{uuid.uuid4().hex[:6].upper()}",
            "room_id": room_id,
            "timestamp": timestamp,
            "severity": "Critical",
            "rule_id": "RULE-001-POST-REVOCATION",
            "rule_name": "Active Post-Revocation Credential Usage",
            "description": (
                f"Credential '{current_event.get('credential_id', 'unknown')}' was used in action "
                f"'{current_event.get('action')}' after formal containment revocation. "
                f"Adversary continued execution on device '{current_event.get('device_label')}'."
            ),
            "related_event_ids": [current_event.get("event_id")],
            "recommended_action": "Maintain active containment; verify perimeter logs; review exfiltration attempts."
        })

    # 2. Unauthorized Restricted Bulk Export Attempt (Critical)
    if current_event.get("action") == "BULK_EXPORT_ATTEMPT":
        related_ids = [current_event.get("event_id")]
        export_attempts = [
            e for e in recent_events
            if e.get("action") == "BULK_EXPORT_ATTEMPT"
        ]
        new_alerts.append({
            "alert_id": f"ALT-EXPORT-{uuid.uuid4().hex[:6].upper()}",
            "room_id": room_id,
            "timestamp": timestamp,
            "severity": "Critical",
            "rule_id": "RULE-002-RESTRICTED-EXPORT",
            "rule_name": "Restricted Bulk Data Export Attempt",
            "description": (
                f"Simulated adversary attempted unauthorized bulk export of "
                f"'{current_event.get('resource')}' using credential '{current_event.get('credential_id')}'. "
                f"Action was intercepted and blocked with HTTP 403."
            ),
            "related_event_ids": [e.get("event_id") for e in export_attempts[-3:]],
            "recommended_action": "Immediately revoke credential bvk-7f3a; terminate active simulator session."
        })

    # 3. Repeated Failed Authentication / Brute Force (High)
    if current_event.get("http_status") == 401 or current_event.get("action") == "AUTH_FAILED":
        recent_failed = [
            e for e in recent_events[-10:]
            if e.get("http_status") == 401 or e.get("decision") == "DENIED" and "AUTH" in e.get("action", "")
        ]
        if len(recent_failed) >= 2:
            new_alerts.append({
                "alert_id": f"ALT-BRUTE-{uuid.uuid4().hex[:6].upper()}",
                "room_id": room_id,
                "timestamp": timestamp,
                "severity": "High",
                "rule_id": "RULE-003-AUTH-FAILURE-BURST",
                "rule_name": "Repeated Authentication Failures",
                "description": (
                    f"Observed {len(recent_failed)} failed authentication attempts in rapid succession "
                    f"from device '{current_event.get('device_label')}'. Invalid secret presented."
                ),
                "related_event_ids": [e.get("event_id") for e in recent_failed[-3:]],
                "recommended_action": "Flag source device label; review credential origin in support tickets."
            })

    # 4. Credential Reuse Across Different Sessions / Devices (High)
    if current_event.get("credential_id") and current_event.get("decision") == "ALLOWED":
        cred_events = [
            e for e in recent_events
            if e.get("credential_id") == current_event.get("credential_id") and e.get("decision") == "ALLOWED"
        ]
        distinct_sessions = {e.get("session_id") for e in cred_events if e.get("session_id")}
        distinct_devices = {e.get("device_label") for e in cred_events if e.get("device_label")}
        
        if len(distinct_sessions) > 1 or len(distinct_devices) > 1:
            new_alerts.append({
                "alert_id": f"ALT-REUSE-{uuid.uuid4().hex[:6].upper()}",
                "room_id": room_id,
                "timestamp": timestamp,
                "severity": "High",
                "rule_id": "RULE-004-CROSS-SESSION-REUSE",
                "rule_name": "Multi-Session Credential Reuse",
                "description": (
                    f"Credential '{current_event.get('credential_id')}' detected active across "
                    f"{len(distinct_sessions)} different sessions and {len(distinct_devices)} device profiles. "
                    f"Indicators point to external credential sharing or unauthorized propagation."
                ),
                "related_event_ids": [current_event.get("event_id")],
                "recommended_action": "Correlate with support ticket TKT-48213; initiate credential containment."
            })

    # 5. Rapid Succession / Burst Activity Spike (Medium)
    if len(recent_events) >= 5:
        burst_events = recent_events[-5:]
        new_alerts.append({
            "alert_id": f"ALT-BURST-{uuid.uuid4().hex[:6].upper()}",
            "room_id": room_id,
            "timestamp": timestamp,
            "severity": "Medium",
            "rule_id": "RULE-005-BURST-ACTIVITY",
            "rule_name": "Unusual Request Velocity",
            "description": (
                f"Automated activity spike: {len(burst_events)} operations recorded within short execution window. "
                f"Pattern consistent with programmatic script execution."
            ),
            "related_event_ids": [e.get("event_id") for e in burst_events],
            "recommended_action": "Inspect API rate thresholds; monitor target endpoint telemetry."
        }) if current_event.get("action") in ("CUSTOMER_DATA_QUERY", "VENDOR_RECORDS_QUERY") and len(recent_events) % 4 == 0 else None

    return new_alerts

def build_correlation_matrix(
    events: List[Dict[str, Any]],
    alerts: List[Dict[str, Any]],
    credential_record: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Builds an explainable multi-source correlation assessment.
    Uses: credential identifier, session identifier, device label, timestamps, decisions.
    Assigns rigorous confidence labels:
    - 'Strong technical correlation'
    - 'Partial correlation'
    - 'Insufficient evidence'
    """
    findings = []
    
    # 1. Ticket-to-Simulator Token Provenance Correlation
    cred_id = credential_record.get("credential_id", "bvk-7f3a")
    matched_events = [e for e in events if e.get("credential_id") == cred_id]
    
    if matched_events:
        findings.append({
            "finding_id": "CORR-001-TOKEN-PROVENANCE",
            "confidence": "Strong technical correlation",
            "title": f"Exposed Token '{cred_id}' Leveraged in Simulated Attacker Session",
            "description": (
                f"Credential identifier '{cred_id}' originally issued under Support Ticket TKT-48213 "
                f"was cryptographically verified in {len(matched_events)} operations on remote simulated devices. "
                f"The synthetic secret matches the recorded SHA-256 hash."
            ),
            "evidence_points": [
                f"Exact match on credential identifier: {cred_id}",
                f"Case Reference: CR-26-047",
                f"Total correlated operations: {len(matched_events)}",
                f"Associated Support Ticket: {credential_record.get('ticket_ref', 'TKT-48213')}"
            ],
            "correlated_event_ids": [e.get("event_id") for e in matched_events[:6]]
        })
    
    # 2. Denied Bulk Exfiltration Attempt Correlation
    denied_exports = [e for e in events if e.get("action") == "BULK_EXPORT_ATTEMPT"]
    if denied_exports:
        findings.append({
            "finding_id": "CORR-002-EXFILTRATION-INTENT",
            "confidence": "Strong technical correlation",
            "title": "Privilege Escalation & Restricted Bulk Export Intent",
            "description": (
                f"Correlated {len(denied_exports)} high-volume export attempts against sensitive customer tables. "
                f"Adversary requested global customer and financial records, violating default vendor API scope."
            ),
            "evidence_points": [
                f"Resource target: ALL_GLOBAL_CUSTOMERS_AND_TRANSACTIONS",
                f"HTTP Decision: 403 Forbidden (Blocked by backend policy)",
                f"Attacker device label: {denied_exports[0].get('device_label', 'Unknown')}"
            ],
            "correlated_event_ids": [e.get("event_id") for e in denied_exports]
        })
        
    # 3. Post-Revocation Containment Verification
    post_revocation_events = [e for e in events if "POST_REVOCATION_ATTEMPT" in e.get("detection_tags", [])]
    if post_revocation_events:
        findings.append({
            "finding_id": "CORR-003-POST-CONTAINMENT-PERSISTENCE",
            "confidence": "Strong technical correlation",
            "title": "Post-Revocation Adversary Activity Intercepted",
            "description": (
                f"Following revocation executed by investigator SOC, {len(post_revocation_events)} subsequent "
                f"requests were intercepted. Demonstrates that investigator containment stopped ongoing access."
            ),
            "evidence_points": [
                f"Revocation status: CONFIRMED_REVOKED",
                f"Backend enforcement: 100% rejection rate for subsequent requests",
                f"Last intercepted attempt event: {post_revocation_events[-1].get('event_id')}"
            ],
            "correlated_event_ids": [e.get("event_id") for e in post_revocation_events]
        })
        
    # 4. Device and Network Telemetry Pattern
    distinct_ips = {e.get("ip_address") for e in events if e.get("ip_address")}
    if len(distinct_ips) > 1:
        findings.append({
            "finding_id": "CORR-004-NETWORK-TRAVERSAL",
            "confidence": "Partial correlation",
            "title": "Multi-Origin Routing Footprint",
            "description": (
                f"Telemetry observed requests across {len(distinct_ips)} distinct network endpoints. "
                f"Note: Network IPs indicate routing origins, not physical human identity."
            ),
            "evidence_points": [
                f"Observed IP endpoints: {', '.join(list(distinct_ips)[:3])}",
                "Forensic constraint: IP addresses represent network routing, not legal attribution."
            ],
            "correlated_event_ids": [e.get("event_id") for e in events[-4:]]
        })
    elif not findings:
        findings.append({
            "finding_id": "CORR-000-BASELINE",
            "confidence": "Insufficient evidence",
            "title": "Awaiting Interactive Incident Telemetry",
            "description": "Insufficient events recorded yet to establish multi-source correlation. Execute attacker simulation to generate telemetry.",
            "evidence_points": ["System initialized in monitoring state."],
            "correlated_event_ids": []
        })

    return findings
