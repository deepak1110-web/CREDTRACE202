"""
CREDTRACE V2 - Master Pytest Test Suite
Tests all core forensic engine, database, detection, correlation, and containment modules
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import pytest
from app.config import settings
from app.database import (
    init_db,
    get_credential,
    update_credential_secret,
    record_security_event,
    get_security_events,
    get_threat_alerts,
    get_overview_statistics,
    revoke_credential,
    reset_room_state,
    list_support_tickets,
    create_support_ticket
)
from app.security import (
    verify_password,
    hash_password,
    verify_secret,
    generate_synthetic_secret,
    compute_event_hash,
    verify_hash_chain,
    GENESIS_HASH
)
from app.rules import evaluate_threat_rules, build_correlation_matrix
from app.reporting import generate_pdf_report, generate_json_report

TEST_ROOM = "PYTEST-AUDIT-ROOM"

@pytest.fixture(autouse=True)
def setup_clean_room():
    init_db()
    reset_room_state(TEST_ROOM)
    yield
    reset_room_state(TEST_ROOM)

def test_password_hashing():
    pw = "Password123!"
    hashed = hash_password(pw)
    assert verify_password(pw, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

def test_synthetic_secret_generation():
    secret = generate_synthetic_secret()
    assert secret.startswith("sec_live_")
    assert len(secret) == 41

def test_cryptographic_hash_chain():
    prev = GENESIS_HASH
    h1 = compute_event_hash(prev, "EVT-01", "2026-11-20T00:00:00Z", "bvk-7f3a", "AUTH", "AUTH:bvk-7f3a", "ALLOWED", 200, "DEV-01")
    h2 = compute_event_hash(h1, "EVT-02", "2026-11-20T00:01:00Z", "bvk-7f3a", "QUERY", "DB:DATA", "ALLOWED", 200, "DEV-01")
    
    events = [
        {"event_id": "EVT-01", "timestamp": "2026-11-20T00:00:00Z", "credential_id": "bvk-7f3a", "action": "AUTH", "resource": "AUTH:bvk-7f3a", "decision": "ALLOWED", "http_status": 200, "device_label": "DEV-01", "previous_hash": prev, "current_hash": h1},
        {"event_id": "EVT-02", "timestamp": "2026-11-20T00:01:00Z", "credential_id": "bvk-7f3a", "action": "QUERY", "resource": "DB:DATA", "decision": "ALLOWED", "http_status": 200, "device_label": "DEV-01", "previous_hash": h1, "current_hash": h2}
    ]
    res = verify_hash_chain(events)
    assert res["valid"] is True
    assert res["total_verified"] == 2

def test_credential_retrieval_and_update():
    cred = get_credential(TEST_ROOM)
    assert cred is not None
    assert cred["credential_id"] == "bvk-7f3a"
    assert cred["status"] == "ACTIVE"

    new_sec = generate_synthetic_secret()
    updated = update_credential_secret(TEST_ROOM, "bvk-7f3a", new_sec)
    assert updated["synthetic_secret"] == new_sec
    assert verify_secret(new_sec, updated["secret_hash"]) is True

def test_support_tickets_management():
    tickets = list_support_tickets(TEST_ROOM)
    assert len(tickets) >= 1
    assert any(t["ticket_id"] == "TKT-48213" for t in tickets)

    created = create_support_ticket(TEST_ROOM, "New API Request", "Integration", "High", "Test description", "marcus.vance")
    assert created["ticket_id"].startswith("TKT-")

def test_threat_detection_restricted_export():
    evt, alerts = record_security_event(
        room_id=TEST_ROOM,
        action="BULK_EXPORT_ATTEMPT",
        resource="RESTRICTED:ALL_GLOBAL_CUSTOMERS_AND_TRANSACTIONS",
        decision="DENIED",
        http_status=403,
        ip_address="192.168.1.100",
        user_agent="Adversary-Simulator/2.0",
        credential_id="bvk-7f3a",
        device_label="LAPTOP-02-ADVERSARY",
        detection_tags=["RESTRICTED_DATA_EXFILTRATION"]
    )
    assert evt["http_status"] == 403
    assert len(alerts) >= 1
    assert any(a["rule_id"] == "RULE-002-RESTRICTED-EXPORT" for a in alerts)

def test_containment_and_revocation():
    # 1. Revoke credential
    rev_res = revoke_credential(TEST_ROOM, "bvk-7f3a", "Suspected compromised token", "INV-CHENG-01")
    assert rev_res["status"] == "REVOKED"
    
    cred = get_credential(TEST_ROOM)
    assert cred["is_revoked"] == 1 or cred["is_revoked"] is True
    assert cred["status"] == "REVOKED"

    # 2. Record post-revocation attempt
    evt, alerts = record_security_event(
        room_id=TEST_ROOM,
        action="CUSTOMER_DATA_QUERY",
        resource="DB:CUSTOMERS",
        decision="DENIED",
        http_status=403,
        ip_address="192.168.1.100",
        user_agent="Adversary-Simulator/2.0",
        credential_id="bvk-7f3a",
        device_label="LAPTOP-02-ADVERSARY",
        detection_tags=["POST_REVOCATION_ATTEMPT"]
    )
    assert any(a["rule_id"] == "RULE-001-POST-REVOCATION" for a in alerts)

def test_multi_source_correlation_engine():
    # Record events
    record_security_event(TEST_ROOM, "AUTH_SUCCESS", "AUTH", "ALLOWED", 200, "192.168.1.1", "curl/7.68", credential_id="bvk-7f3a")
    record_security_event(TEST_ROOM, "BULK_EXPORT_ATTEMPT", "EXPORT", "DENIED", 403, "192.168.1.1", "curl/7.68", credential_id="bvk-7f3a")
    
    events = get_security_events(TEST_ROOM, limit=50)
    alerts = get_threat_alerts(TEST_ROOM, limit=50)
    cred = get_credential(TEST_ROOM)
    
    findings = build_correlation_matrix(events, alerts, cred)
    assert len(findings) >= 1
    assert any(f["confidence"] == "Strong technical correlation" for f in findings)

def test_forensic_reports_generation():
    events = get_security_events(TEST_ROOM, limit=50)
    alerts = get_threat_alerts(TEST_ROOM, limit=50)
    cred = get_credential(TEST_ROOM)
    stats = get_overview_statistics(TEST_ROOM)

    # 1. PDF
    pdf_bytes = generate_pdf_report(TEST_ROOM, stats, events, alerts, cred)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes.startswith(b"%PDF")

    # 2. JSON
    json_data = generate_json_report(TEST_ROOM, stats, events, alerts, cred)
    assert json_data["report_metadata"]["case_id"] == "CR-26-047"
    assert "tamper_evident_audit" in json_data
