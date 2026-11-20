"""
Direct test runner for CREDTRACE
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

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
    list_support_tickets
)
from app.security import verify_hash_chain, generate_synthetic_secret, verify_secret
from app.reporting import generate_pdf_report, generate_json_report

def run_all_checks():
    print("[1/9] Initializing database...")
    init_db()
    print("  -> Database initialized.")

    room = "TEST-RUNNER-ROOM"
    reset_room_state(room)

    print("[2/9] Testing credential management...")
    cred = get_credential(room)
    assert cred is not None
    assert cred["credential_id"] == "bvk-7f3a"
    assert cred["status"] == "ACTIVE"
    old_secret = cred["synthetic_secret"]

    new_secret = generate_synthetic_secret()
    updated = update_credential_secret(room, "bvk-7f3a", new_secret)
    assert updated["synthetic_secret"] == new_secret
    assert verify_secret(new_secret, updated["secret_hash"])
    print("  -> Credential generation and verification passed.")

    print("[3/9] Testing support tickets...")
    tickets = list_support_tickets(room)
    assert len(tickets) >= 1
    assert any(t["ticket_id"] == "TKT-48213" for t in tickets)
    print("  -> Support ticket TKT-48213 confirmed.")

    print("[4/9] Testing security event recording & SHA-256 hash chaining...")
    evt1, alerts1 = record_security_event(
        room_id=room,
        action="SIMULATOR_AUTH_SUCCESS",
        resource="AUTH:bvk-7f3a",
        decision="ALLOWED",
        http_status=200,
        ip_address="192.168.1.55",
        user_agent="Adversary-Simulator/2.0",
        credential_id="bvk-7f3a",
        session_id="sess_001",
        device_label="DEMO-LAPTOP-02"
    )
    assert evt1["previous_hash"] is not None
    assert evt1["current_hash"] is not None

    evt2, alerts2 = record_security_event(
        room_id=room,
        action="BULK_EXPORT_ATTEMPT",
        resource="RESTRICTED:ALL_GLOBAL_CUSTOMERS_AND_TRANSACTIONS",
        decision="DENIED",
        http_status=403,
        ip_address="192.168.1.55",
        user_agent="Adversary-Simulator/2.0",
        credential_id="bvk-7f3a",
        session_id="sess_001",
        device_label="DEMO-LAPTOP-02",
        detection_tags=["RESTRICTED_DATA_EXFILTRATION"]
    )
    assert len(alerts2) >= 1
    assert any(a["rule_id"] == "RULE-002-RESTRICTED-EXPORT" for a in alerts2)
    print("  -> Hash chaining and restricted export alert passed.")

    print("[5/9] Testing multi-source correlation engine...")
    from app.rules import build_correlation_matrix
    events = get_security_events(room, limit=50)
    alerts = get_threat_alerts(room, limit=50)
    correlations = build_correlation_matrix(events, alerts, updated)
    assert len(correlations) >= 1
    assert any(c["confidence"] == "Strong technical correlation" for c in correlations)
    print("  -> Correlation engine passed with Strong technical correlation.")

    print("[6/9] Testing containment & revocation...")
    rev_res = revoke_credential(
        room_id=room,
        credential_id="bvk-7f3a",
        reason="Detected restricted export attempt",
        investigator_id="INV-ELENA-01"
    )
    assert rev_res["status"] == "REVOKED"
    refreshed_cred = get_credential(room)
    assert refreshed_cred["is_revoked"] == 1 or refreshed_cred["is_revoked"] is True
    print("  -> Credential bvk-7f3a containment confirmed.")

    print("[7/9] Testing post-revocation attempt recording & detection...")
    evt3, alerts3 = record_security_event(
        room_id=room,
        action="CUSTOMER_DATA_QUERY",
        resource="DB:CUSTOMERS_GLOBAL_MANIFEST",
        decision="DENIED",
        http_status=403,
        ip_address="192.168.1.55",
        user_agent="Adversary-Simulator/2.0",
        credential_id="bvk-7f3a",
        session_id="sess_001",
        device_label="DEMO-LAPTOP-02",
        detection_tags=["POST_REVOCATION_ATTEMPT"]
    )
    assert any(a["rule_id"] == "RULE-001-POST-REVOCATION" for a in alerts3)
    print("  -> Post-revocation detection rule passed.")

    print("[8/9] Testing cryptographic hash chain verification...")
    all_events = get_security_events(room, limit=100)
    verify_res = verify_hash_chain(all_events)
    assert verify_res["valid"] is True
    assert verify_res["total_verified"] >= 3
    print(f"  -> Hash chain verified intact across {verify_res['total_verified']} blocks.")

    print("[9/9] Testing forensic PDF and JSON reports...")
    stats = get_overview_statistics(room)
    pdf_bytes = generate_pdf_report(room, stats, all_events, alerts, refreshed_cred)
    assert len(pdf_bytes) > 2000
    assert pdf_bytes[:4] == b"%PDF"

    json_report = generate_json_report(room, stats, all_events, alerts, refreshed_cred)
    assert json_report["report_metadata"]["case_id"] == "CR-26-047"
    assert json_report["tamper_evident_audit"]["valid"] is True
    print("  -> PDF and JSON reports generated successfully.")

    print("\nALL 9 CORE FORENSIC ENGINE & BACKEND ACCEPTANCE CHECKS PASSED!")

if __name__ == "__main__":
    run_all_checks()
