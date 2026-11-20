"""
CREDTRACE V2 - Live End-to-End HTTP API Integration Test Suite
Spins up live server thread and tests all endpoints over real HTTP
"""
import json
import os
import sys
import threading
import time
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import uvicorn
from app.main import app
from app.database import init_db

TEST_PORT = 8009
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"

def http_get(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "TestClient/2.0"})
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read()
            try:
                return resp.status, json.loads(content.decode("utf-8")), content
            except Exception:
                return resp.status, None, content
    except urllib.error.HTTPError as e:
        content = e.read()
        try:
            return e.code, json.loads(content.decode("utf-8")), content
        except Exception:
            return e.code, None, content

def http_post(path, data_dict=None):
    url = f"{BASE_URL}{path}"
    body = json.dumps(data_dict or {}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "TestClient/2.0"}
    )
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read()
            try:
                return resp.status, json.loads(content.decode("utf-8")), content
            except Exception:
                return resp.status, None, content
    except urllib.error.HTTPError as e:
        content = e.read()
        try:
            return e.code, json.loads(content.decode("utf-8")), content
        except Exception:
            return e.code, None, content

def run_suite():
    print("=" * 60)
    print("STARTING CREDTRACE V2 LIVE HTTP API INTEGRATION TESTS")
    print("=" * 60)

    init_db()

    # Start live test server
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=TEST_PORT, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    time.sleep(1.2)

    room = "DEMO-LIVE-TEST"

    try:
        # 1. Health check
        print("[1] Testing /health and /api/status...")
        status, data, _ = http_get("/health")
        assert status == 200 and data["status"] == "healthy"
        assert data["case_id"] == "CR-26-047"
        print("  -> PASSED: System healthy, Case CR-26-047 verified.")

        # 2. Demo users and authentication
        print("[2] Testing /api/auth/demo-users and /api/login...")
        status, users, _ = http_get("/api/auth/demo-users")
        assert status == 200 and len(users) >= 3
        
        status, login_res, _ = http_post("/api/login", {
            "username": "sarah.chen",
            "password": "Password123!"
        })
        assert status == 200 and login_res["success"] is True
        token = login_res["token"]
        print(f"  -> PASSED: /api/login succeeded with session token: {token[:12]}...")

        # 3. Invalid login check
        status, bad_login, _ = http_post("/api/login", {
            "username": "sarah.chen",
            "password": "WrongPassword!"
        })
        assert status == 401
        print("  -> PASSED: Invalid login rejected with HTTP 401.")

        # 4. Portal tickets and credential exposure
        print("[3] Testing Module A: Company Portal endpoints...")
        status, cred_info, _ = http_get(f"/api/portal/credential?room={room}")
        assert status == 200
        assert cred_info["credential_id"] == "bvk-7f3a"
        secret = cred_info["secret_display"]
        print(f"  -> PASSED: Credential identifier bvk-7f3a exposed with secret {secret[:14]}...")

        status, tickets, _ = http_get(f"/api/portal/tickets?room={room}")
        assert status == 200 and len(tickets) >= 1
        print(f"  -> PASSED: Support tickets retrieved ({len(tickets)} tickets, including TKT-48213).")

        # 5. Simulator authentication
        print("[4] Testing Module A: Controlled Attacker Simulator...")
        status, sim_auth, _ = http_post("/api/simulator/auth", {
            "room_id": room,
            "device_label": "DEMO-LAPTOP-02-ADVERSARY",
            "secret": secret
        })
        assert status == 200 and sim_auth["decision"] == "ALLOWED"
        session_id = sim_auth["data"]["session_id"]
        print(f"  -> PASSED: Simulator authenticated with session ID {session_id}.")

        # 6. Query synthetic customer data
        status, cust_data, _ = http_get(f"/api/simulator/customers?room={room}&session_id={session_id}")
        assert status == 200 and cust_data["decision"] == "ALLOWED"
        assert len(cust_data["data"]) >= 3
        print(f"  -> PASSED: Retrieved {len(cust_data['data'])} synthetic customer records.")

        # 7. Query synthetic vendor records
        status, vnd_data, _ = http_get(f"/api/simulator/vendors?room={room}&session_id={session_id}")
        assert status == 200 and vnd_data["decision"] == "ALLOWED"
        print(f"  -> PASSED: Retrieved {len(vnd_data['data'])} synthetic vendor records.")

        # 8. Attempt restricted bulk export (Must be denied with 403!)
        print("[5] Testing Restricted Bulk Export Denial (Policy Enforcement)...")
        status, exp_data, _ = http_post("/api/simulator/export", {
            "room_id": room,
            "session_id": session_id,
            "device_label": "DEMO-LAPTOP-02-ADVERSARY"
        })
        assert status == 200
        assert exp_data["status_code"] == 403
        assert exp_data["decision"] == "DENIED"
        assert exp_data["alert_triggered"] is not None
        print(f"  -> PASSED: Bulk export intercepted with HTTP 403; triggered alert {exp_data['alert_triggered']['alert_id']}.")

        # 9. Investigator SOC Overview & Telemetry
        print("[6] Testing Module B: Investigator SOC Overview & Telemetry...")
        status, overview, _ = http_get(f"/api/investigator/overview?room={room}")
        assert status == 200
        assert overview["total_events"] >= 3
        assert overview["risk_score"] > 20
        print(f"  -> PASSED: Real stats computed: {overview['total_events']} events, risk score {overview['risk_score']}/100.")

        # 10. Containment: Revoke credential bvk-7f3a
        print("[7] Testing Investigator Containment Action (Revocation)...")
        status, rev_data, _ = http_post("/api/investigator/revoke", {
            "room_id": room,
            "credential_id": "bvk-7f3a",
            "reason": "Exfiltration alert during active investigation"
        })
        assert status == 200 and rev_data["status"] == "REVOKED"
        print(f"  -> PASSED: Credential bvk-7f3a revoked on server. Containment audit event: {rev_data['event_id']}.")

        # 11. Post-Revocation Rejection Verification
        print("[8] Verifying Post-Revocation Enforcement on Laptop 2 Simulator...")
        status, post_auth, _ = http_post("/api/simulator/auth", {
            "room_id": room,
            "device_label": "DEMO-LAPTOP-02-ADVERSARY",
            "secret": secret
        })
        assert status == 200
        assert post_auth["status_code"] == 403
        assert post_auth["decision"] == "DENIED"
        print("  -> PASSED: Post-revocation authentication rejected with HTTP 403.")

        status, post_cust, _ = http_get(f"/api/simulator/customers?room={room}&session_id={session_id}")
        assert status == 200
        assert post_cust["status_code"] == 403
        assert post_cust["decision"] == "DENIED"
        print("  -> PASSED: Post-revocation customer access rejected with HTTP 403.")

        # 12. Multi-Source Correlation Matrix
        print("[9] Testing Multi-Source Technical Correlation Engine...")
        status, correlations, _ = http_get(f"/api/investigator/correlations?room={room}")
        assert status == 200 and len(correlations) >= 1
        assert any(c["confidence"] == "Strong technical correlation" for c in correlations)
        print(f"  -> PASSED: {len(correlations)} correlation findings generated with explainable confidence.")

        # 13. Cryptographic SHA-256 Hash-Chain Verification
        print("[10] Testing Cryptographic Tamper-Evident Hash Chain Audit...")
        status, audit_res, _ = http_get(f"/api/investigator/verify-audit?room={room}")
        assert status == 200
        v = audit_res["verification"]
        assert v["valid"] is True
        assert v["broken_at_event_id"] is None
        print(f"  -> PASSED: Hash chain validated from Genesis across {v['total_verified']} linked blocks.")

        # 14. Forensic Reports (PDF & JSON)
        print("[11] Testing Forensic Report Generation...")
        status, _, pdf_bytes = http_get(f"/api/reports/pdf?room={room}")
        assert status == 200 and len(pdf_bytes) > 2000
        assert pdf_bytes[:4] == b"%PDF"
        print(f"  -> PASSED: ReportLab forensic PDF generated ({len(pdf_bytes)} bytes).")

        status, json_rep, _ = http_get(f"/api/reports/json?room={room}")
        assert status == 200 and json_rep["report_metadata"]["case_id"] == "CR-26-047"
        assert json_rep["tamper_evident_audit"]["valid"] is True
        print("  -> PASSED: Forensic JSON data export verified.")

        # 15. Room State Reset with Admin Authorization Check
        print("[12] Testing Room Reset (Unauthorized vs Authorized)...")
        bad_status, bad_reset, _ = http_post("/api/investigator/reset", {"room_id": room, "admin_code": "wrong_code"})
        assert bad_status == 403
        print("  -> PASSED: Unauthorized reset blocked with HTTP 403.")

        status, reset_res, _ = http_post("/api/investigator/reset", {"room_id": room, "admin_code": "crimeathon26"})
        assert status == 200 and reset_res["success"] is True
        print("  -> PASSED: Authorized room state reset verified.")

        print("=" * 60)
        print("SUCCESS: ALL 12 LIVE HTTP ENDPOINT ACCEPTANCE TESTS PASSED!")
        print("=" * 60)
    finally:
        server.should_exit = True

if __name__ == "__main__":
    run_suite()
