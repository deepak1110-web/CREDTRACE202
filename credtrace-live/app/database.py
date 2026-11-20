"""
CREDTRACE V2 - Database Manager
Dual-engine persistence layer:
- PostgreSQL (Neon / Render production)
- SQLite (Local development / CI test suite)
"""
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from app.config import settings, BASE_DIR
from app.security import (
    hash_password,
    hash_secret,
    compute_event_hash,
    GENESIS_HASH,
    generate_synthetic_secret
)
from app.rules import evaluate_threat_rules, build_correlation_matrix

# Determine DB Engine
IS_POSTGRES = settings.DATABASE_URL.startswith("postgres://") or settings.DATABASE_URL.startswith("postgresql://")

if IS_POSTGRES:
    import psycopg
    from psycopg.rows import dict_row

def get_db():
    """Returns an active database connection."""
    if IS_POSTGRES:
        conn = psycopg.connect(settings.DATABASE_URL, row_factory=dict_row)
        return conn
    else:
        db_path = settings.DATABASE_URL.replace("sqlite:///", "")
        conn = sqlite3.connect(db_path, check_same_thread=False, timeout=30.0)
        if not db_path.startswith(":memory:"):
            try:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=5000")
            except Exception:
                pass
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    """Initializes tables and default seed records."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Tables DDL
    if IS_POSTGRES:
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id VARCHAR(64) PRIMARY KEY,
            company_name VARCHAR(255) NOT NULL,
            description TEXT,
            status VARCHAR(64) NOT NULL,
            created_at VARCHAR(64) NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(128) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            full_name VARCHAR(128) NOT NULL,
            role VARCHAR(64) NOT NULL,
            department VARCHAR(128) NOT NULL
        );
        CREATE TABLE IF NOT EXISTS credentials (
            room_id VARCHAR(128) NOT NULL,
            credential_id VARCHAR(64) NOT NULL,
            case_id VARCHAR(64) NOT NULL,
            secret_hash VARCHAR(255) NOT NULL,
            synthetic_secret VARCHAR(255) NOT NULL,
            status VARCHAR(64) NOT NULL,
            created_at VARCHAR(64) NOT NULL,
            expires_at VARCHAR(64) NOT NULL,
            ticket_ref VARCHAR(64) NOT NULL,
            is_revoked BOOLEAN DEFAULT FALSE,
            revoked_at VARCHAR(64),
            revocation_reason TEXT,
            revoked_by VARCHAR(128),
            PRIMARY KEY (room_id, credential_id)
        );
        CREATE TABLE IF NOT EXISTS support_tickets (
            room_id VARCHAR(128) NOT NULL,
            ticket_id VARCHAR(64) NOT NULL,
            title VARCHAR(255) NOT NULL,
            category VARCHAR(128) NOT NULL,
            priority VARCHAR(64) NOT NULL,
            status VARCHAR(64) NOT NULL,
            author VARCHAR(128) NOT NULL,
            description TEXT,
            credential_id VARCHAR(64),
            created_at VARCHAR(64) NOT NULL,
            PRIMARY KEY (room_id, ticket_id)
        );
        CREATE TABLE IF NOT EXISTS security_events (
            id SERIAL PRIMARY KEY,
            room_id VARCHAR(128) NOT NULL,
            event_id VARCHAR(64) NOT NULL,
            case_id VARCHAR(64) NOT NULL,
            timestamp VARCHAR(64) NOT NULL,
            credential_id VARCHAR(64),
            session_id VARCHAR(128),
            device_label VARCHAR(128),
            action VARCHAR(128) NOT NULL,
            resource VARCHAR(255) NOT NULL,
            decision VARCHAR(64) NOT NULL,
            http_status INT NOT NULL,
            ip_address VARCHAR(128) NOT NULL,
            user_agent VARCHAR(255) NOT NULL,
            detection_tags TEXT NOT NULL,
            previous_hash VARCHAR(128) NOT NULL,
            current_hash VARCHAR(128) NOT NULL
        );
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id SERIAL PRIMARY KEY,
            room_id VARCHAR(128) NOT NULL,
            alert_id VARCHAR(64) NOT NULL,
            timestamp VARCHAR(64) NOT NULL,
            severity VARCHAR(64) NOT NULL,
            rule_id VARCHAR(128) NOT NULL,
            rule_name VARCHAR(255) NOT NULL,
            description TEXT NOT NULL,
            related_event_ids TEXT NOT NULL,
            recommended_action TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS revocations (
            id SERIAL PRIMARY KEY,
            room_id VARCHAR(128) NOT NULL,
            credential_id VARCHAR(64) NOT NULL,
            revoked_at VARCHAR(64) NOT NULL,
            reason TEXT NOT NULL,
            revoked_by VARCHAR(128) NOT NULL,
            event_id VARCHAR(64) NOT NULL
        );
        """)
    else:
        cursor.executescript("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id TEXT PRIMARY KEY,
            company_name TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            department TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS credentials (
            room_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            secret_hash TEXT NOT NULL,
            synthetic_secret TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            ticket_ref TEXT NOT NULL,
            is_revoked INTEGER DEFAULT 0,
            revoked_at TEXT,
            revocation_reason TEXT,
            revoked_by TEXT,
            PRIMARY KEY (room_id, credential_id)
        );
        CREATE TABLE IF NOT EXISTS support_tickets (
            room_id TEXT NOT NULL,
            ticket_id TEXT NOT NULL,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            status TEXT NOT NULL,
            author TEXT NOT NULL,
            description TEXT,
            credential_id TEXT,
            created_at TEXT NOT NULL,
            PRIMARY KEY (room_id, ticket_id)
        );
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            case_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            credential_id TEXT,
            session_id TEXT,
            device_label TEXT,
            action TEXT NOT NULL,
            resource TEXT NOT NULL,
            decision TEXT NOT NULL,
            http_status INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            user_agent TEXT NOT NULL,
            detection_tags TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            current_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS threat_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id TEXT NOT NULL,
            alert_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            rule_name TEXT NOT NULL,
            description TEXT NOT NULL,
            related_event_ids TEXT NOT NULL,
            recommended_action TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS revocations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id TEXT NOT NULL,
            credential_id TEXT NOT NULL,
            revoked_at TEXT NOT NULL,
            reason TEXT NOT NULL,
            revoked_by TEXT NOT NULL,
            event_id TEXT NOT NULL
        );
        """)

    conn.commit()
    seed_default_data(conn)
    conn.close()

def seed_default_data(conn):
    """Seeds default demo users, case, and initial credentials."""
    cursor = conn.cursor()
    
    # 1. Seed Case CR-26-047
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        "SELECT COUNT(*) FROM cases WHERE case_id = ?" if not IS_POSTGRES else
        "SELECT COUNT(*) FROM cases WHERE case_id = %s",
        ("CR-26-047",)
    )
    row = cursor.fetchone()
    count = row[0] if not IS_POSTGRES else list(row.values())[0]
    if count == 0:
        cursor.execute(
            """INSERT INTO cases (case_id, company_name, description, status, created_at)
               VALUES (?, ?, ?, ?, ?)""" if not IS_POSTGRES else
            """INSERT INTO cases (case_id, company_name, description, status, created_at)
               VALUES (%s, %s, %s, %s, %s)""",
            (
                settings.CASE_ID,
                settings.COMPANY_NAME,
                "Investigation of suspected credential exposure and unauthorized access to Harbor & Finch logistics services.",
                "ACTIVE_INVESTIGATION",
                now
            )
        )
    
    # 2. Seed Demo Employees
    demo_users = [
        ("sarah.chen", "Password123!", "Sarah Chen", "Operations Lead", "Freight Logistics"),
        ("marcus.vance", "Password123!", "Marcus Vance", "Dispatch Operations Specialist", "Port Terminal Ops"),
        ("elena.rostova", "Password123!", "Elena Rostova", "IT Security Administrator", "InfoSec & Infrastructure"),
    ]
    for username, raw_pass, full_name, role, dept in demo_users:
        cursor.execute(
            "SELECT COUNT(*) FROM users WHERE username = ?" if not IS_POSTGRES else
            "SELECT COUNT(*) FROM users WHERE username = %s",
            (username,)
        )
        u_row = cursor.fetchone()
        u_count = u_row[0] if not IS_POSTGRES else list(u_row.values())[0]
        if u_count == 0:
            pw_hash = hash_password(raw_pass)
            cursor.execute(
                """INSERT INTO users (username, password_hash, full_name, role, department)
                   VALUES (?, ?, ?, ?, ?)""" if not IS_POSTGRES else
                """INSERT INTO users (username, password_hash, full_name, role, department)
                   VALUES (%s, %s, %s, %s, %s)""",
                (username, pw_hash, full_name, role, dept)
            )

    # 3. Seed Default Room Credential and Support Ticket
    seed_room_credential(conn, settings.DEFAULT_ROOM_ID)
    conn.commit()

def seed_room_credential(conn, room_id: str):
    """Ensures a specific room has its primary credential and support ticket seeded."""
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM credentials WHERE room_id = ? AND credential_id = ?" if not IS_POSTGRES else
        "SELECT COUNT(*) FROM credentials WHERE room_id = %s AND credential_id = %s",
        (room_id, settings.PRIMARY_CREDENTIAL_ID)
    )
    c_row = cursor.fetchone()
    c_count = c_row[0] if not IS_POSTGRES else list(c_row.values())[0]
    
    now = datetime.now(timezone.utc).isoformat()
    if c_count == 0:
        default_secret = "sec_live_9b4e72c81a6f0012e8b2841d9c025d31"
        s_hash = hash_secret(default_secret)
        cursor.execute(
            """INSERT INTO credentials 
               (room_id, credential_id, case_id, secret_hash, synthetic_secret, status, created_at, expires_at, ticket_ref, is_revoked)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""" if not IS_POSTGRES else
            """INSERT INTO credentials 
               (room_id, credential_id, case_id, secret_hash, synthetic_secret, status, created_at, expires_at, ticket_ref, is_revoked)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                room_id,
                settings.PRIMARY_CREDENTIAL_ID,
                settings.CASE_ID,
                s_hash,
                default_secret,
                "ACTIVE",
                now,
                "2026-12-31T23:59:59Z",
                settings.PRIMARY_TICKET_REF,
                0 if not IS_POSTGRES else False
            )
        )
        
        # Support Ticket
        cursor.execute(
            """INSERT INTO support_tickets
               (room_id, ticket_id, title, category, priority, status, author, description, credential_id, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""" if not IS_POSTGRES else
            """INSERT INTO support_tickets
               (room_id, ticket_id, title, category, priority, status, author, description, credential_id, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                room_id,
                settings.PRIMARY_TICKET_REF,
                "Urgent: BlueVault API Key Generation for Third-Party EDI Gateway Integration",
                "Vendor API Integration",
                "High",
                "CLOSED - CREDENTIAL ISSUED",
                "sarah.chen",
                "Vendor requested test API token for automated freight manifest sync. Generated test credential identifier bvk-7f3a attached below.",
                settings.PRIMARY_CREDENTIAL_ID,
                now
            )
        )

def get_credential(room_id: str, credential_id: str = settings.PRIMARY_CREDENTIAL_ID) -> Optional[Dict[str, Any]]:
    """Fetches credential record for a given room."""
    conn = get_db()
    seed_room_credential(conn, room_id)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM credentials WHERE room_id = ? AND credential_id = ?" if not IS_POSTGRES else
        "SELECT * FROM credentials WHERE room_id = %s AND credential_id = %s",
        (room_id, credential_id)
    )
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return dict(row)

def update_credential_secret(room_id: str, credential_id: str, new_secret: str) -> Dict[str, Any]:
    """Generates and updates a fresh synthetic secret for the demonstration ticket."""
    conn = get_db()
    seed_room_credential(conn, room_id)
    cursor = conn.cursor()
    s_hash = hash_secret(new_secret)
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """UPDATE credentials 
           SET synthetic_secret = ?, secret_hash = ?, status = 'ACTIVE', is_revoked = 0, revoked_at = NULL, revocation_reason = NULL, revoked_by = NULL
           WHERE room_id = ? AND credential_id = ?""" if not IS_POSTGRES else
        """UPDATE credentials 
           SET synthetic_secret = %s, secret_hash = %s, status = 'ACTIVE', is_revoked = FALSE, revoked_at = NULL, revocation_reason = NULL, revoked_by = NULL
           WHERE room_id = %s AND credential_id = %s""",
        (new_secret, s_hash, room_id, credential_id)
    )
    conn.commit()
    conn.close()
    return get_credential(room_id, credential_id)

def record_security_event(
    room_id: str,
    action: str,
    resource: str,
    decision: str,
    http_status: int,
    ip_address: str,
    user_agent: str,
    credential_id: Optional[str] = None,
    session_id: Optional[str] = None,
    device_label: Optional[str] = None,
    detection_tags: Optional[List[str]] = None
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Appends a security event into the database with SHA-256 hash chaining.
    Evaluates threat detection rules and appends alerts if triggered.
    Returns (event_dict, newly_triggered_alerts).
    """
    conn = get_db()
    seed_room_credential(conn, room_id)
    cursor = conn.cursor()
    
    # 1. Fetch latest event for this room to obtain previous hash
    cursor.execute(
        "SELECT current_hash FROM security_events WHERE room_id = ? ORDER BY id DESC LIMIT 1" if not IS_POSTGRES else
        "SELECT current_hash FROM security_events WHERE room_id = %s ORDER BY id DESC LIMIT 1",
        (room_id,)
    )
    last_row = cursor.fetchone()
    if last_row:
        prev_hash = last_row["current_hash"] if IS_POSTGRES or hasattr(last_row, "__getitem__") else last_row[0]
    else:
        prev_hash = GENESIS_HASH
        
    event_id = f"EVT-{uuid.uuid4().hex[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()
    tags = detection_tags or []
    
    # 2. Compute current SHA-256 hash
    curr_hash = compute_event_hash(
        prev_hash=prev_hash,
        event_id=event_id,
        timestamp=timestamp,
        credential_id=credential_id,
        action=action,
        resource=resource,
        decision=decision,
        http_status=http_status,
        device_label=device_label
    )
    
    tags_json = json.dumps(tags)
    
    # 3. Insert event
    if IS_POSTGRES:
        cursor.execute(
            """INSERT INTO security_events 
               (room_id, event_id, case_id, timestamp, credential_id, session_id, device_label, action, resource, decision, http_status, ip_address, user_agent, detection_tags, previous_hash, current_hash)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (room_id, event_id, settings.CASE_ID, timestamp, credential_id, session_id, device_label, action, resource, decision, http_status, ip_address, user_agent, tags_json, prev_hash, curr_hash)
        )
        row_id = cursor.fetchone()["id"]
    else:
        cursor.execute(
            """INSERT INTO security_events 
               (room_id, event_id, case_id, timestamp, credential_id, session_id, device_label, action, resource, decision, http_status, ip_address, user_agent, detection_tags, previous_hash, current_hash)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (room_id, event_id, settings.CASE_ID, timestamp, credential_id, session_id, device_label, action, resource, decision, http_status, ip_address, user_agent, tags_json, prev_hash, curr_hash)
        )
        row_id = cursor.lastrowid

    conn.commit()

    event_dict = {
        "id": row_id,
        "event_id": event_id,
        "room_id": room_id,
        "case_id": settings.CASE_ID,
        "timestamp": timestamp,
        "credential_id": credential_id,
        "session_id": session_id,
        "device_label": device_label,
        "action": action,
        "resource": resource,
        "decision": decision,
        "http_status": http_status,
        "ip_address": ip_address,
        "user_agent": user_agent,
        "detection_tags": tags,
        "previous_hash": prev_hash,
        "current_hash": curr_hash
    }
    
    # 4. Fetch recent events to run detection rules
    recent_events = get_security_events(room_id, limit=20)
    cred_rec = get_credential(room_id, credential_id or settings.PRIMARY_CREDENTIAL_ID) or {}
    
    new_alerts = evaluate_threat_rules(event_dict, recent_events, cred_rec)
    
    # Insert new alerts
    for alt in new_alerts:
        related_json = json.dumps(alt.get("related_event_ids", []))
        if IS_POSTGRES:
            cursor.execute(
                """INSERT INTO threat_alerts
                   (room_id, alert_id, timestamp, severity, rule_id, rule_name, description, related_event_ids, recommended_action)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (room_id, alt["alert_id"], alt["timestamp"], alt["severity"], alt["rule_id"], alt["rule_name"], alt["description"], related_json, alt["recommended_action"])
            )
        else:
            cursor.execute(
                """INSERT INTO threat_alerts
                   (room_id, alert_id, timestamp, severity, rule_id, rule_name, description, related_event_ids, recommended_action)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (room_id, alt["alert_id"], alt["timestamp"], alt["severity"], alt["rule_id"], alt["rule_name"], alt["description"], related_json, alt["recommended_action"])
            )
            
    conn.commit()
    conn.close()
    return event_dict, new_alerts

def get_security_events(room_id: str, limit: int = 100, since_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Returns chronologically ordered events for a room."""
    conn = get_db()
    cursor = conn.cursor()
    
    if since_id:
        cursor.execute(
            "SELECT * FROM security_events WHERE room_id = ? AND id > ? ORDER BY id ASC LIMIT ?" if not IS_POSTGRES else
            "SELECT * FROM security_events WHERE room_id = %s AND id > %s ORDER BY id ASC LIMIT %s",
            (room_id, since_id, limit)
        )
    else:
        cursor.execute(
            "SELECT * FROM security_events WHERE room_id = ? ORDER BY id DESC LIMIT ?" if not IS_POSTGRES else
            "SELECT * FROM security_events WHERE room_id = %s ORDER BY id DESC LIMIT %s",
            (room_id, limit)
        )
        
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in (reversed(rows) if not since_id else rows):
        item = dict(r)
        if isinstance(item.get("detection_tags"), str):
            try:
                item["detection_tags"] = json.loads(item["detection_tags"])
            except Exception:
                item["detection_tags"] = []
        results.append(item)
    return results

def get_threat_alerts(room_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """Returns threat alerts recorded for this room."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM threat_alerts WHERE room_id = ? ORDER BY id DESC LIMIT ?" if not IS_POSTGRES else
        "SELECT * FROM threat_alerts WHERE room_id = %s ORDER BY id DESC LIMIT %s",
        (room_id, limit)
    )
    rows = cursor.fetchall()
    conn.close()
    
    alerts = []
    for r in rows:
        item = dict(r)
        if isinstance(item.get("related_event_ids"), str):
            try:
                item["related_event_ids"] = json.loads(item["related_event_ids"])
            except Exception:
                item["related_event_ids"] = []
        alerts.append(item)
    return alerts

def revoke_credential(
    room_id: str,
    credential_id: str,
    reason: str,
    investigator_id: str = "SOC-INVESTIGATOR-01"
) -> Dict[str, Any]:
    """
    Executes formal containment: revokes the credential, updates state,
    and logs an audit security event to the tamper-evident chain.
    """
    conn = get_db()
    seed_room_credential(conn, room_id)
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    
    # 1. Update credential state
    cursor.execute(
        """UPDATE credentials 
           SET status = 'REVOKED', is_revoked = 1, revoked_at = ?, revocation_reason = ?, revoked_by = ?
           WHERE room_id = ? AND credential_id = ?""" if not IS_POSTGRES else
        """UPDATE credentials 
           SET status = 'REVOKED', is_revoked = TRUE, revoked_at = %s, revocation_reason = %s, revoked_by = %s
           WHERE room_id = %s AND credential_id = %s""",
        (now, reason, investigator_id, room_id, credential_id)
    )
    conn.commit()
    conn.close()
    
    # 2. Record containment audit event into hash chain
    event_dict, _ = record_security_event(
        room_id=room_id,
        action="CREDENTIAL_CONTAINMENT_REVOKED",
        resource=f"CREDENTIAL:{credential_id}",
        decision="ENFORCED",
        http_status=200,
        ip_address="127.0.0.1",
        user_agent="CREDTRACE-SOC-CONTAINMENT/2.0",
        credential_id=credential_id,
        device_label="INVESTIGATOR-CONSOLE",
        detection_tags=["CONTAINMENT_ACTION", "MANUAL_REVOCATION", "INCIDENT_ISOLATION"]
    )
    
    # 3. Record in revocations table
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO revocations (room_id, credential_id, revoked_at, reason, revoked_by, event_id)
           VALUES (?, ?, ?, ?, ?, ?)""" if not IS_POSTGRES else
        """INSERT INTO revocations (room_id, credential_id, revoked_at, reason, revoked_by, event_id)
           VALUES (%s, %s, %s, %s, %s, %s)""",
        (room_id, credential_id, now, reason, investigator_id, event_dict["event_id"])
    )
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "credential_id": credential_id,
        "status": "REVOKED",
        "revoked_at": now,
        "event_id": event_dict["event_id"],
        "message": f"Credential {credential_id} successfully revoked and contained."
    }

def get_overview_statistics(room_id: str) -> Dict[str, Any]:
    """Computes real database-backed metrics and chart telemetry."""
    events = get_security_events(room_id, limit=300)
    alerts = get_threat_alerts(room_id, limit=50)
    cred = get_credential(room_id) or {}
    
    total_events = len(events)
    allowed_requests = sum(1 for e in events if e.get("decision") == "ALLOWED")
    denied_requests = sum(1 for e in events if e.get("decision") == "DENIED")
    failed_auth = sum(1 for e in events if e.get("http_status") == 401 or e.get("action") == "AUTH_FAILED")
    
    # Threat risk scoring (0-100)
    risk_score = 15
    if any(a.get("severity") == "Critical" for a in alerts):
        risk_score = min(100, risk_score + 55)
    if any(a.get("severity") == "High" for a in alerts):
        risk_score = min(100, risk_score + 25)
    if cred.get("is_revoked"):
        # Contained! Risk is mitigated
        risk_score = max(20, risk_score - 30)
    risk_score = min(100, max(0, risk_score + min(30, denied_requests * 5)))

    # Activity timeline breakdown
    activity_timeline = []
    for e in events[-15:]:
        activity_timeline.append({
            "timestamp": e.get("timestamp"),
            "action": e.get("action"),
            "decision": e.get("decision"),
            "http_status": e.get("http_status")
        })

    # Event categories
    categories = {}
    for e in events:
        act = e.get("action", "OTHER")
        categories[act] = categories.get(act, 0) + 1

    return {
        "total_events": total_events,
        "allowed_requests": allowed_requests,
        "denied_requests": denied_requests,
        "failed_auth": failed_auth,
        "active_credentials": 0 if cred.get("is_revoked") else 1,
        "revoked_credentials": 1 if cred.get("is_revoked") else 0,
        "threat_alerts": len(alerts),
        "risk_score": risk_score,
        "activity_timeline": activity_timeline,
        "allowed_vs_denied": {
            "ALLOWED": allowed_requests,
            "DENIED": denied_requests
        },
        "event_categories": categories,
        "credential_status": cred
    }

def reset_room_state(room_id: str) -> Dict[str, Any]:
    """Resets simulation events and alerts for a room to allow clean judge demos."""
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute(
        "DELETE FROM security_events WHERE room_id = ?" if not IS_POSTGRES else
        "DELETE FROM security_events WHERE room_id = %s",
        (room_id,)
    )
    cursor.execute(
        "DELETE FROM threat_alerts WHERE room_id = ?" if not IS_POSTGRES else
        "DELETE FROM threat_alerts WHERE room_id = %s",
        (room_id,)
    )
    cursor.execute(
        "DELETE FROM revocations WHERE room_id = ?" if not IS_POSTGRES else
        "DELETE FROM revocations WHERE room_id = %s",
        (room_id,)
    )
    # Reset credential to ACTIVE
    cursor.execute(
        """UPDATE credentials 
           SET status = 'ACTIVE', is_revoked = 0, revoked_at = NULL, revocation_reason = NULL, revoked_by = NULL
           WHERE room_id = ?""" if not IS_POSTGRES else
        """UPDATE credentials 
           SET status = 'ACTIVE', is_revoked = FALSE, revoked_at = NULL, revocation_reason = NULL, revoked_by = NULL
           WHERE room_id = %s""",
        (room_id,)
    )
    conn.commit()
    conn.close()
    
    return {
        "success": True,
        "room_id": room_id,
        "message": f"Simulation room '{room_id}' state reset successfully."
    }

def list_support_tickets(room_id: str) -> List[Dict[str, Any]]:
    """Lists support tickets for the company portal."""
    conn = get_db()
    seed_room_credential(conn, room_id)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM support_tickets WHERE room_id = ? ORDER BY created_at DESC" if not IS_POSTGRES else
        "SELECT * FROM support_tickets WHERE room_id = %s ORDER BY created_at DESC",
        (room_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def create_support_ticket(room_id: str, title: str, category: str, priority: str, description: str, author: str) -> Dict[str, Any]:
    """Creates a new support ticket in the company portal."""
    conn = get_db()
    cursor = conn.cursor()
    ticket_id = f"TKT-{uuid.uuid4().hex[:5].upper()}"
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """INSERT INTO support_tickets 
           (room_id, ticket_id, title, category, priority, status, author, description, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""" if not IS_POSTGRES else
        """INSERT INTO support_tickets 
           (room_id, ticket_id, title, category, priority, status, author, description, created_at)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (room_id, ticket_id, title, category, priority, "OPEN", author, description, now)
    )
    conn.commit()
    conn.close()
    return {
        "ticket_id": ticket_id,
        "title": title,
        "category": category,
        "priority": priority,
        "status": "OPEN",
        "author": author,
        "created_at": now
    }
