"""
CREDTRACE V2 - Pydantic Data Models & Schemas
"""
from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# Authentication
class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    success: bool
    message: str
    token: Optional[str] = None
    user: Optional[Dict[str, Any]] = None

class DemoUser(BaseModel):
    username: str
    full_name: str
    role: str
    department: str
    description: str

# Company Portal
class TicketCreate(BaseModel):
    title: str
    category: str = "Vendor API Integration"
    priority: str = "Medium"
    description: str

class TicketResponse(BaseModel):
    ticket_id: str
    title: str
    category: str
    priority: str
    status: str
    created_at: str
    author: str
    credential_id: Optional[str] = None

class CredentialDetail(BaseModel):
    credential_id: str
    case_id: str
    secret_display: str
    status: str  # ACTIVE or REVOKED
    created_at: str
    expires_at: str
    ticket_ref: str
    is_revoked: bool
    revoked_at: Optional[str] = None
    revocation_reason: Optional[str] = None

# Attacker Simulator
class SimulatorAuthRequest(BaseModel):
    room_id: str = "CR-26-047-DEMO"
    device_label: str = "LAPTOP-02-SIMULATOR"
    secret: str
    session_id: Optional[str] = None

class SimulatorRequest(BaseModel):
    room_id: str = "CR-26-047-DEMO"
    session_id: str
    device_label: str = "LAPTOP-02-SIMULATOR"
    credential_id: Optional[str] = "bvk-7f3a"

class SimulatorExportRequest(BaseModel):
    room_id: str = "CR-26-047-DEMO"
    session_id: str
    device_label: str = "LAPTOP-02-SIMULATOR"
    credential_id: Optional[str] = "bvk-7f3a"
    format: str = "CSV_UNENCRYPTED"
    scope: str = "ALL_GLOBAL_CUSTOMERS_AND_TRANSACTIONS"

class SimulatorActionResponse(BaseModel):
    success: bool
    status_code: int
    event_id: str
    timestamp: str
    action: str
    resource: str
    decision: str  # ALLOWED or DENIED
    message: str
    data: Optional[Any] = None
    alert_triggered: Optional[Dict[str, Any]] = None

# Investigator SOC Models
class SecurityEventItem(BaseModel):
    id: int
    event_id: str
    room_id: str
    case_id: str
    timestamp: str
    credential_id: Optional[str]
    session_id: Optional[str]
    device_label: Optional[str]
    action: str
    resource: str
    decision: str
    http_status: int
    ip_address: str
    user_agent: str
    detection_tags: List[str]
    previous_hash: str
    current_hash: str

class ThreatAlertItem(BaseModel):
    id: int
    alert_id: str
    room_id: str
    timestamp: str
    severity: str  # Critical, High, Medium, Low
    rule_id: str
    rule_name: str
    description: str
    related_event_ids: List[str]
    recommended_action: str

class CorrelationFinding(BaseModel):
    finding_id: str
    confidence: str  # Strong technical correlation, Partial correlation, Insufficient evidence
    title: str
    description: str
    evidence_points: List[str]
    correlated_event_ids: List[str]

class OverviewStatistics(BaseModel):
    total_events: int
    allowed_requests: int
    denied_requests: int
    failed_auth: int
    active_credentials: int
    revoked_credentials: int
    threat_alerts: int
    risk_score: int
    activity_timeline: List[Dict[str, Any]]
    allowed_vs_denied: Dict[str, int]
    event_categories: Dict[str, int]
    credential_status: Dict[str, Any]

class RevocationRequest(BaseModel):
    room_id: str = "CR-26-047-DEMO"
    credential_id: str = "bvk-7f3a"
    reason: str = "Suspected compromised credential during forensic investigation (Incident CR-26-047)"
    investigator_id: str = "INV-CHEN-01"

class RevocationResponse(BaseModel):
    success: bool
    credential_id: str
    status: str
    revoked_at: str
    event_id: str
    message: str

class RoomResetRequest(BaseModel):
    room_id: str = "CR-26-047-DEMO"
    admin_code: Optional[str] = "crimeathon26"

class RoomResetResponse(BaseModel):
    success: bool
    room_id: str
    message: str
    cleared_events: int
    cleared_alerts: int
