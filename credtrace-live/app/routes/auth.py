"""
CREDTRACE V2 - Authentication & Demo User Management
Fixes /api/login endpoint and provides role-based credentials
"""
import uuid
from fastapi import APIRouter, HTTPException, Depends
from app.models import LoginRequest, LoginResponse, DemoUser
from app.database import get_db, IS_POSTGRES
from app.security import verify_password

router = APIRouter(prefix="/api", tags=["Authentication"])

@router.post("/login", response_model=LoginResponse)
async def login(req: LoginRequest):
    """
    Authenticates company portal employee or investigator.
    Fixes the previously missing /api/login route.
    """
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username = ?" if not IS_POSTGRES else
        "SELECT * FROM users WHERE username = %s",
        (req.username.strip(),)
    )
    user_row = cursor.fetchone()
    conn.close()

    if not user_row:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    
    user = dict(user_row)
    if not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    session_token = f"sess_{uuid.uuid4().hex}"
    
    return LoginResponse(
        success=True,
        message=f"Welcome back, {user['full_name']} ({user['role']}).",
        token=session_token,
        user={
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"],
            "department": user["department"]
        }
    )

@router.get("/auth/demo-users", response_model=list[DemoUser])
async def get_demo_users():
    """Provides one-click employee identities for seamless hackathon judge testing."""
    return [
        DemoUser(
            username="sarah.chen",
            full_name="Sarah Chen",
            role="Operations Lead",
            department="Freight Logistics",
            description="Author of Ticket TKT-48213 where credential bvk-7f3a was issued."
        ),
        DemoUser(
            username="marcus.vance",
            full_name="Marcus Vance",
            role="Dispatch Operations Specialist",
            department="Port Terminal Ops",
            description="Manages vessel unloading telemetry and manifest routing."
        ),
        DemoUser(
            username="elena.rostova",
            full_name="Elena Rostova",
            role="IT Security Administrator",
            department="InfoSec & Infrastructure",
            description="Lead investigator in SOC command centre."
        ),
    ]
