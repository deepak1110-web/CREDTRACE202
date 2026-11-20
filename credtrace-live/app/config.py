"""
CREDTRACE V2 - Application Configuration
Case ID: CR-26-047 | Harbor & Finch Freight Pvt. Ltd.
"""
import os
from pathlib import Path
from pydantic import BaseModel

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseModel):
    # App Settings
    APP_NAME: str = "CREDTRACE-LIVE"
    APP_VERSION: str = "2.0.0"
    APP_ENV: str = os.getenv("APP_ENV", "production")
    DEBUG: bool = os.getenv("DEBUG", "false").lower() in ("true", "1")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "credtrace-secret-key-crimeathon-2026-cr26047")
    
    # Host and Port
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", "8000"))
    
    # Database
    # Supports PostgreSQL (Neon, Render) or SQLite fallback for local testing
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{BASE_DIR / 'credtrace.db'}"
    )
    
    # CORS Origins for cross-laptop and internet communication
    CORS_ORIGINS: list[str] = [
        "*",  # Open for hackathon multi-device testing over internet
    ]
    
    # Demonstration & Case Constants
    CASE_ID: str = "CR-26-047"
    COMPANY_NAME: str = "Harbor & Finch Freight Pvt. Ltd."
    PRIMARY_CREDENTIAL_ID: str = "bvk-7f3a"
    PRIMARY_TICKET_REF: str = "TKT-48213"
    DEFAULT_ROOM_ID: str = "CR-26-047-DEMO"
    ADMIN_RESET_KEY: str = os.getenv("ADMIN_RESET_KEY", "crimeathon26")
    
    # Evidence Limitations Disclaimer
    EVIDENCE_LIMITATIONS: str = (
        "EVIDENCE LIMITATIONS & FORENSIC BOUNDARIES: "
        "1. Credential identifier 'bvk-7f3a' is an index handle, not the raw secret. "
        "2. All demonstrated tokens and secrets are synthetically generated for demonstration. "
        "3. Network IP addresses identify endpoint routing paths, not legal human identities. "
        "4. Correlated evidence demonstrates technical association, not definitive human attribution. "
        "5. SHA-256 hash chaining proves ledger sequence integrity against tampering, "
        "   subject to underlying storage administration controls."
    )

settings = Settings()
