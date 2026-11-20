"""
CREDTRACE V2 - Security & Cryptographic Integrity Engine
- PBKDF2-HMAC-SHA256 password hashing
- Synthetic secret generation
- Cryptographic SHA-256 hash chaining for tamper-evident security audit
"""
import hashlib
import hmac
import os
import secrets
from typing import List, Dict, Any, Optional

SALT_SIZE = 16
HASH_ITERATIONS = 100_000

def generate_synthetic_secret(prefix: str = "sec_live_") -> str:
    """Generates a random synthetic secret (32 hex characters)."""
    random_hex = secrets.token_hex(16)
    return f"{prefix}{random_hex}"

def hash_secret(raw_secret: str) -> str:
    """Computes SHA-256 hash of a credential secret for safe storage."""
    return hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()

def verify_secret(raw_secret: str, stored_hash: str) -> bool:
    """Verifies a raw secret against its stored SHA-256 hash."""
    computed = hash_secret(raw_secret)
    return hmac.compare_digest(computed, stored_hash)

def hash_password(password: str) -> str:
    """Hashes a password using PBKDF2-HMAC-SHA256 with random salt."""
    salt = os.urandom(SALT_SIZE)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, HASH_ITERATIONS)
    return f"{salt.hex()}:{key.hex()}"

def verify_password(password: str, hashed: str) -> bool:
    """Verifies a password against salt:key format."""
    try:
        salt_hex, key_hex = hashed.split(":")
        salt = bytes.fromhex(salt_hex)
        key = bytes.fromhex(key_hex)
        computed_key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, HASH_ITERATIONS)
        return hmac.compare_digest(computed_key, key)
    except Exception:
        return False

# Genesis block hash for the tamper-evident event chain
GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def compute_event_hash(
    prev_hash: str,
    event_id: str,
    timestamp: str,
    credential_id: Optional[str],
    action: str,
    resource: str,
    decision: str,
    http_status: int,
    device_label: Optional[str] = None
) -> str:
    """
    Computes a cryptographic SHA-256 hash for an event chained to the previous event hash.
    Forms a blockchain-like tamper-evident audit ledger.
    """
    payload = (
        f"{prev_hash}|"
        f"{event_id}|"
        f"{timestamp}|"
        f"{credential_id or 'none'}|"
        f"{action}|"
        f"{resource}|"
        f"{decision}|"
        f"{http_status}|"
        f"{device_label or 'none'}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def verify_hash_chain(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Traverses the event chain from genesis to latest, re-computing each block hash.
    Detects any modification, insertion, deletion, or reordering of records.
    """
    if not events:
        return {
            "valid": True,
            "total_verified": 0,
            "broken_at_event_id": None,
            "genesis_hash": GENESIS_HASH,
            "reason": "Chain is empty (no events recorded yet)."
        }
    
    expected_prev_hash = GENESIS_HASH
    
    for idx, ev in enumerate(events):
        event_id = ev.get("event_id")
        timestamp = ev.get("timestamp")
        credential_id = ev.get("credential_id")
        action = ev.get("action")
        resource = ev.get("resource")
        decision = ev.get("decision")
        http_status = ev.get("http_status")
        device_label = ev.get("device_label")
        stored_prev_hash = ev.get("previous_hash")
        stored_current_hash = ev.get("current_hash")
        
        # Check prev_hash linkage
        if stored_prev_hash != expected_prev_hash:
            return {
                "valid": False,
                "total_verified": idx,
                "broken_at_event_id": event_id,
                "genesis_hash": GENESIS_HASH,
                "reason": (
                    f"Previous hash mismatch at index {idx} (Event ID: {event_id}). "
                    f"Expected {expected_prev_hash[:16]}..., found {stored_prev_hash[:16]}..."
                )
            }
        
        # Recalculate hash of this block
        recalculated_hash = compute_event_hash(
            prev_hash=stored_prev_hash,
            event_id=event_id,
            timestamp=timestamp,
            credential_id=credential_id,
            action=action,
            resource=resource,
            decision=decision,
            http_status=http_status,
            device_label=device_label
        )
        
        if recalculated_hash != stored_current_hash:
            return {
                "valid": False,
                "total_verified": idx,
                "broken_at_event_id": event_id,
                "genesis_hash": GENESIS_HASH,
                "reason": (
                    f"Data tampering detected at index {idx} (Event ID: {event_id}). "
                    f"Stored hash does not match recalculated content hash."
                )
            }
        
        expected_prev_hash = stored_current_hash
        
    return {
        "valid": True,
        "total_verified": len(events),
        "broken_at_event_id": None,
        "genesis_hash": GENESIS_HASH,
        "latest_hash": expected_prev_hash,
        "reason": f"Cryptographic audit chain fully verified across {len(events)} events."
    }
