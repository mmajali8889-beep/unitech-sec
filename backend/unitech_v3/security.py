"""Authentication, RBAC, hashing."""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
import uuid
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

_ph = PasswordHasher()

ROLES = {
    "admin": {"*"},
    "analyst": {"projects:read", "projects:write", "scans:read", "scans:run", "scans:cancel", "findings:read",
                "findings:triage", "reports:read", "reports:create", "schedules:read", "schedules:write",
                "engines:read", "beko:run", "system:read", "browse"},
    "viewer": {"projects:read", "scans:read", "findings:read", "reports:read", "schedules:read", "engines:read", "system:read"},
    "auditor": {"projects:read", "scans:read", "findings:read", "reports:read", "schedules:read", "engines:read",
                "system:read", "audit:read"},
}


def has_perm(role: str, perm: str) -> bool:
    p = ROLES.get(role, set())
    return "*" in p or perm in p


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw: str, hashed: str) -> bool:
    try:
        return _ph.verify(hashed, pw)
    except (VerifyMismatchError, InvalidHashError):
        return False


def password_policy(pw: str) -> str | None:
    if len(pw) < 12:
        return "Password must be at least 12 characters"
    if not (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)):
        return "Password must contain upper-case, lower-case and digit characters"
    return None


def load_secret(path: Path) -> str:
    if path.exists():
        return path.read_text().strip()
    s = secrets.token_urlsafe(48)
    path.write_text(s)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return s


def make_token(secret: str, user_id: int, ttl_min: int) -> tuple[str, str, float]:
    jti = uuid.uuid4().hex
    exp = time.time() + ttl_min * 60
    return jwt.encode({"sub": str(user_id), "jti": jti, "exp": int(exp), "iss": "unitech-v3"}, secret, algorithm="HS256"), jti, exp


def decode_token(secret: str, token: str) -> dict | None:
    try:
        return jwt.decode(token, secret, algorithms=["HS256"], issuer="unitech-v3")
    except jwt.PyJWTError:
        return None


def token_hash(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def new_secret_token(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def ct_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
