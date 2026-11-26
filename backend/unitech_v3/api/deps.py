from __future__ import annotations

import time

from fastapi import Depends, Header, HTTPException, Request

from .. import audit, security
from ..services import Ctx


def ctx_of(request: Request) -> Ctx:
    return request.app.state.ctx


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _bearer(authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def current_user(request: Request, authorization: str | None = Header(default=None), ctx: Ctx = Depends(ctx_of)) -> dict:
    ip = client_ip(request)
    tok = _bearer(authorization)
    if not tok:
        raise HTTPException(401, "authentication required")
    claims = security.decode_token(ctx.secret, tok)
    if not claims:
        raise HTTPException(401, "invalid or expired token")
    sess = ctx.db.one("SELECT revoked,expires_at FROM sessions WHERE jti=?", (claims["jti"],))
    user = ctx.db.one("SELECT * FROM users WHERE id=?", (int(claims["sub"]),))
    if not sess or sess["revoked"] or sess["expires_at"] < time.time() or not user or not user["active"]:
        raise HTTPException(401, "session is no longer valid")
    if not ctx.limiter.allow(f"u:{user['id']}", ctx.settings.rate_limit_per_minute):
        raise HTTPException(429, "rate limit exceeded")
    user["jti"] = claims["jti"]
    user["ip"] = ip
    return user


def require(perm: str):
    def dep(request: Request, user: dict = Depends(current_user), ctx: Ctx = Depends(ctx_of)) -> dict:
        if user["must_change_password"] and not request.url.path.endswith("/auth/change-password"):
            raise HTTPException(403, "password change required")
        if not security.has_perm(user["role"], perm):
            audit.log(ctx.db, user["username"], "authz.denied", role=user["role"], target=perm, ip=user["ip"], outcome="denied",
                      detail={"path": request.url.path})
            raise HTTPException(403, f"permission '{perm}' required")
        return user
    return dep


def agent_auth(request: Request, authorization: str | None = Header(default=None), ctx: Ctx = Depends(ctx_of)) -> dict:
    tok = _bearer(authorization)
    if not tok or not tok.startswith("agt_"):
        raise HTTPException(401, "agent authentication required")
    a = ctx.db.one("SELECT * FROM agents WHERE token_hash=? AND revoked=0", (security.token_hash(tok),))
    if not a:
        audit.log(ctx.db, "unknown-agent", "agent.auth", ip=client_ip(request), outcome="denied")
        raise HTTPException(401, "invalid agent token")
    if not ctx.limiter.allow(f"a:{a['id']}", 1200):
        raise HTTPException(429, "rate limit exceeded")
    return a
