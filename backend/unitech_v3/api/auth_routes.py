from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from .. import audit, security
from ..services import Ctx
from .deps import client_ip, ctx_of, current_user, require

router = APIRouter(prefix="/api")


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


def public_user(u: dict) -> dict:
    return {k: u[k] for k in ("id", "username", "display_name", "role", "locale", "active", "must_change_password", "created_at", "last_login") if k in u}


@router.post("/auth/login")
def login(body: LoginIn, request: Request, ctx: Ctx = Depends(ctx_of)):
    ip = client_ip(request)
    if not ctx.limiter.allow(f"login:{ip}", ctx.settings.login_limit_per_minute):
        audit.log(ctx.db, body.username, "auth.login", ip=ip, outcome="rate_limited")
        raise HTTPException(429, "too many login attempts")
    u = ctx.db.one("SELECT * FROM users WHERE username=?", (body.username,))
    now = time.time()
    if u and u["locked_until"] and u["locked_until"] > now:
        audit.log(ctx.db, body.username, "auth.login", ip=ip, outcome="locked")
        raise HTTPException(423, "account temporarily locked")
    if not u or not u["active"] or not security.verify_password(body.password, u["password_hash"]):
        if u:
            fails = u["failed_logins"] + 1
            lock = now + ctx.settings.lockout_minutes * 60 if fails >= ctx.settings.lockout_threshold else None
            ctx.db.run("UPDATE users SET failed_logins=?, locked_until=? WHERE id=?", (0 if lock else fails, lock, u["id"]))
        audit.log(ctx.db, body.username, "auth.login", ip=ip, outcome="denied")
        raise HTTPException(401, "invalid credentials")
    ctx.db.run("UPDATE users SET failed_logins=0, locked_until=NULL, last_login=? WHERE id=?", (now, u["id"]))
    tok, jti, exp = security.make_token(ctx.secret, u["id"], ctx.settings.token_ttl_minutes)
    ctx.db.run("INSERT INTO sessions(jti,user_id,expires_at,created_at,ip) VALUES(?,?,?,?,?)", (jti, u["id"], exp, now, ip))
    audit.log(ctx.db, u["username"], "auth.login", role=u["role"], ip=ip)
    return {"token": tok, "expires_at": exp, "user": public_user(u)}


@router.post("/auth/logout")
def logout(user: dict = Depends(current_user), ctx: Ctx = Depends(ctx_of)):
    ctx.db.run("UPDATE sessions SET revoked=1 WHERE jti=?", (user["jti"],))
    audit.log(ctx.db, user["username"], "auth.logout", role=user["role"], ip=user["ip"])
    return {"ok": True}


@router.get("/auth/me")
def me(user: dict = Depends(current_user)):
    from ..security import ROLES
    p = ROLES[user["role"]]
    return {**public_user(user), "permissions": sorted(p)}


class PwIn(BaseModel):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


@router.post("/auth/change-password")
def change_password(body: PwIn, user: dict = Depends(current_user), ctx: Ctx = Depends(ctx_of)):
    if not security.verify_password(body.current_password, user["password_hash"]):
        raise HTTPException(400, "current password is incorrect")
    bad = security.password_policy(body.new_password)
    if bad:
        raise HTTPException(422, bad)
    ctx.db.run("UPDATE users SET password_hash=?, must_change_password=0 WHERE id=?", (security.hash_password(body.new_password), user["id"]))
    ctx.db.run("UPDATE sessions SET revoked=1 WHERE user_id=? AND jti!=?", (user["id"], user["jti"]))
    audit.log(ctx.db, user["username"], "auth.change_password", role=user["role"], ip=user["ip"])
    return {"ok": True}


class PrefsIn(BaseModel):
    locale: str = Field(pattern="^(en|ar)$")


@router.put("/auth/preferences")
def prefs(body: PrefsIn, user: dict = Depends(current_user), ctx: Ctx = Depends(ctx_of)):
    ctx.db.run("UPDATE users SET locale=? WHERE id=?", (body.locale, user["id"]))
    return {"ok": True}


# ------------------------------------------------------------------ user management
class UserIn(BaseModel):
    username: str = Field(pattern=r"^[A-Za-z0-9_.\-]{3,40}$")
    display_name: str = Field(default="", max_length=80)
    role: str = Field(pattern="^(admin|analyst|viewer|auditor)$")
    password: str = Field(max_length=256)


class UserPatch(BaseModel):
    display_name: str | None = Field(default=None, max_length=80)
    role: str | None = Field(default=None, pattern="^(admin|analyst|viewer|auditor)$")
    active: bool | None = None
    password: str | None = Field(default=None, max_length=256)


@router.get("/users")
def list_users(user: dict = Depends(require("users:manage")), ctx: Ctx = Depends(ctx_of)):
    return [public_user(u) for u in ctx.db.all("SELECT * FROM users ORDER BY id")]


@router.post("/users", status_code=201)
def create_user(body: UserIn, user: dict = Depends(require("users:manage")), ctx: Ctx = Depends(ctx_of)):
    bad = security.password_policy(body.password)
    if bad:
        raise HTTPException(422, bad)
    if ctx.db.one("SELECT id FROM users WHERE username=?", (body.username,)):
        raise HTTPException(409, "username already exists")
    uid = ctx.db.run("INSERT INTO users(username,display_name,password_hash,role,must_change_password,created_at) VALUES(?,?,?,?,1,?)",
                     (body.username, body.display_name, security.hash_password(body.password), body.role, time.time()))
    audit.log(ctx.db, user["username"], "user.create", role=user["role"], target=body.username, ip=user["ip"], detail={"role": body.role})
    return public_user(ctx.db.one("SELECT * FROM users WHERE id=?", (uid,)))


@router.patch("/users/{uid}")
def patch_user(uid: int, body: UserPatch, user: dict = Depends(require("users:manage")), ctx: Ctx = Depends(ctx_of)):
    t = ctx.db.one("SELECT * FROM users WHERE id=?", (uid,))
    if not t:
        raise HTTPException(404, "user not found")
    admins = ctx.db.one("SELECT COUNT(*) n FROM users WHERE role='admin' AND active=1")["n"]
    demoting = t["role"] == "admin" and t["active"] and ((body.role and body.role != "admin") or body.active is False)
    if demoting and admins <= 1:
        raise HTTPException(409, "cannot remove the last active administrator")
    sets, args = [], []
    for col, val in (("display_name", body.display_name), ("role", body.role), ("active", None if body.active is None else int(body.active))):
        if val is not None:
            sets.append(f"{col}=?"); args.append(val)
    if body.password is not None:
        bad = security.password_policy(body.password)
        if bad:
            raise HTTPException(422, bad)
        sets += ["password_hash=?", "must_change_password=1", "failed_logins=0", "locked_until=NULL"]; args.append(security.hash_password(body.password))
    if sets:
        ctx.db.run(f"UPDATE users SET {','.join(sets)} WHERE id=?", (*args, uid))
    if body.active is False or body.role or body.password:
        ctx.db.run("UPDATE sessions SET revoked=1 WHERE user_id=?", (uid,))
    audit.log(ctx.db, user["username"], "user.update", role=user["role"], target=t["username"], ip=user["ip"],
              detail={"role": body.role, "active": body.active, "password_reset": body.password is not None})
    return public_user(ctx.db.one("SELECT * FROM users WHERE id=?", (uid,)))
