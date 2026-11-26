from __future__ import annotations

import json
import threading
import time

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from pydantic import BaseModel, Field

from .. import audit, security, services as S, __version__
from .deps import ctx_of, require

router = APIRouter(prefix="/api")
Ctx = S.Ctx


# ------------------------------------------------------------ dashboard / health
@router.get("/dashboard")
def dashboard(days: int = Query(30, ge=1, le=365), user=Depends(require("scans:read")), ctx: Ctx = Depends(ctx_of)):
    db = ctx.db
    latest = "SELECT MAX(id) FROM scan_jobs WHERE state IN ('completed','partial') GROUP BY COALESCE(project_id, adhoc_path)"
    sev = {r["severity"]: r["n"] for r in db.all(f"SELECT severity, COUNT(*) n FROM findings WHERE job_id IN ({latest}) AND status NOT IN ('false_positive','fixed') GROUP BY severity")}
    cat = db.all(f"SELECT category, COUNT(*) n FROM findings WHERE job_id IN ({latest}) AND status NOT IN ('false_positive','fixed') GROUP BY category ORDER BY n DESC")
    top = db.all(f"SELECT rule_id, title, severity, COUNT(*) n FROM findings WHERE job_id IN ({latest}) AND status NOT IN ('false_positive','fixed') GROUP BY rule_id,title,severity ORDER BY n DESC LIMIT 8")
    since = time.time() - days * 86400
    trend = db.all("""SELECT date(finished_at,'unixepoch') day, ROUND(AVG(risk_score)) risk, COUNT(*) scans FROM scan_jobs
                      WHERE state IN ('completed','partial') AND finished_at>? GROUP BY day ORDER BY day""", (since,))
    states = {r["state"]: r["n"] for r in db.all("SELECT state, COUNT(*) n FROM scan_jobs GROUP BY state")}
    projects = db.all(f"""SELECT p.id, p.name, j.risk_score, j.id job_id, j.finished_at FROM projects p
                          LEFT JOIN scan_jobs j ON j.id=(SELECT MAX(id) FROM scan_jobs WHERE project_id=p.id AND state IN ('completed','partial'))
                          WHERE p.active=1 ORDER BY COALESCE(j.risk_score,-1) DESC LIMIT 10""")
    return {"severity": sev, "categories": cat, "top_rules": top, "risk_trend": trend, "job_states": states, "projects_at_risk": projects,
            "totals": {"projects": db.one("SELECT COUNT(*) n FROM projects WHERE active=1")["n"], "scans": sum(states.values()),
                       "open_findings": sum(sev.values()), "agents_online": len(S.online_agents(ctx)),
                       "schedules": db.one("SELECT COUNT(*) n FROM schedules WHERE enabled=1")["n"]}}


@router.get("/health")
def health_public(ctx: Ctx = Depends(ctx_of)):
    return {"status": "ok", "version": __version__}


@router.get("/system/health")
def system_health(user=Depends(require("system:read")), ctx: Ctx = Depends(ctx_of)):
    agents = ctx.db.all("SELECT id,name,hostname,version,last_seen,roots_json,status_json,engines_json,revoked FROM agents ORDER BY id")
    now = time.time()
    for a in agents:
        a["online"] = bool(a["last_seen"] and now - a["last_seen"] < ctx.settings.agent_offline_after_s and not a["revoked"])
        a["roots"] = [r["name"] for r in json.loads(a.pop("roots_json"))]
        a["status"] = json.loads(a.pop("status_json")); a["external_engines"] = json.loads(a.pop("engines_json"))
    db_ok = ctx.db.one("SELECT COUNT(*) n FROM schema_migrations")["n"]
    return {"version": __version__, "database": {"ok": True, "migrations": db_ok, "path_name": ctx.settings.db_path.name},
            "agents": agents, "beko": S.beko_status(ctx), "scheduler": {"enabled": ctx.settings.start_scheduler},
            "queue": {r["state"]: r["n"] for r in ctx.db.all("SELECT state, COUNT(*) n FROM scan_jobs WHERE state IN ('queued','running') GROUP BY state")},
            "bind": f"{ctx.settings.host}:{ctx.settings.port}"}


# ------------------------------------------------------------ engines
class EngineToggle(BaseModel):
    enabled: bool


@router.patch("/engines/{eid}")
def toggle_engine(eid: str, body: EngineToggle, user=Depends(require("settings:write")), ctx: Ctx = Depends(ctx_of)):
    from ..engines import registry
    if eid not in {e["id"] for e in registry.describe()}:
        raise HTTPException(404, "unknown engine")
    dis = set(ctx.db.get_setting("engines.disabled", []))
    (dis.discard if body.enabled else dis.add)(eid)
    ctx.db.set_setting("engines.disabled", sorted(dis))
    audit.log(ctx.db, user["username"], "engine.toggle", role=user["role"], target=eid, ip=user["ip"], detail={"enabled": body.enabled})
    return {"id": eid, "enabled": body.enabled}


# ------------------------------------------------------------ audit
@router.get("/audit")
def audit_list(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), actor: str | None = None, action: str | None = Query(None, max_length=60),
               outcome: str | None = None, user=Depends(require("audit:read")), ctx: Ctx = Depends(ctx_of)):
    where, args = [], []
    for col, v in (("actor", actor), ("outcome", outcome)):
        if v:
            where.append(f"{col}=?"); args.append(v)
    if action:
        where.append("action LIKE ?"); args.append(f"{action}%")
    w = ("WHERE " + " AND ".join(where)) if where else ""
    total = ctx.db.one(f"SELECT COUNT(*) n FROM audit_logs {w}", args)["n"]
    rows = ctx.db.all(f"SELECT id,ts,actor,role,action,target,ip,outcome,detail_json FROM audit_logs {w} ORDER BY id DESC LIMIT ? OFFSET ?", (*args, limit, offset))
    for r in rows:
        r["detail"] = json.loads(r.pop("detail_json"))
    return {"total": total, "items": rows}


@router.get("/audit/verify")
def audit_verify(user=Depends(require("audit:read")), ctx: Ctx = Depends(ctx_of)):
    return audit.verify_chain(ctx.db)


# ------------------------------------------------------------ agents (admin)
class AgentIn(BaseModel):
    name: str = Field(pattern=r"^[A-Za-z0-9_.\-]{3,40}$")


@router.post("/agents", status_code=201)
def create_agent(body: AgentIn, user=Depends(require("agents:manage")), ctx: Ctx = Depends(ctx_of)):
    if ctx.db.one("SELECT id FROM agents WHERE name=?", (body.name,)):
        raise HTTPException(409, "agent name exists")
    tok = security.new_secret_token("agt")
    aid = ctx.db.run("INSERT INTO agents(name,token_hash,created_at) VALUES(?,?,?)", (body.name, security.token_hash(tok), time.time()))
    audit.log(ctx.db, user["username"], "agent.create", role=user["role"], target=body.name, ip=user["ip"])
    return {"id": aid, "name": body.name, "token": tok, "note": "Store this token in the agent config now; it is shown only once."}


@router.delete("/agents/{aid}")
def revoke_agent(aid: int, user=Depends(require("agents:manage")), ctx: Ctx = Depends(ctx_of)):
    ctx.db.run("UPDATE agents SET revoked=1 WHERE id=?", (aid,))
    audit.log(ctx.db, user["username"], "agent.revoke", role=user["role"], target=f"agent:{aid}", ip=user["ip"])
    return {"ok": True}


# ------------------------------------------------------------ settings
class SettingsIn(BaseModel):
    store_snippets: bool | None = None
    beko_url: str | None = Field(default=None, max_length=200)
    beko_model: str | None = Field(default=None, max_length=100)
    notifications_enabled: bool | None = None
    webhook_url: str | None = Field(default=None, max_length=300)
    webhook_secret: str | None = Field(default=None, max_length=200)
    only_on_findings: bool | None = None
    n8n_enabled: bool | None = None


def _settings_view(ctx: Ctx) -> dict:
    n = ctx.db.get_setting("notifications", {})
    return {"store_snippets": ctx.db.get_setting("store_snippets", True),
            "beko_url": ctx.db.get_setting("beko.url", ctx.settings.ollama_url), "beko_model": ctx.db.get_setting("beko.model", ctx.settings.ollama_model),
            "notifications_enabled": bool(n.get("enabled")), "webhook_url": n.get("webhook_url", ""), "webhook_secret_set": bool(n.get("secret")),
            "only_on_findings": bool(n.get("only_on_findings")), "n8n_enabled": ctx.db.get_setting("n8n.enabled", False)}


@router.get("/settings")
def get_settings(user=Depends(require("settings:read")), ctx: Ctx = Depends(ctx_of)):
    return _settings_view(ctx)


@router.put("/settings")
def put_settings(body: SettingsIn, user=Depends(require("settings:write")), ctx: Ctx = Depends(ctx_of)):
    db = ctx.db
    if body.store_snippets is not None:
        db.set_setting("store_snippets", body.store_snippets)
    if body.beko_url is not None:
        from urllib.parse import urlparse
        u = urlparse(body.beko_url)
        if u.scheme not in ("http", "https") or u.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise HTTPException(422, "BEKO endpoint must be a local (loopback) Ollama URL")
        db.set_setting("beko.url", body.beko_url)
    if body.beko_model is not None:
        db.set_setting("beko.model", body.beko_model)
    n = db.get_setting("notifications", {})
    if body.notifications_enabled is not None:
        n["enabled"] = body.notifications_enabled
    if body.only_on_findings is not None:
        n["only_on_findings"] = body.only_on_findings
    if body.webhook_url is not None:
        if body.webhook_url:
            try:
                S.check_webhook_url(body.webhook_url, ctx.settings.allow_external_webhooks)
            except ValueError as e:
                raise HTTPException(422, str(e))
        n["webhook_url"] = body.webhook_url
    if body.webhook_secret is not None:
        n["secret"] = body.webhook_secret
    db.set_setting("notifications", n)
    if body.n8n_enabled is not None:
        db.set_setting("n8n.enabled", body.n8n_enabled)
    audit.log(db, user["username"], "settings.update", role=user["role"], ip=user["ip"], detail=body.model_dump(exclude={"webhook_secret"}, exclude_none=True))
    return _settings_view(ctx)


# ------------------------------------------------------------ BEKO
@router.get("/beko/status")
def beko_status(user=Depends(require("system:read")), ctx: Ctx = Depends(ctx_of)):
    return S.beko_status(ctx)


class BekoIn(BaseModel):
    job_id: int


@router.post("/beko/analyse", status_code=202)
def beko_run(body: BekoIn, user=Depends(require("beko:run")), ctx: Ctx = Depends(ctx_of)):
    j = ctx.db.one("SELECT * FROM scan_jobs WHERE id=?", (body.job_id,))
    if not j:
        raise HTTPException(404, "scan not found")
    if j["state"] not in ("completed", "partial"):
        raise HTTPException(409, "scan has no completed results to analyse")
    ctx.db.run("UPDATE scan_jobs SET beko_state='pending' WHERE id=?", (body.job_id,))
    audit.log(ctx.db, user["username"], "beko.analyse", role=user["role"], target=f"job:{body.job_id}", ip=user["ip"],
              detail={"sent": "aggregated rule metadata only (no code, paths or secrets)"})
    threading.Thread(target=S.run_beko, args=(ctx, body.job_id, user["username"]), daemon=True).start()
    return {"accepted": True}


@router.get("/beko/analyses")
def beko_list(job_id: int, user=Depends(require("findings:read")), ctx: Ctx = Depends(ctx_of)):
    rows = ctx.db.all("SELECT * FROM ai_analyses WHERE job_id=? ORDER BY id DESC", (job_id,))
    for r in rows:
        r["disclaimer"] = S.DISCLAIMER_AI
    return {"items": rows, "sent_metadata_preview": S.sanitized_metadata(ctx.db, job_id)}


@router.post("/beko/analyses/{aid}/review")
def beko_review(aid: int, user=Depends(require("findings:triage")), ctx: Ctx = Depends(ctx_of)):
    ctx.db.run("UPDATE ai_analyses SET human_reviewed=1, reviewed_by=? WHERE id=?", (user["username"], aid))
    audit.log(ctx.db, user["username"], "beko.review", role=user["role"], target=f"analysis:{aid}", ip=user["ip"])
    return {"ok": True}


# ------------------------------------------------------------ n8n integration (optional, key-authenticated)
class KeyIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)


@router.get("/integrations/keys")
def list_keys(user=Depends(require("settings:write")), ctx: Ctx = Depends(ctx_of)):
    return ctx.db.all("SELECT id,name,scope,created_by,created_at,revoked,last_used FROM api_keys ORDER BY id DESC")


@router.post("/integrations/keys", status_code=201)
def create_key(body: KeyIn, user=Depends(require("settings:write")), ctx: Ctx = Depends(ctx_of)):
    k = security.new_secret_token("n8n")
    kid = ctx.db.run("INSERT INTO api_keys(name,key_hash,scope,created_by,created_at) VALUES(?,?,?,?,?)", (body.name, security.token_hash(k), "n8n", user["username"], time.time()))
    audit.log(ctx.db, user["username"], "apikey.create", role=user["role"], target=body.name, ip=user["ip"])
    return {"id": kid, "key": k, "note": "Shown only once."}


@router.delete("/integrations/keys/{kid}")
def revoke_key(kid: int, user=Depends(require("settings:write")), ctx: Ctx = Depends(ctx_of)):
    ctx.db.run("UPDATE api_keys SET revoked=1 WHERE id=?", (kid,))
    audit.log(ctx.db, user["username"], "apikey.revoke", role=user["role"], target=f"key:{kid}", ip=user["ip"])
    return {"ok": True}


def _n8n(ctx: Ctx, x_api_key: str | None) -> dict:
    if not ctx.db.get_setting("n8n.enabled", False):
        raise HTTPException(404, "n8n integration is disabled")
    k = ctx.db.one("SELECT * FROM api_keys WHERE key_hash=? AND revoked=0 AND scope='n8n'", (security.token_hash(x_api_key or ""),))
    if not k:
        raise HTTPException(401, "invalid API key")
    if not ctx.limiter.allow(f"k:{k['id']}", 60):
        raise HTTPException(429, "rate limit exceeded")
    ctx.db.run("UPDATE api_keys SET last_used=? WHERE id=?", (time.time(), k["id"]))
    return k


class N8nScan(BaseModel):
    project: str = Field(max_length=80)
    engines: list[str] = Field(default_factory=lambda: ["secrets", "source", "config", "docker", "authz", "taint", "deps"], max_length=20)


@router.post("/integrations/n8n/scan", status_code=201)
def n8n_scan(body: N8nScan, x_api_key: str | None = Header(default=None), ctx: Ctx = Depends(ctx_of)):
    k = _n8n(ctx, x_api_key)
    p = ctx.db.one("SELECT * FROM projects WHERE name=? AND active=1", (body.project,))
    if not p:
        raise HTTPException(404, "project not found")
    ag = ctx.db.one("SELECT * FROM agents WHERE id=?", (p["agent_id"],))
    bad = [e for e in body.engines if e not in S.enabled_engine_ids(ctx, ag)]
    if bad:
        raise HTTPException(422, f"engines unavailable: {bad}")
    jid = S.create_job(ctx, user=f"n8n:{k['name']}", project=p, adhoc_path=None, agent_id=p["agent_id"], target_kind="project", targets=[], engines=body.engines, options={})
    audit.log(ctx.db, f"n8n:{k['name']}", "scan.create", target=f"job:{jid}", detail={"project": p["name"]})
    return {"job_id": jid}


@router.get("/integrations/n8n/scans/{jid}")
def n8n_status(jid: int, x_api_key: str | None = Header(default=None), ctx: Ctx = Depends(ctx_of)):
    _n8n(ctx, x_api_key)
    j = ctx.db.one("SELECT id,state,progress,risk_score,summary_json FROM scan_jobs WHERE id=?", (jid,))
    if not j:
        raise HTTPException(404, "scan not found")
    j["summary"] = json.loads(j.pop("summary_json"))
    return j
