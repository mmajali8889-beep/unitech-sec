from __future__ import annotations

import json
import time

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .. import audit, services as S
from ..engines.base import SEVERITIES
from .deps import ctx_of, require

router = APIRouter(prefix="/api")
Ctx = S.Ctx


def _agent_for(ctx: Ctx, agent_id: int | None = None) -> dict:
    ags = S.online_agents(ctx)
    if agent_id is not None:
        ags = [a for a in ags if a["id"] == agent_id]
    if not ags:
        raise HTTPException(503, "no Windows agent is online")
    return ags[0]


def _rpc(ctx: Ctx, agent: dict, kind: str, params: dict):
    try:
        return S.rpc(ctx, agent["id"], kind, params)
    except S.RpcError as e:
        raise HTTPException(e.code, str(e))


# ============================================================ browse / projects
@router.get("/browse")
def browse(path: str = Query(default="", max_length=1024), agent_id: int | None = None, user=Depends(require("browse")), ctx: Ctx = Depends(ctx_of)):
    """Browse approved directories only (agent enforces the allow-list)."""
    ag = _agent_for(ctx, agent_id)
    res = _rpc(ctx, ag, "browse", {"path": path})
    audit.log(ctx.db, user["username"], "browse", role=user["role"], target=path or "<roots>", ip=user["ip"])
    return {**res, "agent_id": ag["id"]}


class DiscoverIn(BaseModel):
    path: str = Field(default="", max_length=1024)
    agent_id: int | None = None


@router.post("/projects/discover")
def discover(body: DiscoverIn, user=Depends(require("projects:write")), ctx: Ctx = Depends(ctx_of)):
    ag = _agent_for(ctx, body.agent_id)
    known = {p["canonical_path"] for p in ctx.db.all("SELECT canonical_path FROM projects")}
    res = _rpc(ctx, ag, "discover", {"path": body.path})
    for c in res["candidates"]:
        c["registered"] = c["path"] in known
    return {**res, "agent_id": ag["id"]}


class ProjectIn(BaseModel):
    name: str = Field(min_length=2, max_length=80, pattern=r"^[\w .\-]+$")
    path: str = Field(min_length=1, max_length=1024)
    kind: str = Field(default="generic", max_length=30)
    tags: str = Field(default="", max_length=200)
    agent_id: int | None = None


@router.get("/projects")
def list_projects(user=Depends(require("projects:read")), ctx: Ctx = Depends(ctx_of)):
    rows = ctx.db.all("""SELECT p.*, (SELECT risk_score FROM scan_jobs j WHERE j.project_id=p.id AND j.state IN ('completed','partial') ORDER BY j.id DESC LIMIT 1) risk_score,
                         (SELECT id FROM scan_jobs j WHERE j.project_id=p.id AND j.state IN ('completed','partial') ORDER BY j.id DESC LIMIT 1) last_job_id
                         FROM projects p ORDER BY p.name""")
    return rows


@router.post("/projects", status_code=201)
def register_project(body: ProjectIn, user=Depends(require("projects:write")), ctx: Ctx = Depends(ctx_of)):
    ag = _agent_for(ctx, body.agent_id)
    res = _rpc(ctx, ag, "validate_path", {"path": body.path, "must_be_dir": True})
    canon = res["canonical"]
    if ctx.db.one("SELECT id FROM projects WHERE name=? OR canonical_path=?", (body.name, canon)):
        raise HTTPException(409, "project name or path already registered")
    pid = ctx.db.run("INSERT INTO projects(name,canonical_path,kind,tags,agent_id,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                     (body.name, canon, body.kind, body.tags, ag["id"], user["username"], time.time()))
    audit.log(ctx.db, user["username"], "project.register", role=user["role"], target=body.name, ip=user["ip"], detail={"path": canon})
    return ctx.db.one("SELECT * FROM projects WHERE id=?", (pid,))


@router.delete("/projects/{pid}")
def deactivate_project(pid: int, user=Depends(require("projects:write")), ctx: Ctx = Depends(ctx_of)):
    """Soft-removes the registration only. Never touches files on disk."""
    p = ctx.db.one("SELECT * FROM projects WHERE id=?", (pid,))
    if not p:
        raise HTTPException(404, "project not found")
    ctx.db.run("UPDATE projects SET active=0 WHERE id=?", (pid,))
    ctx.db.run("UPDATE schedules SET enabled=0 WHERE project_id=?", (pid,))
    audit.log(ctx.db, user["username"], "project.deactivate", role=user["role"], target=p["name"], ip=user["ip"])
    return {"ok": True}


# ============================================================ scans
class ScanIn(BaseModel):
    project_id: int | None = None
    adhoc_path: str | None = Field(default=None, max_length=1024)
    targets: list[str] = Field(default_factory=list, max_length=200)
    engines: list[str] = Field(min_length=1, max_length=20)
    beko: bool = False
    timeout_s: int = Field(default=600, ge=10, le=3600)
    max_files: int = Field(default=20000, ge=1, le=200000)


@router.get("/capabilities")
def capabilities(user=Depends(require("engines:read")), ctx: Ctx = Depends(ctx_of)):
    from ..engines import registry
    ags = S.online_agents(ctx)
    ext = set()
    for a in ags:
        ext |= set(json.loads(a["engines_json"]))
    return {"engines": registry.describe(disabled=set(ctx.db.get_setting("engines.disabled", [])), agent_ext=ext),
            "classification": registry.CLASSIFICATION, "legacy": registry.LEGACY, "agents_online": len(ags)}


@router.post("/scans", status_code=201)
def create_scan(body: ScanIn, user=Depends(require("scans:run")), ctx: Ctx = Depends(ctx_of)):
    if (body.project_id is None) == (body.adhoc_path is None):
        raise HTTPException(422, "provide exactly one of project_id or adhoc_path")
    try:
        targets = S.validate_targets(body.targets)
    except ValueError as e:
        raise HTTPException(422, str(e))
    project = None
    if body.project_id is not None:
        project = ctx.db.one("SELECT * FROM projects WHERE id=? AND active=1", (body.project_id,))
        if not project:
            raise HTTPException(404, "project not found")
        agent = _agent_for(ctx, project["agent_id"]) if S.online_agents(ctx) else ctx.db.one("SELECT * FROM agents WHERE id=?", (project["agent_id"],))
        if not agent:
            raise HTTPException(503, "project agent is not available")
        kind = "files" if targets else "project"
        adhoc = None
    else:
        agent = _agent_for(ctx)
        res = _rpc(ctx, agent, "validate_path", {"path": body.adhoc_path})
        adhoc, kind = res["canonical"], ("file" if res["is_file"] else "directory")
        if res["is_file"] and targets:
            raise HTTPException(422, "targets not allowed for a single-file scan")
    allowed = S.enabled_engine_ids(ctx, agent)
    bad = [e for e in body.engines if e not in allowed]
    if bad:
        raise HTTPException(422, f"engines unavailable or disabled: {', '.join(bad)}")
    opts = {"beko": body.beko, "timeout_s": body.timeout_s, "max_files": body.max_files}
    jid = S.create_job(ctx, user=user["username"], project=project, adhoc_path=adhoc, agent_id=agent["id"], target_kind=kind,
                       targets=targets, engines=list(dict.fromkeys(body.engines)), options=opts)
    audit.log(ctx.db, user["username"], "scan.create", role=user["role"], target=f"job:{jid}", ip=user["ip"],
              detail={"project": project["name"] if project else None, "engines": body.engines, "kind": kind})
    return ctx.db.one("SELECT * FROM scan_jobs WHERE id=?", (jid,))


def _job_row(j: dict) -> dict:
    for k in ("target_json", "engines_json", "options_json", "summary_json", "engine_status_json"):
        j[k[:-5]] = json.loads(j.pop(k) or "null")
    return j


@router.get("/scans")
def list_scans(state: str | None = None, project_id: int | None = None, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
               user=Depends(require("scans:read")), ctx: Ctx = Depends(ctx_of)):
    where, args = [], []
    if state:
        if state not in S.SCAN_STATES:
            raise HTTPException(422, "invalid state")
        where.append("j.state=?"); args.append(state)
    if project_id:
        where.append("j.project_id=?"); args.append(project_id)
    w = ("WHERE " + " AND ".join(where)) if where else ""
    total = ctx.db.one(f"SELECT COUNT(*) n FROM scan_jobs j {w}", args)["n"]
    rows = ctx.db.all(f"SELECT j.*, p.name project_name FROM scan_jobs j LEFT JOIN projects p ON p.id=j.project_id {w} ORDER BY j.id DESC LIMIT ? OFFSET ?", (*args, limit, offset))
    return {"total": total, "items": [_job_row(r) for r in rows]}


def _get_job(ctx: Ctx, jid: int) -> dict:
    j = ctx.db.one("SELECT j.*, p.name project_name FROM scan_jobs j LEFT JOIN projects p ON p.id=j.project_id WHERE j.id=?", (jid,))
    if not j:
        raise HTTPException(404, "scan not found")
    return j


@router.get("/scans/{jid}")
def get_scan(jid: int, user=Depends(require("scans:read")), ctx: Ctx = Depends(ctx_of)):
    return _job_row(_get_job(ctx, jid))


@router.get("/scans/{jid}/events")
def scan_events(jid: int, after: int = 0, user=Depends(require("scans:read")), ctx: Ctx = Depends(ctx_of)):
    j = _get_job(ctx, jid)
    ev = ctx.db.all("SELECT id,ts,level,kind,message,data_json FROM job_events WHERE job_id=? AND id>? ORDER BY id LIMIT 500", (jid, after))
    for e in ev:
        e["data"] = json.loads(e.pop("data_json"))
    return {"state": j["state"], "progress": j["progress"], "events": ev}


@router.post("/scans/{jid}/cancel")
def cancel_scan(jid: int, user=Depends(require("scans:cancel")), ctx: Ctx = Depends(ctx_of)):
    j = _get_job(ctx, jid)
    if j["state"] == "queued":
        ctx.db.run("UPDATE scan_jobs SET state='cancelled', finished_at=?, cancel_requested=1 WHERE id=? AND state='queued'", (time.time(), jid))
        S.log_event(ctx.db, jid, "state", f"cancelled by {user['username']} before start", "warning")
    elif j["state"] == "running":
        ctx.db.run("UPDATE scan_jobs SET cancel_requested=1 WHERE id=?", (jid,))
        S.log_event(ctx.db, jid, "cancel", f"cancellation requested by {user['username']}", "warning")
    else:
        raise HTTPException(409, f"scan already {j['state']}")
    audit.log(ctx.db, user["username"], "scan.cancel", role=user["role"], target=f"job:{jid}", ip=user["ip"])
    return _job_row(_get_job(ctx, jid))


@router.get("/scans/{jid}/compare")
def compare(jid: int, base: int | None = None, user=Depends(require("scans:read")), ctx: Ctx = Depends(ctx_of)):
    j = _get_job(ctx, jid)
    if base is None:
        prev = ctx.db.one("SELECT id FROM scan_jobs WHERE project_id IS ? AND id<? AND state IN ('completed','partial') ORDER BY id DESC LIMIT 1", (j["project_id"], jid))
        if not prev:
            return {"base": None, "new": [], "fixed": [], "unchanged": 0, "note": "no previous scan to compare with"}
        base = prev["id"]
    cur = {f["fingerprint"]: f for f in ctx.db.all("SELECT * FROM findings WHERE job_id=?", (jid,))}
    old = {f["fingerprint"]: f for f in ctx.db.all("SELECT * FROM findings WHERE job_id=?", (base,))}
    new = [cur[k] for k in cur if k not in old]
    fixed = [old[k] for k in old if k not in cur]
    bj = ctx.db.one("SELECT risk_score FROM scan_jobs WHERE id=?", (base,))
    return {"base": base, "new": new, "fixed": fixed, "unchanged": len(set(cur) & set(old)),
            "risk_delta": j["risk_score"] - (bj["risk_score"] if bj else 0)}


# ============================================================ findings
CATEGORY_GROUPS = {"source": ["source", "authz", "taint"], "secrets": ["secrets"], "dependency": ["dependency"], "docker": ["docker"], "config": ["config"]}


@router.get("/findings")
def list_findings(job_id: int | None = None, project_id: int | None = None, severity: str | None = None, category: str | None = None,
                  engine: str | None = None, rule_id: str | None = None, status: str | None = None, q: str | None = Query(None, max_length=100),
                  verification: str | None = None, latest: bool = True, limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0),
                  user=Depends(require("findings:read")), ctx: Ctx = Depends(ctx_of)):
    where, args = [], []
    if job_id:
        where.append("f.job_id=?"); args.append(job_id)
    elif latest:  # most recent finished scan of each project
        where.append("f.job_id IN (SELECT MAX(id) FROM scan_jobs WHERE state IN ('completed','partial') GROUP BY COALESCE(project_id, adhoc_path))")
    for col, val in (("f.project_id", project_id), ("f.severity", severity), ("f.engine", engine), ("f.rule_id", rule_id), ("f.status", status), ("f.verification", verification)):
        if val:
            where.append(f"{col}=?"); args.append(val)
    if severity and severity not in SEVERITIES:
        raise HTTPException(422, "invalid severity")
    if category:
        cats = CATEGORY_GROUPS.get(category, [category])
        where.append(f"f.category IN ({','.join('?' * len(cats))})"); args += cats
    if q:
        where.append("(f.file LIKE ? OR f.title LIKE ? OR f.rule_id LIKE ?)"); args += [f"%{q}%"] * 3
    w = ("WHERE " + " AND ".join(where)) if where else ""
    total = ctx.db.one(f"SELECT COUNT(*) n FROM findings f {w}", args)["n"]
    sev = {r["severity"]: r["n"] for r in ctx.db.all(f"SELECT severity, COUNT(*) n FROM findings f {w} GROUP BY severity", args)}
    rows = ctx.db.all(f"""SELECT f.*, p.name project_name FROM findings f LEFT JOIN projects p ON p.id=f.project_id {w}
        ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.file, f.line LIMIT ? OFFSET ?""", (*args, limit, offset))
    return {"total": total, "severity_counts": sev, "items": rows}


class TriageIn(BaseModel):
    status: str = Field(pattern="^(open|triaged|accepted|false_positive|fixed)$")
    note: str = Field(default="", max_length=500)


@router.patch("/findings/{fid}")
def triage(fid: int, body: TriageIn, user=Depends(require("findings:triage")), ctx: Ctx = Depends(ctx_of)):
    f = ctx.db.one("SELECT * FROM findings WHERE id=?", (fid,))
    if not f:
        raise HTTPException(404, "finding not found")
    # applies to every occurrence of the same fingerprint in the project so triage survives re-scans
    if f["project_id"]:
        ctx.db.run("UPDATE findings SET status=?, status_note=?, status_by=? WHERE project_id=? AND fingerprint=?", (body.status, body.note, user["username"], f["project_id"], f["fingerprint"]))
    else:
        ctx.db.run("UPDATE findings SET status=?, status_note=?, status_by=? WHERE id=?", (body.status, body.note, user["username"], fid))
    audit.log(ctx.db, user["username"], "finding.triage", role=user["role"], target=f"finding:{fid}", ip=user["ip"], detail={"status": body.status})
    return ctx.db.one("SELECT * FROM findings WHERE id=?", (fid,))


# ============================================================ reports
class ReportIn(BaseModel):
    job_id: int
    format: str = Field(pattern="^(json|html|sarif|pdf)$")


@router.post("/reports", status_code=201)
def create_report(body: ReportIn, user=Depends(require("reports:create")), ctx: Ctx = Depends(ctx_of)):
    j = _get_job(ctx, body.job_id)
    if j["state"] in ("queued", "running"):
        raise HTTPException(409, "scan has not finished")
    r = S.generate_report(ctx, body.job_id, body.format, user["username"])
    audit.log(ctx.db, user["username"], "report.create", role=user["role"], target=f"job:{body.job_id}", ip=user["ip"], detail={"format": body.format})
    return r


@router.get("/reports")
def list_reports(job_id: int | None = None, user=Depends(require("reports:read")), ctx: Ctx = Depends(ctx_of)):
    w, a = ("WHERE r.job_id=?", [job_id]) if job_id else ("", [])
    return ctx.db.all(f"SELECT r.id,r.job_id,r.format,r.sha256,r.size,r.created_by,r.created_at,p.name project_name FROM reports r JOIN scan_jobs j ON j.id=r.job_id LEFT JOIN projects p ON p.id=j.project_id {w} ORDER BY r.id DESC LIMIT 200", a)


@router.get("/reports/{rid}/download")
def download_report(rid: int, user=Depends(require("reports:read")), ctx: Ctx = Depends(ctx_of)):
    r = ctx.db.one("SELECT * FROM reports WHERE id=?", (rid,))
    if not r:
        raise HTTPException(404, "report not found")
    audit.log(ctx.db, user["username"], "report.download", role=user["role"], target=f"report:{rid}", ip=user["ip"])
    return FileResponse(r["path"], media_type=S.RENDERERS[r["format"]][1], filename=f"unitech-report-job{r['job_id']}.{r['format']}",
                        headers={"X-Content-Type-Options": "nosniff", "Content-Security-Policy": "sandbox"})


# ============================================================ schedules
class ScheduleIn(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    project_id: int
    engines: list[str] = Field(min_length=1, max_length=20)
    beko: bool = False
    interval_minutes: int | None = Field(default=None, ge=5, le=525600)
    daily_at: str | None = Field(default=None, pattern=r"^([01]\d|2[0-3]):[0-5]\d$")


@router.get("/schedules")
def list_schedules(user=Depends(require("schedules:read")), ctx: Ctx = Depends(ctx_of)):
    rows = ctx.db.all("SELECT s.*, p.name project_name FROM schedules s JOIN projects p ON p.id=s.project_id ORDER BY s.id DESC")
    for r in rows:
        r["engines"] = json.loads(r.pop("engines_json")); r["options"] = json.loads(r.pop("options_json"))
    return rows


@router.post("/schedules", status_code=201)
def create_schedule(body: ScheduleIn, user=Depends(require("schedules:write")), ctx: Ctx = Depends(ctx_of)):
    if bool(body.interval_minutes) == bool(body.daily_at):
        raise HTTPException(422, "provide exactly one of interval_minutes or daily_at")
    p = ctx.db.one("SELECT * FROM projects WHERE id=? AND active=1", (body.project_id,))
    if not p:
        raise HTTPException(404, "project not found")
    ag = ctx.db.one("SELECT * FROM agents WHERE id=?", (p["agent_id"],))
    bad = [e for e in body.engines if e not in S.enabled_engine_ids(ctx, ag)]
    if bad:
        raise HTTPException(422, f"engines unavailable or disabled: {', '.join(bad)}")
    sid = ctx.db.run("INSERT INTO schedules(name,project_id,engines_json,options_json,interval_minutes,daily_at,next_run,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                     (body.name, body.project_id, json.dumps(body.engines), json.dumps({"beko": body.beko}), body.interval_minutes, body.daily_at,
                      S.next_run_for(body.interval_minutes, body.daily_at), user["username"], time.time()))
    audit.log(ctx.db, user["username"], "schedule.create", role=user["role"], target=body.name, ip=user["ip"])
    return ctx.db.one("SELECT * FROM schedules WHERE id=?", (sid,))


class SchedulePatch(BaseModel):
    enabled: bool


@router.patch("/schedules/{sid}")
def toggle_schedule(sid: int, body: SchedulePatch, user=Depends(require("schedules:write")), ctx: Ctx = Depends(ctx_of)):
    s = ctx.db.one("SELECT * FROM schedules WHERE id=?", (sid,))
    if not s:
        raise HTTPException(404, "schedule not found")
    ctx.db.run("UPDATE schedules SET enabled=?, next_run=? WHERE id=?", (int(body.enabled), S.next_run_for(s["interval_minutes"], s["daily_at"]), sid))
    audit.log(ctx.db, user["username"], "schedule.update", role=user["role"], target=s["name"], ip=user["ip"], detail={"enabled": body.enabled})
    return ctx.db.one("SELECT * FROM schedules WHERE id=?", (sid,))


@router.delete("/schedules/{sid}")
def delete_schedule(sid: int, user=Depends(require("schedules:write")), ctx: Ctx = Depends(ctx_of)):
    s = ctx.db.one("SELECT * FROM schedules WHERE id=?", (sid,))
    if not s:
        raise HTTPException(404, "schedule not found")
    ctx.db.run("UPDATE scan_jobs SET schedule_id=NULL WHERE schedule_id=?", (sid,))
    ctx.db.run("DELETE FROM schedules WHERE id=?", (sid,))
    audit.log(ctx.db, user["username"], "schedule.delete", role=user["role"], target=s["name"], ip=user["ip"])
    return {"ok": True}
