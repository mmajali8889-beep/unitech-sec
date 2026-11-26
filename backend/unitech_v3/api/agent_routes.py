"""Endpoints used only by the local Windows agent (bearer agent token)."""
from __future__ import annotations

import json
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from .. import services as S
from .deps import agent_auth, ctx_of

router = APIRouter(prefix="/api/agent")
Ctx = S.Ctx


class Heartbeat(BaseModel):
    hostname: str = Field(max_length=100)
    version: str = Field(max_length=20)
    roots: list[dict] = Field(max_length=50)
    engines: list[str] = Field(default_factory=list, max_length=20)
    status: dict = Field(default_factory=dict)


@router.post("/heartbeat")
def heartbeat(body: Heartbeat, a=Depends(agent_auth), ctx: Ctx = Depends(ctx_of)):
    ctx.db.run("UPDATE agents SET last_seen=?, hostname=?, version=?, roots_json=?, engines_json=?, status_json=? WHERE id=?",
               (time.time(), body.hostname, body.version, json.dumps([{"name": str(r.get("name"))[:80]} for r in body.roots]),
                json.dumps(body.engines), json.dumps(body.status), a["id"]))
    cancel = [r["id"] for r in ctx.db.all("SELECT id FROM scan_jobs WHERE agent_id=? AND state='running' AND cancel_requested=1", (a["id"],))]
    return {"cancel_job_ids": cancel, "server_time": time.time()}


@router.post("/claim")
def claim(a=Depends(agent_auth), ctx: Ctx = Depends(ctx_of)):
    with ctx.db.tx() as c:
        row = c.execute("SELECT * FROM scan_jobs WHERE state='queued' AND agent_id=? ORDER BY id LIMIT 1", (a["id"],)).fetchone()
        if not row:
            return {"job": None}
        c.execute("UPDATE scan_jobs SET state='running', started_at=? WHERE id=?", (time.time(), row["id"]))
    j = dict(row)
    root = j["adhoc_path"]
    if j["project_id"]:
        root = ctx.db.one("SELECT canonical_path FROM projects WHERE id=?", (j["project_id"],))["canonical_path"]
    S.log_event(ctx.db, j["id"], "state", f"job started on agent {a['name']}")
    return {"job": {"id": j["id"], "root": root, "target_kind": j["target_kind"], "targets": json.loads(j["target_json"]),
                    "engines": json.loads(j["engines_json"]), "options": json.loads(j["options_json"])}}


def _own(ctx: Ctx, a: dict, jid: int) -> dict:
    j = ctx.db.one("SELECT * FROM scan_jobs WHERE id=? AND agent_id=?", (jid, a["id"]))
    if not j:
        raise HTTPException(404, "job not found for this agent")
    return j


class Events(BaseModel):
    progress: float | None = Field(default=None, ge=0, le=1)
    events: list[dict] = Field(default_factory=list, max_length=100)


@router.post("/jobs/{jid}/events")
def events(jid: int, body: Events, a=Depends(agent_auth), ctx: Ctx = Depends(ctx_of)):
    j = _own(ctx, a, jid)
    if j["state"] != "running":
        return {"cancel": True}
    for e in body.events:
        lvl = e.get("level") if e.get("level") in ("info", "warning", "error") else "info"
        S.log_event(ctx.db, jid, str(e.get("kind", "progress"))[:30], str(e.get("message", "")), lvl, e.get("data") if isinstance(e.get("data"), dict) else None)
    if body.progress is not None:
        ctx.db.run("UPDATE scan_jobs SET progress=? WHERE id=?", (body.progress, jid))
    return {"cancel": bool(j["cancel_requested"])}


class Findings(BaseModel):
    findings: list[dict] = Field(max_length=2000)


@router.post("/jobs/{jid}/findings")
def findings(jid: int, body: Findings, a=Depends(agent_auth), ctx: Ctx = Depends(ctx_of)):
    j = _own(ctx, a, jid)
    if j["state"] != "running":
        raise HTTPException(409, "job is not running")
    return {"stored": S.ingest_findings(ctx, j, body.findings)}


class Complete(BaseModel):
    outcome: str = Field(pattern="^(completed|failed|cancelled)$")
    engine_status: dict = Field(default_factory=dict)
    files_scanned: int = 0
    notes: list[str] = Field(default_factory=list, max_length=100)
    error: str | None = Field(default=None, max_length=500)


@router.post("/jobs/{jid}/complete")
def complete(jid: int, body: Complete, a=Depends(agent_auth), ctx: Ctx = Depends(ctx_of)):
    j = _own(ctx, a, jid)
    if j["state"] != "running":
        raise HTTPException(409, "job is not running")
    outcome = "cancelled" if j["cancel_requested"] and body.outcome != "failed" else body.outcome
    return {"state": S.finalize_job(ctx, j, outcome, body.engine_status, body.files_scanned, body.notes, body.error)["state"]}


@router.get("/rpc/claim")
def rpc_claim(a=Depends(agent_auth), ctx: Ctx = Depends(ctx_of)):
    with ctx.db.tx() as c:
        row = c.execute("SELECT * FROM agent_rpc WHERE agent_id=? AND state='pending' AND created_at>? ORDER BY id LIMIT 1", (a["id"], time.time() - 60)).fetchone()
        if not row:
            return {"rpc": None}
        c.execute("UPDATE agent_rpc SET state='claimed' WHERE id=?", (row["id"],))
    return {"rpc": {"id": row["id"], "kind": row["kind"], "params": json.loads(row["params_json"])}}


class RpcResult(BaseModel):
    ok: bool
    result: dict | None = None
    error: str | None = Field(default=None, max_length=300)
    denied: bool = False


@router.post("/rpc/{rid}/result")
def rpc_result(rid: int, body: RpcResult, a=Depends(agent_auth), ctx: Ctx = Depends(ctx_of)):
    r = ctx.db.one("SELECT id FROM agent_rpc WHERE id=? AND agent_id=? AND state='claimed'", (rid, a["id"]))
    if not r:
        raise HTTPException(404, "rpc not found")
    ctx.db.run("UPDATE agent_rpc SET state='done', result_json=?, done_at=? WHERE id=?", (json.dumps(body.model_dump()), time.time(), rid))
    return {"ok": True}
