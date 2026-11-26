"""Shared services: ingest, job lifecycle, reports, BEKO (Ollama), RPC to agents, scheduler, notifications."""
from __future__ import annotations

import hashlib
import html
import ipaddress
import json
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx

from . import audit
from .config import Settings
from .db import DB
from .engines.base import SEVERITIES
from .redact import redact_line

WEIGHTS = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
FINDING_STATUSES = ["open", "triaged", "accepted", "false_positive", "fixed"]
SCAN_STATES = ["queued", "running", "completed", "partial", "failed", "cancelled"]
DISCLAIMER_AI = "AI-GENERATED - UNVERIFIED. Requires human review before any action."


class Ctx:
    def __init__(self, settings: Settings, db: DB, secret: str, limiter):
        self.settings, self.db, self.secret, self.limiter = settings, db, secret, limiter
        self.stop = threading.Event()


# ---------------------------------------------------------------- jobs / ingest
def risk_score(counts: dict[str, int]) -> int:
    return min(100, sum(WEIGHTS[s] * counts.get(s, 0) for s in SEVERITIES))


def log_event(db: DB, job_id: int, kind: str, message: str, level: str = "info", data: dict | None = None) -> None:
    db.run("INSERT INTO job_events(job_id,ts,level,kind,message,data_json) VALUES(?,?,?,?,?,?)",
           (job_id, time.time(), level, kind, redact_line(message, 400), json.dumps(data or {})))


def fingerprint(project_key: str, f: dict) -> str:
    return hashlib.sha256(f"{project_key}|{f['rule_id']}|{f['file']}|{f.get('context_hash', '')}".encode()).hexdigest()[:32]


def ingest_findings(ctx: Ctx, job: dict, items: list[dict]) -> int:
    store_snip = ctx.db.get_setting("store_snippets", True)
    pkey = str(job["project_id"] or ("adhoc:" + (job["adhoc_path"] or "")))
    now = time.time()
    n = 0
    with ctx.db.tx() as c:
        for f in items[:5000]:
            sev = f.get("severity")
            if sev not in SEVERITIES:
                continue
            rel = str(f.get("file", "")).replace("\\", "/")
            if rel.startswith("/") or (len(rel) > 1 and rel[1] == ":"):
                rel = Path(rel).name        # never persist absolute host paths
            fp = fingerprint(pkey, {**f, "file": rel})
            prior = c.execute("SELECT status,status_note FROM findings WHERE project_id IS ? AND fingerprint=? AND status!='open' ORDER BY id DESC LIMIT 1",
                              (job["project_id"], fp)).fetchone() if job["project_id"] else None
            snippet = redact_line(str(f.get("snippet", ""))) if store_snip else ""
            c.execute("""INSERT INTO findings(job_id,project_id,fingerprint,engine,rule_id,category,severity,title,file,line,col,snippet,
                         verification,remediation,cwe,status,status_note,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (job["id"], job["project_id"], fp, str(f.get("engine", ""))[:40], str(f.get("rule_id", ""))[:40], str(f.get("category", "source"))[:30],
                       sev, redact_line(str(f.get("title", "")), 200), rel[:500], int(f.get("line") or 0), int(f.get("col") or 0), snippet,
                       f.get("verification") if f.get("verification") in ("deterministic", "heuristic") else "heuristic",
                       str(f.get("remediation", ""))[:500], str(f.get("cwe", ""))[:20],
                       prior["status"] if prior else "open", prior["status_note"] if prior else "", now))
            n += 1
    return n


def finalize_job(ctx: Ctx, job: dict, outcome: str, engine_status: dict, files_scanned: int, notes: list[str], error: str | None) -> dict:
    db = ctx.db
    counts = {r["severity"]: r["n"] for r in db.all("SELECT severity, COUNT(*) n FROM findings WHERE job_id=? GROUP BY severity", (job["id"],))}
    if outcome == "cancelled":
        state = "cancelled"
    elif outcome == "failed":
        state = "failed"
    else:
        failed = [e for e, s in engine_status.items() if s.get("state") == "failed"]
        state = "completed" if not failed else ("failed" if len(failed) == len(engine_status) else "partial")
    summary = {"counts": counts, "total": sum(counts.values()), "notes": notes[:20]}
    want_beko = bool(json.loads(job["options_json"] or "{}").get("beko")) and state in ("completed", "partial")
    db.run("""UPDATE scan_jobs SET state=?, finished_at=?, progress=?, error=?, summary_json=?, engine_status_json=?, files_scanned=?, risk_score=?,
              beko_state=CASE WHEN ? THEN 'pending' ELSE beko_state END WHERE id=?""",
           (state, time.time(), 1.0 if state in ("completed", "partial") else job["progress"], (error or "")[:500] or None,
            json.dumps(summary), json.dumps(engine_status), files_scanned, risk_score(counts), int(want_beko), job["id"]))
    if job["project_id"] and state in ("completed", "partial"):
        db.run("UPDATE projects SET last_scan_at=? WHERE id=?", (time.time(), job["project_id"]))
    log_event(db, job["id"], "state", f"job {state}", "info" if state in ("completed", "partial") else "warning", {"state": state})
    audit.log(db, f"agent:{job['agent_id']}", "scan.finish", target=f"job:{job['id']}", detail={"state": state, "total": summary["total"]})
    job = db.one("SELECT * FROM scan_jobs WHERE id=?", (job["id"],))
    opts = json.loads(job["options_json"] or "{}")
    if want_beko:
        threading.Thread(target=run_beko, args=(ctx, job["id"], "auto"), daemon=True).start()
    threading.Thread(target=notify, args=(ctx, job["id"]), daemon=True).start()
    return job


def validate_targets(targets: list[str]) -> list[str]:
    clean = []
    for t in targets:
        t = t.replace("\\", "/").strip()
        if not t or t.startswith("/") or (len(t) > 1 and t[1] == ":") or ".." in t.split("/") or "\x00" in t or len(t) > 500:
            raise ValueError(f"invalid target path: {t[:60]!r}")
        clean.append(t)
    if len(clean) > 200:
        raise ValueError("too many targets (max 200)")
    return clean


def create_job(ctx: Ctx, *, user: str, project: dict | None, adhoc_path: str | None, agent_id: int, target_kind: str,
               targets: list[str], engines: list[str], options: dict, schedule_id: int | None = None) -> int:
    jid = ctx.db.run("""INSERT INTO scan_jobs(project_id,adhoc_path,target_kind,target_json,engines_json,options_json,state,created_by,created_at,agent_id,schedule_id)
                        VALUES(?,?,?,?,?,?, 'queued',?,?,?,?)""",
                     (project["id"] if project else None, adhoc_path, target_kind, json.dumps(targets), json.dumps(engines),
                      json.dumps(options), user, time.time(), agent_id, schedule_id))
    log_event(ctx.db, jid, "state", "job queued", data={"engines": engines})
    return jid


def enabled_engine_ids(ctx: Ctx, agent: dict | None = None) -> set[str]:
    from .engines import registry
    disabled = set(ctx.db.get_setting("engines.disabled", []))
    ext = set(json.loads(agent["engines_json"])) if agent else set()
    return {e["id"] for e in registry.describe(disabled=disabled, agent_ext=ext) if e["available"] and e["enabled"]}


def online_agents(ctx: Ctx) -> list[dict]:
    cutoff = time.time() - ctx.settings.agent_offline_after_s
    return ctx.db.all("SELECT * FROM agents WHERE revoked=0 AND last_seen>? ORDER BY last_seen DESC", (cutoff,))


# ---------------------------------------------------------------- RPC to agent
class RpcError(Exception):
    def __init__(self, msg: str, code: int = 502):
        super().__init__(msg)
        self.code = code


def rpc(ctx: Ctx, agent_id: int, kind: str, params: dict, timeout: float = 20.0) -> dict:
    rid = ctx.db.run("INSERT INTO agent_rpc(agent_id,kind,params_json,created_at) VALUES(?,?,?,?)", (agent_id, kind, json.dumps(params), time.time()))
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        r = ctx.db.one("SELECT state,result_json FROM agent_rpc WHERE id=?", (rid,))
        if r and r["state"] == "done":
            res = json.loads(r["result_json"])
            if not res.get("ok"):
                raise RpcError(res.get("error", "agent error"), 400 if res.get("denied") else 502)
            return res["result"]
        time.sleep(0.1)
    ctx.db.run("UPDATE agent_rpc SET state='expired' WHERE id=? AND state='pending'", (rid,))
    raise RpcError("agent did not respond in time", 504)


# ---------------------------------------------------------------- reports
def job_bundle(db: DB, job_id: int) -> dict:
    job = db.one("SELECT * FROM scan_jobs WHERE id=?", (job_id,))
    proj = db.one("SELECT id,name,kind FROM projects WHERE id=?", (job["project_id"],)) if job["project_id"] else None
    fs = db.all("SELECT * FROM findings WHERE job_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, file, line", (job_id,))
    ai = db.one("SELECT * FROM ai_analyses WHERE job_id=? ORDER BY id DESC LIMIT 1", (job_id,))
    return {"job": job, "project": proj, "findings": fs, "ai": ai}


def render_json(b: dict) -> bytes:
    j = b["job"]
    doc = {"report": "UNITECH Security Center V3", "generated_at": datetime.now(timezone.utc).isoformat(),
           "job": {k: j[k] for k in ("id", "state", "target_kind", "created_at", "started_at", "finished_at", "files_scanned", "risk_score")},
           "project": b["project"], "engines": json.loads(j["engine_status_json"]), "summary": json.loads(j["summary_json"]),
           "findings": [{k: f[k] for k in ("id", "severity", "rule_id", "engine", "category", "title", "file", "line", "verification", "remediation", "cwe", "status", "snippet")} for f in b["findings"]]}
    if b["ai"]:
        doc["ai_analysis"] = {"model": b["ai"]["model"], "state": b["ai"]["state"], "disclaimer": DISCLAIMER_AI, "human_reviewed": bool(b["ai"]["human_reviewed"]), "content": b["ai"]["content"]}
    return json.dumps(doc, indent=2).encode()


def render_sarif(b: dict) -> bytes:
    lvl = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, seen = [], set()
    for f in b["findings"]:
        if f["rule_id"] not in seen:
            seen.add(f["rule_id"])
            rules.append({"id": f["rule_id"], "name": f["title"], "shortDescription": {"text": f["title"]}, "help": {"text": f["remediation"]},
                          "properties": {"category": f["category"], "cwe": f["cwe"]}})
    results = [{"ruleId": f["rule_id"], "level": lvl[f["severity"]], "message": {"text": f"{f['title']} ({f['severity']})"},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]}, "region": {"startLine": max(1, f["line"])}}}],
                "partialFingerprints": {"v3": f["fingerprint"]}, "properties": {"verification": f["verification"], "status": f["status"]}} for f in b["findings"]]
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "UNITECH Security Center V3", "version": "3.0.0", "rules": rules}}, "results": results}]}
    return json.dumps(doc, indent=2).encode()


def render_html(b: dict) -> bytes:
    e = html.escape
    j, counts = b["job"], json.loads(b["job"]["summary_json"]).get("counts", {})
    rows = "".join(f"<tr class='{e(f['severity'])}'><td>{e(f['severity'])}</td><td>{e(f['rule_id'])}</td><td>{e(f['title'])}</td><td>{e(f['file'])}:{f['line']}</td><td>{e(f['verification'])}</td><td>{e(f['remediation'])}</td></tr>" for f in b["findings"])
    chips = "".join(f"<span class='chip {s}'>{s}: {counts.get(s, 0)}</span>" for s in SEVERITIES)
    ai = ""
    if b["ai"] and b["ai"]["state"] == "ok":
        ai = f"<h2>BEKO AI analysis</h2><p class='warn'>{e(DISCLAIMER_AI)}</p><pre>{e(b['ai']['content'])}</pre>"
    name = e(b["project"]["name"]) if b["project"] else "ad-hoc scan"
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Security report #{j['id']}</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem;color:#111}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.35rem;font-size:.85rem;text-align:left}}
.chip{{display:inline-block;padding:.2rem .6rem;margin:.1rem;border-radius:1rem;background:#eee}}.critical td:first-child{{color:#b00020;font-weight:700}}.high td:first-child{{color:#d84315;font-weight:700}}
.medium td:first-child{{color:#b26a00}}.warn{{background:#fff3cd;padding:.5rem;border-radius:.3rem}}pre{{white-space:pre-wrap}}</style></head><body>
<h1>UNITECH Security Center V3 - Scan report #{j['id']}</h1><p>Project: <b>{name}</b> · State: <b>{e(j['state'])}</b> · Risk score: <b>{j['risk_score']}/100</b> · Files scanned: {j['files_scanned']}</p>
<p>{chips}</p><p><small>Secret values and source snippets are redacted. READ-ONLY scan - no files were modified.</small></p>
<table><tr><th>Severity</th><th>Rule</th><th>Title</th><th>Location</th><th>Verification</th><th>Remediation</th></tr>{rows}</table>{ai}</body></html>"""
    return doc.encode()


def render_pdf(b: dict) -> bytes:
    import io
    from xml.sax.saxutils import escape
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), title=f"Security report {b['job']['id']}")
    st = getSampleStyleSheet()
    small = st["BodyText"].clone("small", fontSize=7, leading=9)
    j = b["job"]
    name = b["project"]["name"] if b["project"] else "ad-hoc scan"
    els = [Paragraph("UNITECH Security Center V3 - Scan Report", st["Title"]),
           Paragraph(escape(f"Job #{j['id']} · {name} · state {j['state']} · risk {j['risk_score']}/100 · files {j['files_scanned']}"), st["Normal"]),
           Paragraph("Secrets and snippets are redacted. READ-ONLY scan.", st["Italic"]), Spacer(1, 8)]
    data = [["Severity", "Rule", "Title", "Location", "Verif.", "Remediation"]]
    for f in b["findings"][:2000]:
        data.append([f["severity"], f["rule_id"], Paragraph(escape(f["title"]), small), Paragraph(escape(f"{f['file']}:{f['line']}"), small), f["verification"][:6], Paragraph(escape(f["remediation"]), small)])
    t = Table(data, repeatRows=1, colWidths=[55, 50, 170, 190, 40, 250])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("FONTSIZE", (0, 0), (-1, -1), 7), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    els.append(t)
    if b["ai"] and b["ai"]["state"] == "ok":
        els += [Spacer(1, 10), Paragraph("BEKO AI analysis (" + escape(DISCLAIMER_AI) + ")", st["Heading3"]), Paragraph(escape(b["ai"]["content"])[:6000].replace("\n", "<br/>"), small)]
    doc.build(els)
    return buf.getvalue()


RENDERERS = {"json": (render_json, "application/json"), "html": (render_html, "text/html"),
             "sarif": (render_sarif, "application/sarif+json"), "pdf": (render_pdf, "application/pdf")}


def generate_report(ctx: Ctx, job_id: int, fmt: str, user: str) -> dict:
    b = job_bundle(ctx.db, job_id)
    data = RENDERERS[fmt][0](b)
    path = ctx.settings.reports_dir / f"job{job_id}_{int(time.time() * 1000)}.{fmt}"
    path.write_bytes(data)
    rid = ctx.db.run("INSERT INTO reports(job_id,format,path,sha256,size,created_by,created_at) VALUES(?,?,?,?,?,?,?)",
                     (job_id, fmt, str(path), hashlib.sha256(data).hexdigest(), len(data), user, time.time()))
    return ctx.db.one("SELECT id,job_id,format,sha256,size,created_by,created_at FROM reports WHERE id=?", (rid,))


# ---------------------------------------------------------------- BEKO (local Ollama)
def sanitized_metadata(db: DB, job_id: int) -> dict:
    """Only aggregate rule metadata. No file paths, snippets, messages with values, or project names."""
    rows = db.all("""SELECT rule_id,severity,category,cwe,title,verification,COUNT(*) n FROM findings WHERE job_id=?
                     GROUP BY rule_id,severity,category,cwe,title,verification ORDER BY n DESC LIMIT 60""", (job_id,))
    return {"findings": [{"rule": r["rule_id"], "severity": r["severity"], "category": r["category"], "cwe": r["cwe"],
                          "title": r["title"], "verification": r["verification"], "count": r["n"]} for r in rows]}


def beko_status(ctx: Ctx) -> dict:
    url = ctx.db.get_setting("beko.url", ctx.settings.ollama_url).rstrip("/")
    model = ctx.db.get_setting("beko.model", ctx.settings.ollama_model)
    try:
        r = httpx.get(url + "/models", timeout=4.0)
        r.raise_for_status()
        ids = [m.get("id") for m in r.json().get("data", [])]
        return {"endpoint": url, "model": model, "reachable": True, "model_available": model in ids, "models": ids[:20]}
    except Exception as ex:
        return {"endpoint": url, "model": model, "reachable": False, "model_available": False, "error": type(ex).__name__}


def run_beko(ctx: Ctx, job_id: int, trigger: str) -> dict:
    db = ctx.db
    st = beko_status(ctx)
    now = time.time()
    if not st["reachable"] or not st["model_available"]:
        state = "unavailable" if not st["reachable"] else "model_missing"
        db.run("INSERT INTO ai_analyses(job_id,model,state,error,created_at) VALUES(?,?,?,?,?)", (job_id, st["model"], state, f"Ollama {state}", now))
        db.run("UPDATE scan_jobs SET beko_state=? WHERE id=?", (state, job_id))
        log_event(db, job_id, "beko", f"BEKO AI analysis {state}; scanner results are unaffected", "warning")
        return {"state": state}
    meta = sanitized_metadata(db, job_id)
    prompt = ("You are a security analyst. Below is sanitized scanner metadata (rule ids, severities, counts only; no code). "
              "Prioritise the issues, explain the likely risk of each category, and suggest remediation steps. "
              "State clearly that your analysis is unverified.\n" + json.dumps(meta))
    try:
        r = httpx.post(st["endpoint"] + "/chat/completions", timeout=180.0,
                       json={"model": st["model"], "messages": [{"role": "user", "content": prompt}], "temperature": 0.2, "stream": False})
        r.raise_for_status()
        content = r.json()["choices"][0]["message"]["content"]
        db.run("INSERT INTO ai_analyses(job_id,model,state,content,created_at) VALUES(?,?,?,?,?)", (job_id, st["model"], "ok", redact_line(content, 20000), now))
        db.run("UPDATE scan_jobs SET beko_state='done' WHERE id=?", (job_id,))
        log_event(db, job_id, "beko", "BEKO AI analysis finished (unverified)")
        return {"state": "ok"}
    except Exception as ex:
        db.run("INSERT INTO ai_analyses(job_id,model,state,error,created_at) VALUES(?,?,?,?,?)", (job_id, st["model"], "failed", type(ex).__name__, now))
        db.run("UPDATE scan_jobs SET beko_state='failed' WHERE id=?", (job_id,))
        log_event(db, job_id, "beko", f"BEKO AI analysis failed ({type(ex).__name__}); scanner results are unaffected", "warning")
        return {"state": "failed"}


# ---------------------------------------------------------------- notifications / n8n
def check_webhook_url(url: str, allow_external: bool) -> None:
    u = urlparse(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("webhook must be an http(s) URL")
    if allow_external:
        return
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or 80)
    except socket.gaierror as e:
        raise ValueError("webhook host does not resolve") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not (ip.is_loopback or ip.is_private):
            raise ValueError("webhook host must be loopback/private (external webhooks are disabled)")


def notify(ctx: Ctx, job_id: int) -> None:
    db = ctx.db
    cfg = db.get_setting("notifications", {})
    if not cfg.get("enabled") or not cfg.get("webhook_url"):
        return
    job = db.one("SELECT * FROM scan_jobs WHERE id=?", (job_id,))
    if cfg.get("only_on_findings") and json.loads(job["summary_json"]).get("total", 0) == 0:
        return
    proj = db.one("SELECT name FROM projects WHERE id=?", (job["project_id"],)) if job["project_id"] else None
    payload = {"event": "scan.finished", "job_id": job_id, "state": job["state"], "project": proj["name"] if proj else None,
               "risk_score": job["risk_score"], "counts": json.loads(job["summary_json"]).get("counts", {})}
    try:
        check_webhook_url(cfg["webhook_url"], ctx.settings.allow_external_webhooks)
        headers = {"X-UNITECH-Secret": cfg["secret"]} if cfg.get("secret") else {}
        httpx.post(cfg["webhook_url"], json=payload, headers=headers, timeout=8.0)
        audit.log(db, "system", "notify.sent", target=f"job:{job_id}")
    except Exception as ex:
        audit.log(db, "system", "notify.sent", target=f"job:{job_id}", outcome="error", detail={"error": type(ex).__name__})


# ---------------------------------------------------------------- scheduler / health
def next_run_for(interval: int | None, daily_at: str | None, now: float | None = None) -> float:
    now = now or time.time()
    if interval:
        return now + interval * 60
    hh, mm = (int(x) for x in (daily_at or "02:00").split(":"))
    dt = datetime.fromtimestamp(now)
    cand = dt.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if cand.timestamp() <= now:
        cand += timedelta(days=1)
    return cand.timestamp()


def scheduler_tick(ctx: Ctx) -> int:
    db = ctx.db
    fired = 0
    now = time.time()
    for s in db.all("SELECT * FROM schedules WHERE enabled=1 AND next_run IS NOT NULL AND next_run<=?", (now,)):
        proj = db.one("SELECT * FROM projects WHERE id=? AND active=1", (s["project_id"],))
        nxt = next_run_for(s["interval_minutes"], s["daily_at"], now)
        db.run("UPDATE schedules SET next_run=?, last_run=? WHERE id=?", (nxt, now, s["id"]))
        if not proj or not proj["agent_id"]:
            continue
        busy = db.one("SELECT id FROM scan_jobs WHERE schedule_id=? AND state IN ('queued','running')", (s["id"],))
        if busy:
            continue
        jid = create_job(ctx, user=f"schedule:{s['name']}", project=proj, adhoc_path=None, agent_id=proj["agent_id"], target_kind="project",
                         targets=[], engines=json.loads(s["engines_json"]), options=json.loads(s["options_json"]), schedule_id=s["id"])
        db.run("UPDATE schedules SET last_job_id=? WHERE id=?", (jid, s["id"]))
        audit.log(db, "system", "schedule.fire", target=f"schedule:{s['id']}", detail={"job": jid})
        fired += 1
    return fired


def health_tick(ctx: Ctx) -> int:
    """Fail running jobs whose agent stopped heartbeating."""
    cutoff = time.time() - ctx.settings.agent_lost_job_after_s
    n = 0
    for j in ctx.db.all("""SELECT j.* FROM scan_jobs j JOIN agents a ON a.id=j.agent_id WHERE j.state='running' AND (a.last_seen IS NULL OR a.last_seen<?)""", (cutoff,)):
        counts_state = "cancelled" if j["cancel_requested"] else "failed"
        ctx.db.run("UPDATE scan_jobs SET state=?, finished_at=?, error=? WHERE id=?", (counts_state, time.time(), "agent heartbeat lost", j["id"]))
        log_event(ctx.db, j["id"], "state", "agent heartbeat lost; job closed", "error")
        n += 1
    return n


def start_background(ctx: Ctx) -> threading.Thread:
    def loop():
        while not ctx.stop.wait(5):
            try:
                scheduler_tick(ctx)
                health_tick(ctx)
            except Exception:
                pass
    t = threading.Thread(target=loop, daemon=True, name="v3-scheduler")
    t.start()
    return t
