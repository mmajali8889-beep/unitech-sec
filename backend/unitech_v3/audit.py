"""Tamper-evident audit log (hash chain). Never logs secrets."""
from __future__ import annotations

import hashlib
import json
import threading
import time

from .db import DB
from .redact import redact_text

_lock = threading.Lock()


def _digest(prev: str, row: dict) -> str:
    return hashlib.sha256((prev + json.dumps(row, sort_keys=True)).encode()).hexdigest()


def log(db: DB, actor: str, action: str, *, role: str | None = None, target: str | None = None,
        ip: str | None = None, outcome: str = "ok", detail: dict | None = None) -> None:
    safe = json.loads(redact_text(json.dumps(detail or {})))
    with _lock, db.tx() as c:
        last = c.execute("SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1").fetchone()
        prev = last[0] if last else "0" * 64
        ts = time.time()
        row = {"ts": ts, "actor": actor, "role": role, "action": action, "target": target, "ip": ip,
               "outcome": outcome, "detail": safe}
        c.execute("INSERT INTO audit_logs(ts,actor,role,action,target,ip,outcome,detail_json,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (ts, actor, role, action, target, ip, outcome, json.dumps(safe), prev, _digest(prev, row)))


def verify_chain(db: DB) -> dict:
    prev = "0" * 64
    n = 0
    for r in db.all("SELECT * FROM audit_logs ORDER BY id"):
        row = {"ts": r["ts"], "actor": r["actor"], "role": r["role"], "action": r["action"], "target": r["target"],
               "ip": r["ip"], "outcome": r["outcome"], "detail": json.loads(r["detail_json"])}
        if r["prev_hash"] != prev or _digest(prev, row) != r["hash"]:
            return {"valid": False, "broken_at": r["id"], "checked": n}
        prev = r["hash"]
        n += 1
    return {"valid": True, "checked": n}
