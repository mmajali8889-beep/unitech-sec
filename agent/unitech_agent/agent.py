"""Restricted local scanning agent. Pulls jobs from the control plane; it never accepts inbound connections,
never executes shell commands from the network and never opens scanned files for writing."""
from __future__ import annotations

import logging
import os
import platform
import threading
import time
from pathlib import Path

import httpx

from unitech_v3 import __version__
from unitech_v3.engines import external
from unitech_v3.engines.base import Limits
from unitech_v3.engines.scanner import NATIVE
from unitech_v3.pathguard import PathDenied, is_link_like, validate_under_roots
from unitech_v3.redact import redact_line

from .config import AgentConfig
from .worker import ScanProcess

log = logging.getLogger("unitech.agent")
PROJECT_MARKERS = {".git", "package.json", "requirements.txt", "pyproject.toml", "Dockerfile", "docker-compose.yml", "pom.xml", "go.mod", "composer.json"}
MARKER_KIND = {"package.json": "node", "requirements.txt": "python", "pyproject.toml": "python", "Dockerfile": "docker", "pom.xml": "java", "go.mod": "go", "composer.json": "php"}


class SanitizingFilter(logging.Filter):
    def filter(self, record):
        record.msg = redact_line(str(record.getMessage()), 500)
        record.args = ()
        return True


class Agent:
    def __init__(self, cfg: AgentConfig, client=None):
        self.cfg = cfg
        self.client = client or httpx.Client(base_url=cfg.server_url, timeout=30, verify=cfg.verify_tls,
                                             headers={"Authorization": f"Bearer {cfg.token}"})
        self.stop = threading.Event()
        self.active_job: int | None = None
        self.cancel_ids: set[int] = set()
        self._lock = threading.Lock()
        log.addFilter(SanitizingFilter())

    # ---------------------------------------------------------- transport
    def _post(self, path, json=None):
        r = self.client.post(path, json=json or {})
        r.raise_for_status()
        return r.json()

    def _get(self, path):
        r = self.client.get(path)
        r.raise_for_status()
        return r.json()

    # ---------------------------------------------------------- heartbeat
    def external_available(self) -> list[str]:
        return [eid for eid, c in self.cfg.external_engines.items() if external.available(c)[0]]

    def heartbeat(self) -> dict:
        status = {"active_job": self.active_job, "platform": platform.system(), "python": platform.python_version()}
        try:
            status["load"] = round(os.getloadavg()[0], 2)
        except (AttributeError, OSError):
            pass
        res = self._post("/api/agent/heartbeat", {
            "hostname": platform.node()[:100], "version": __version__,
            "roots": [{"name": str(r)} for r in self.cfg.approved_roots], "engines": self.external_available(), "status": status})
        with self._lock:
            self.cancel_ids = set(res.get("cancel_job_ids", []))
        return res

    # ---------------------------------------------------------- RPC (browse / validate / discover)
    def handle_rpc(self, rpc: dict) -> dict:
        kind, p = rpc["kind"], rpc["params"]
        try:
            if kind == "browse":
                return {"ok": True, "result": self.browse(p.get("path", ""))}
            if kind == "validate_path":
                path = validate_under_roots(p["path"], self.cfg.approved_roots)
                if p.get("must_be_dir") and not path.is_dir():
                    return {"ok": False, "error": "path is not a directory", "denied": True}
                if not path.exists():
                    return {"ok": False, "error": "path does not exist", "denied": True}
                return {"ok": True, "result": {"canonical": str(path), "is_file": path.is_file()}}
            if kind == "discover":
                return {"ok": True, "result": self.discover(p.get("path", ""))}
            return {"ok": False, "error": "unsupported request", "denied": True}
        except PathDenied as e:
            return {"ok": False, "error": str(e), "denied": True}
        except OSError as e:
            return {"ok": False, "error": f"filesystem error: {type(e).__name__}", "denied": True}

    def browse(self, raw: str) -> dict:
        if not raw:
            return {"path": "", "entries": [{"name": str(r), "path": str(r), "type": "dir"} for r in self.cfg.approved_roots], "roots": True}
        d = validate_under_roots(raw, self.cfg.approved_roots)
        if not d.is_dir():
            raise PathDenied("not a directory")
        entries = []
        for e in sorted(os.scandir(d), key=lambda x: (not x.is_dir(follow_symlinks=False), x.name.lower()))[:500]:
            p = Path(e.path)
            if is_link_like(p):
                continue                                  # links/junctions are never listed
            entries.append({"name": e.name, "path": str(p), "type": "dir" if e.is_dir(follow_symlinks=False) else "file",
                            "size": e.stat(follow_symlinks=False).st_size if e.is_file(follow_symlinks=False) else None})
        parent = str(d.parent) if any(str(d) != str(Path(os.path.realpath(r))) for r in self.cfg.approved_roots) and any(
            str(d.parent).startswith(str(Path(os.path.realpath(r)))) for r in self.cfg.approved_roots) else ""
        return {"path": str(d), "parent": parent, "entries": entries, "roots": False}

    def discover(self, raw: str, max_depth: int = 3) -> dict:
        starts = [validate_under_roots(raw, self.cfg.approved_roots)] if raw else [Path(os.path.realpath(r)) for r in self.cfg.approved_roots]
        found = []
        for s in starts:
            stack = [(s, 0)]
            while stack and len(found) < 200:
                d, depth = stack.pop()
                try:
                    names = {e.name for e in os.scandir(d)}
                except OSError:
                    continue
                marks = sorted(names & PROJECT_MARKERS)
                if marks:
                    kind = next((MARKER_KIND[m] for m in marks if m in MARKER_KIND), "generic")
                    found.append({"path": str(d), "name": d.name, "kind": kind, "markers": marks})
                    continue
                if depth < max_depth:
                    for e in os.scandir(d):
                        p = Path(e.path)
                        if e.is_dir(follow_symlinks=False) and not is_link_like(p) and e.name.lower() not in ("node_modules", ".git", "__pycache__", "venv", ".venv"):
                            stack.append((p, depth + 1))
        return {"candidates": found}

    # ---------------------------------------------------------- job execution
    def run_job(self, job: dict) -> None:
        jid = job["id"]
        self.active_job = jid
        events: list[dict] = []
        try:
            try:
                root = validate_under_roots(job["root"], self.cfg.approved_roots)       # defence in depth: agent re-validates
            except PathDenied as e:
                self._post(f"/api/agent/jobs/{jid}/complete", {"outcome": "failed", "error": f"path not approved: {e}"})
                return
            if root.is_file():
                targets, scan_root = [root.name], root.parent
            else:
                targets, scan_root = job["targets"], root
            engines = job["engines"]
            for e in engines:
                if e not in NATIVE and e not in self.cfg.external_engines:
                    self._post(f"/api/agent/jobs/{jid}/complete", {"outcome": "failed", "error": f"engine not permitted on agent: {e}"})
                    return
            o = job.get("options", {})
            limits = Limits(timeout_s=min(int(o.get("timeout_s", 600)), self.cfg.job_timeout_cap_s), max_files=int(o.get("max_files", 20000)))
            self._post(f"/api/agent/jobs/{jid}/events", {"events": [{"kind": "start", "message": f"scanning {len(engines)} engines (read-only)"}]})
            proc = ScanProcess(scan_root, targets, engines, limits.__dict__.copy(), self.cfg.external_engines, self.cfg.job_memory_mb)
            proc.start()
            last_hb = last_ev = 0.0
            progress = 0.0
            result, error, cancelled = None, None, False
            while True:
                for msg in proc.poll():
                    if msg[0] == "progress":
                        progress = msg[1]
                        events.append({"kind": "progress", "message": msg[2], "data": {"progress": round(msg[1], 3)}})
                    elif msg[0] == "result":
                        result = msg[1]
                    elif msg[0] == "error":
                        error = msg[1]
                now = time.monotonic()
                if now - last_hb > 2:
                    last_hb = now
                    try:
                        self.heartbeat()
                    except httpx.HTTPError:
                        pass
                    if jid in self.cancel_ids:
                        cancelled = True
                if now - last_ev > 1.0 and events:
                    last_ev = now
                    try:
                        r = self._post(f"/api/agent/jobs/{jid}/events", {"progress": progress, "events": events[-20:]})
                        events.clear()
                        cancelled = cancelled or r.get("cancel", False)
                    except httpx.HTTPError:
                        pass
                if cancelled:
                    proc.kill()
                    self._post(f"/api/agent/jobs/{jid}/complete", {"outcome": "cancelled"})
                    return
                if time.monotonic() > proc.deadline:
                    proc.kill()
                    error = "timeout"
                if result is not None or error is not None:
                    break
                if not proc.alive():
                    for msg in proc.poll():
                        if msg[0] == "result":
                            result = msg[1]
                        elif msg[0] == "error":
                            error = msg[1]
                    if result is None and error is None:
                        error = f"scan process exited unexpectedly (code {proc.p.exitcode})"
                    break
                time.sleep(0.1)
            proc.kill()
            if result is None:
                self._post(f"/api/agent/jobs/{jid}/complete", {"outcome": "failed", "error": error})
                return
            fs = result["findings"]
            for i in range(0, len(fs), 500):
                self._post(f"/api/agent/jobs/{jid}/findings", {"findings": fs[i:i + 500]})
            self._post(f"/api/agent/jobs/{jid}/events", {"progress": 0.95, "events": [{"kind": "persist", "message": f"{len(fs)} findings persisted"}]})
            self._post(f"/api/agent/jobs/{jid}/complete", {"outcome": "completed", "engine_status": result["engine_status"],
                                                           "files_scanned": result["files_scanned"], "notes": result["notes"]})
        except Exception as ex:
            log.error("job %s failed: %s", jid, ex)
            try:
                self._post(f"/api/agent/jobs/{jid}/complete", {"outcome": "failed", "error": f"agent error: {type(ex).__name__}"})
            except Exception:
                pass
        finally:
            self.active_job = None

    # ---------------------------------------------------------- main loops
    def _rpc_loop(self):
        while not self.stop.is_set():
            try:
                r = self._get("/api/agent/rpc/claim")["rpc"]
                if r:
                    self._post(f"/api/agent/rpc/{r['id']}/result", self.handle_rpc(r))
                    continue
            except httpx.HTTPError:
                pass
            self.stop.wait(0.3)

    def _hb_loop(self):
        while not self.stop.is_set():
            wait = self.cfg.heartbeat_s
            try:
                self.heartbeat()
            except httpx.HTTPError as e:
                log.warning("heartbeat failed: %s", type(e).__name__)
                wait = min(wait, 1.5)          # reconnect quickly after an outage / server restart
            self.stop.wait(wait)

    def run_forever(self):
        threading.Thread(target=self._hb_loop, daemon=True).start()
        threading.Thread(target=self._rpc_loop, daemon=True).start()
        while not self.stop.is_set():
            try:
                job = self._post("/api/agent/claim")["job"]
                if job:
                    self.run_job(job)
                    continue
            except httpx.HTTPError as e:
                log.warning("claim failed: %s", type(e).__name__)
            self.stop.wait(self.cfg.poll_interval_s)
