"""Read-only scan driver. Walks a validated root, never follows links, never executes anything."""
from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Callable

from . import deps as deps_mod
from . import external as ext_mod
from . import taint as taint_mod
from .base import Cancelled, Limits, RawFinding, ScanFile, Timeout, ctx_hash
from .rules import BY_ENGINE
from ..pathguard import PathDenied, is_link_like, safe_join
from ..redact import redact_line

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".tox", "dist", "build", ".next",
             ".idea", ".vscode", "bin", "obj", "target", ".mypy_cache", ".pytest_cache", "site-packages", ".svn", ".hg"}
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".7z", ".exe", ".dll", ".so", ".pyc",
             ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".svg", ".lock", ".map", ".min.js", ".db", ".sqlite", ".bin", ".whl"}
NATIVE = {"secrets", "source", "config", "docker", "authz", "taint", "deps"}


def _name_norm(name_l: str) -> str:
    if name_l.startswith("dockerfile"):
        return "dockerfile"
    if re.match(r"(docker-)?compose[.\w-]*\.ya?ml$", name_l):
        return "docker-compose.yml" if name_l.startswith("docker-") else "compose.yml"
    return name_l


def collect_files(root: Path, targets: list[str], limits: Limits, check: Callable[[], None]) -> tuple[list[Path], list[str]]:
    notes: list[str] = []
    files: list[Path] = []
    total = 0
    starts: list[Path] = []
    if targets:
        for t in targets:
            starts.append(safe_join(root, t))   # raises PathDenied on traversal / link escape
    else:
        starts.append(root)
    for start in starts:
        if is_link_like(start):
            notes.append(f"skipped link: {start.name}")
            continue
        if start.is_file():
            files.append(start)
            continue
        for dirpath, dirnames, filenames in os.walk(start, followlinks=False):
            check()
            keep = []
            for d in dirnames:
                p = Path(dirpath, d)
                if d.lower() in SKIP_DIRS:
                    continue
                if is_link_like(p):
                    notes.append(f"skipped link/junction: {os.path.relpath(p, root)}")
                    continue
                keep.append(d)
            dirnames[:] = keep
            for f in filenames:
                p = Path(dirpath, f)
                if is_link_like(p):
                    notes.append(f"skipped link: {os.path.relpath(p, root)}")
                    continue
                if p.suffix.lower() in SKIP_EXTS:
                    continue
                try:
                    sz = p.stat().st_size
                except OSError:
                    continue
                if sz > limits.max_file_bytes:
                    notes.append(f"skipped large file (> {limits.max_file_bytes} bytes): {os.path.relpath(p, root)}")
                    continue
                total += sz
                if len(files) >= limits.max_files or total > limits.max_total_bytes:
                    notes.append("limit reached: file/byte quota - scan truncated")
                    return files, notes
                files.append(p)
    return files, notes


def read_file(p: Path, root: Path) -> ScanFile | None:
    try:
        with open(p, "rb") as fh:                      # read-only
            data = fh.read()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    text = data.decode("utf-8", "replace")
    name_l = p.name.lower()
    ext = p.suffix.lower()
    if name_l.startswith(".env"):
        ext = ".env"
    rel = os.path.relpath(p, root).replace("\\", "/")
    return ScanFile(rel, _name_norm(name_l), ext, text, text.splitlines())


def _rule_findings(sf: ScanFile, engine: str, cap: int) -> list[RawFinding]:
    out: list[RawFinding] = []
    for r in BY_ENGINE.get(engine, []):
        if not r.applies(sf.name_l, sf.ext):
            continue
        if r.id == "CFG009":
            out.append(RawFinding(engine, r.id, r.category, r.severity, r.title, sf.rel, 1, "<sensitive file>", r.remediation, r.cwe, "deterministic", 0, ctx_hash(sf.rel)))
            continue
        if r.flags & re.S:
            for m in r._re.finditer(sf.text):
                ln = sf.text.count("\n", 0, m.start()) + 1
                raw = sf.lines[ln - 1] if ln <= len(sf.lines) else ""
                out.append(RawFinding(engine, r.id, r.category, r.severity, r.title, sf.rel, ln, redact_line(raw), r.remediation, r.cwe, r.verification, 0, ctx_hash(raw)))
                break
            continue
        for i, line in enumerate(sf.lines, 1):
            if len(line) > 2000:
                continue
            m = r._re.search(line)
            if not m or (r._un and r._un.search(line)):
                continue
            out.append(RawFinding(engine, r.id, r.category, r.severity, r.title, sf.rel, i, redact_line(line), r.remediation, r.cwe, r.verification, m.start(), ctx_hash(line)))
            if len(out) >= cap:
                return out
    if engine == "docker" and sf.name_l == "dockerfile" and not re.search(r"^\s*HEALTHCHECK\b", sf.text, re.M | re.I):
        out.append(RawFinding(engine, "DKR012", "docker", "low", "No HEALTHCHECK instruction", sf.rel, 1, "<file>", "Add a HEALTHCHECK instruction.", "", "deterministic", 0, ctx_hash(sf.rel + "hc")))
    return out


def scan(root: Path, targets: list[str], engines: list[str], limits: Limits, cancel_check: Callable[[], bool],
         progress: Callable[[float, str], None] | None = None, external_cfg: dict | None = None) -> dict:
    """Returns {findings, engine_status, files_scanned, notes}. Raises Cancelled/Timeout."""
    t0 = time.monotonic()

    def check():
        if cancel_check():
            raise Cancelled()
        if time.monotonic() - t0 > limits.timeout_s:
            raise Timeout()

    external_cfg = external_cfg or {}
    status: dict[str, dict] = {e: {"state": "ok", "findings": 0} for e in engines}
    findings: list[RawFinding] = []
    native = [e for e in engines if e in NATIVE]
    ext = [e for e in engines if e not in NATIVE]
    files, notes = collect_files(root, targets, limits, check)
    n = len(files)
    if progress:
        progress(0.02, f"discovered {n} files")
    per_engine: dict[str, int] = {e: 0 for e in engines}
    scanned = 0
    for idx, p in enumerate(files):
        check()
        sf = read_file(p, root)
        if sf is None:
            continue
        scanned += 1
        for e in native:
            if status[e]["state"] == "failed" or per_engine[e] >= limits.max_findings_per_engine:
                continue
            try:
                if e == "taint":
                    fs = taint_mod.analyse_python(sf.rel, sf.text, sf.lines) if sf.ext == ".py" else []
                elif e == "deps":
                    fs = deps_mod.analyse(sf.rel, sf.name_l, sf.text, sf.lines)
                else:
                    fs = _rule_findings(sf, e, limits.max_findings_per_engine)
            except (Cancelled, Timeout):
                raise
            except Exception as ex:  # an engine bug must not discard other engines' results
                status[e] = {"state": "failed", "error": f"{type(ex).__name__}: {ex}"[:300], "findings": per_engine[e]}
                continue
            per_engine[e] += len(fs)
            findings.extend(fs)
        if progress and (idx % 25 == 0 or idx == n - 1):
            progress(0.05 + 0.80 * ((idx + 1) / max(n, 1)), f"scanned {idx + 1}/{n} files")
    for e in ext:
        check()
        cfg = external_cfg.get(e)
        if not cfg:
            status[e] = {"state": "failed", "error": "engine not configured on this agent", "findings": 0}
            continue
        ok, why = ext_mod.available(cfg)
        if not ok:
            status[e] = {"state": "failed", "error": why, "findings": 0}
            continue
        try:
            remaining = max(1, int(limits.timeout_s - (time.monotonic() - t0)))
            fs = ext_mod.run(cfg, e, root if not targets else safe_join(root, targets[0]), root, remaining, cancel_check)
            per_engine[e] = len(fs)
            findings.extend(fs)
        except (Cancelled, Timeout):
            raise
        except Exception as ex:
            status[e] = {"state": "failed", "error": f"{type(ex).__name__}: {ex}"[:300], "findings": 0}
    for e in engines:
        if status[e]["state"] == "ok":
            status[e]["findings"] = per_engine[e]
    # de-duplicate identical (engine, rule, file, line)
    seen, uniq = set(), []
    for f in findings:
        k = (f.engine, f.rule_id, f.file, f.line)
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    if progress:
        progress(0.9, "normalising findings")
    return {"findings": uniq, "engine_status": status, "files_scanned": scanned, "notes": notes[:50]}
