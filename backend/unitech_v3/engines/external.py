"""Fixed-template external engine adapter (e.g. VibeSec). Templates are configured by an
administrator in the agent config file - never supplied by the browser or API clients."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .base import RawFinding, ctx_hash, Cancelled, Timeout
from ..redact import redact_line

ALLOWED_PLACEHOLDERS = {"{target}", "{output}"}
FORBIDDEN_FLAGS = {"--fix", "--autofix", "--apply", "--write", "--in-place", "--remediate", "-fix"}
_SEV = {"error": "high", "warning": "medium", "note": "low", "none": "info",
        "critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}


def validate_template(argv: list[str]) -> None:
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv template must be a non-empty list of strings")
    for a in argv:
        if a.lower() in FORBIDDEN_FLAGS or any(a.lower().startswith(f + "=") for f in FORBIDDEN_FLAGS):
            raise ValueError(f"forbidden flag in template: {a}")
        if "{" in a and not any(p in a for p in ALLOWED_PLACEHOLDERS):
            raise ValueError(f"unknown placeholder in template: {a}")
    if not any("{target}" in a for a in argv):
        raise ValueError("template must contain {target}")


def available(cfg: dict) -> tuple[bool, str]:
    try:
        validate_template(cfg["argv"])
    except (KeyError, ValueError) as e:
        return False, str(e)
    exe = cfg["argv"][0]
    if not (shutil.which(exe) or Path(exe).exists()):
        return False, f"executable not found: {exe}"
    return True, "ok"


def run(cfg: dict, engine_id: str, target: Path, rel_root: Path, timeout_s: int, cancel_check) -> list[RawFinding]:
    validate_template(cfg["argv"])
    with tempfile.TemporaryDirectory(prefix="v3ext_") as tmp:
        out = Path(tmp) / "result.json"
        argv = [a.replace("{target}", str(target)).replace("{output}", str(out)) for a in cfg["argv"]]
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "LANG", "PYTHONIOENCODING")}
        p = subprocess.Popen(argv, cwd=tmp, env=env, shell=False, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        import time
        deadline = time.monotonic() + timeout_s
        while p.poll() is None:
            if cancel_check():
                p.kill(); p.wait(); raise Cancelled()
            if time.monotonic() > deadline:
                p.kill(); p.wait(); raise Timeout()
            time.sleep(0.05)
        ok_codes = set(cfg.get("ok_exit_codes", [0, 1]))
        if p.returncode not in ok_codes:
            raise RuntimeError(f"{engine_id} exited with code {p.returncode}")
        raw = out.read_text(encoding="utf-8") if out.exists() else (p.stdout.read().decode("utf-8", "replace") if p.stdout else "")
        return parse_sarif(engine_id, raw, target, rel_root)


def parse_sarif(engine_id: str, raw: str, target: Path, rel_root: Path) -> list[RawFinding]:
    data = json.loads(raw)
    found: list[RawFinding] = []
    for run_ in data.get("runs", []):
        for r in run_.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 0) or 0
            p = Path(uri.replace("file://", ""))
            try:
                rel = str(p.resolve().relative_to(rel_root.resolve())) if p.is_absolute() else str(p)
            except ValueError:
                rel = p.name
            snippet = loc.get("region", {}).get("snippet", {}).get("text", "")
            msg = (r.get("message") or {}).get("text", "") if isinstance(r.get("message"), dict) else str(r.get("message", ""))
            found.append(RawFinding(engine_id, str(r.get("ruleId", "EXT")), "source", _SEV.get(str(r.get("level", "warning")).lower(), "medium"),
                                    redact_line(msg, 160) or "External finding", rel.replace("\\", "/"), int(line), redact_line(snippet),
                                    "See external engine documentation for remediation.", "", "heuristic", 0, ctx_hash(snippet or msg)))
    return found


# ---------------------------------------------------------------- pip-audit (CVE) - fixed argv, opt-in
PIP_AUDIT_ARGV = ["pip-audit", "--no-deps", "--disable-pip", "-f", "json", "-r"]


def pip_audit_available() -> bool:
    return shutil.which("pip-audit") is not None


def parse_pip_audit(raw: str, rel: str, lines: list[str]) -> list[RawFinding]:
    out: list[RawFinding] = []
    data = json.loads(raw)
    for dep in data.get("dependencies", []):
        name = dep.get("name", "")
        ln = next((i for i, l in enumerate(lines, 1) if l.strip().lower().startswith(name.lower())), 1)
        raw_line = lines[ln - 1] if lines else name
        for v in dep.get("vulns", []):
            ids = [v.get("id", "")] + list(v.get("aliases", []))
            cve = next((i for i in ids if i.startswith("CVE-")), ids[0] if ids else "VULN")
            fixes = ", ".join(v.get("fix_versions") or []) or "no fixed version published"
            out.append(RawFinding("pip-audit", cve, "dependency", "high", f"{name} {dep.get('version')}: known vulnerability {cve}",
                                  rel, ln, redact_line(raw_line), f"Upgrade to a fixed version ({fixes}).", "", "deterministic", 0,
                                  ctx_hash(f"{name}{dep.get('version')}{cve}")))
    return out


def run_pip_audit(req_file: Path, rel: str, timeout_s: int, cancel_check) -> list[RawFinding]:
    import time
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "SYSTEMROOT", "TEMP", "TMP", "HOME", "LANG", "HTTPS_PROXY", "HTTP_PROXY", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE")}
    p = subprocess.Popen([*PIP_AUDIT_ARGV, str(req_file)], env=env, shell=False, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    end = time.monotonic() + timeout_s
    while p.poll() is None:
        if cancel_check():
            p.kill(); p.wait(); raise Cancelled()
        if time.monotonic() > end:
            p.kill(); p.wait(); raise Timeout()
        time.sleep(0.05)
    stdout = p.stdout.read().decode("utf-8", "replace") if p.stdout else ""
    if p.returncode not in (0, 1) or not stdout.strip().startswith("{"):
        err = (p.stderr.read().decode("utf-8", "replace") if p.stderr else "")[-200:]
        raise RuntimeError(f"pip-audit failed (code {p.returncode}): {redact_line(err, 200)}")
    lines = req_file.read_text(encoding="utf-8", errors="replace").splitlines()
    return parse_pip_audit(stdout, rel, lines)
