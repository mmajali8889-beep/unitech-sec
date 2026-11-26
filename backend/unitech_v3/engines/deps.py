"""Dependency hygiene analysis (offline, deterministic). NOT a CVE scanner - see registry for CVE adapters."""
from __future__ import annotations

import json
import re

from .base import RawFinding, ctx_hash
from ..redact import redact_line

FIX_PIN = "Pin an exact, reviewed version and commit the lockfile."


def _f(rid, sev, title, rel, ln, raw, fix, cwe="CWE-1104", ver="deterministic"):
    return RawFinding("deps", rid, "dependency", sev, title, rel, ln, redact_line(raw), fix, cwe, ver, 0, ctx_hash(raw))


def analyse(rel: str, name_l: str, text: str, lines: list[str]) -> list[RawFinding]:
    out: list[RawFinding] = []
    if re.fullmatch(r"requirements[\w.\-]*\.txt", name_l):
        for i, l in enumerate(lines, 1):
            s = l.strip()
            if not s or s.startswith(("#", "-r", "--hash", "-c")) or s.startswith("--"):
                if s.startswith("--index-url") or s.startswith("--extra-index-url") or s.startswith("--trusted-host"):
                    if s.startswith("--trusted-host") or "http://" in s:
                        out.append(_f("DEP004", "high", "Insecure package index (HTTP / trusted-host)", rel, i, l, "Use an HTTPS index.", "CWE-319"))
                continue
            if re.match(r"^(git\+|https?://|-e\s)", s):
                out.append(_f("DEP003", "medium", "Dependency installed from VCS/URL (unreviewed source)", rel, i, l, "Publish to an internal index or pin a commit hash.", "CWE-494"))
            elif "==" not in s:
                out.append(_f("DEP001", "low", "Dependency not pinned to an exact version", rel, i, l, FIX_PIN))
    elif name_l == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return out
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            for pkg, ver in (data.get(section) or {}).items():
                ln = next((i for i, l in enumerate(lines, 1) if f'"{pkg}"' in l), 1)
                raw = lines[ln - 1] if lines else ""
                v = str(ver)
                if v in ("*", "latest", "") or v.startswith(("http:", "git:", "git+http:")):
                    out.append(_f("DEP002", "medium", f"Unsafe version specifier for {pkg}", rel, ln, raw, FIX_PIN))
                elif v.startswith(("git+", "github:", "https:", "file:")):
                    out.append(_f("DEP003", "medium", f"{pkg} installed from VCS/URL", rel, ln, raw, "Pin a commit hash or use a registry package.", "CWE-494"))
        scripts = data.get("scripts") or {}
        for k in ("preinstall", "postinstall", "install"):
            if k in scripts and re.search(r"curl|wget|powershell|\|\s*(sh|bash)", str(scripts[k]), re.I):
                ln = next((i for i, l in enumerate(lines, 1) if f'"{k}"' in l), 1)
                out.append(_f("DEP005", "high", f"npm {k} script downloads/executes remote code", rel, ln, lines[ln - 1], "Remove network-executing lifecycle scripts.", "CWE-829"))
    elif name_l in ("pipfile", "pyproject.toml", "go.mod", "pom.xml", "composer.json"):
        pass
    return out
