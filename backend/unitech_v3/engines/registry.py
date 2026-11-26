"""Unified security engine registry: capabilities, parameters, outputs, limitations."""
from __future__ import annotations

import shutil

from .rules import BY_ENGINE

NATIVE_META = {
    "secrets": dict(name="Secrets Detection", category="secrets", targets=["file", "directory", "project"],
                    limitations=["Pattern based; may miss obfuscated or split secrets", "Values are always redacted in output"]),
    "source": dict(name="Source Code Analysis", category="source", targets=["file", "directory", "project"],
                   limitations=["Line-oriented regex rules; no inter-procedural analysis", "Languages: Python, JS/TS, PHP, Ruby, Java, C#, Go, shell"]),
    "config": dict(name="Configuration Security", category="config", targets=["file", "directory", "project"],
                   limitations=["JSON/YAML/INI/TOML/.env/XML configs; no schema awareness"]),
    "docker": dict(name="Docker Configuration", category="docker", targets=["file", "directory", "project"],
                   limitations=["Static Dockerfile / Compose analysis only; never talks to the Docker daemon or socket"]),
    "authz": dict(name="Authentication & Authorization", category="authz", targets=["file", "directory", "project"],
                  limitations=["Heuristic patterns; does not prove missing authorisation on routes"]),
    "taint": dict(name="Taint Tracking (Python)", category="taint", targets=["file", "directory", "project"],
                  limitations=["Python only (AST based)", "Intra-procedural: data flow across function calls is not followed", "Findings are deterministic paths from source to sink"]),
    "deps": dict(name="Dependency Hygiene", category="dependency", targets=["directory", "project"],
                 limitations=["Offline manifest hygiene (pinning, untrusted sources). NOT a CVE scanner"]),
}

PLANNED = [
    dict(id="pip-audit", name="pip-audit (Python CVE scan)", binary="pip-audit", category="dependency",
         reason="CVE scanners are enabled only after installation and compatibility are verified; they also need network access to a vulnerability database."),
    dict(id="osv-scanner", name="OSV-Scanner (multi-ecosystem CVE scan)", binary="osv-scanner", category="dependency",
         reason="Same as pip-audit; requires explicit installation approval."),
    dict(id="npm-audit", name="npm audit (JavaScript CVE scan)", binary="npm", category="dependency",
         reason="Needs a lockfile and registry access; disabled until compatibility is verified."),
]

LEGACY = [
    dict(id="vibesec", name="VibeSec scanner (legacy V2)", kind="external",
         note="Integrated through the fixed-template external adapter (read-only, --fix is rejected). Becomes available when an administrator defines its argv template in the Windows agent config; the V2 source was not present in the build environment so the CLI contract is unverified."),
    dict(id="beko", name="BEKO Security Analyzer (AI)", kind="ai",
         note="AI layer, separate from deterministic scanning. Uses local Ollama; see /api/beko/status."),
    dict(id="multi-project-audit", name="Multi-Project Audit (legacy V2)", kind="planned",
         note="Superseded by native multi-project scan jobs; legacy script not imported (source unavailable at build time)."),
    dict(id="report-normalizer", name="Report normalizer (legacy V2)", kind="planned",
         note="Superseded by native finding normalisation and SARIF importer (engines/external.parse_sarif)."),
    dict(id="importer", name="Importer (legacy V2)", kind="planned", note="V2 PostgreSQL data is never touched; V3 uses its own database."),
]

CLASSIFICATION = {
    "scanners": ["secrets", "source", "config", "docker", "authz", "taint", "deps", "vibesec (external)"],
    "report_processors": ["report-normalizer", "importer"],
    "monitoring_tools": [],
    "administrative_operations": [],
    "deployment_tools": [],
}


def describe(external_ids: dict[str, dict] | None = None, disabled: set[str] | None = None, agent_ext: set[str] | None = None) -> list[dict]:
    disabled = disabled or set()
    agent_ext = agent_ext or set()
    out = []
    for eid, meta in NATIVE_META.items():
        out.append(dict(id=eid, kind="native", deterministic=True, available=True, enabled=eid not in disabled,
                        rules=[dict(id=r.id, severity=r.severity, title=r.title, cwe=r.cwe) for r in BY_ENGINE.get(eid, [])]
                        if eid in BY_ENGINE else ([dict(id=i, severity="critical", title=t, cwe=c) for i, t, c in _TAINT_RULES] if eid == "taint" else
                                                  [dict(id=i, severity="low", title=t, cwe="CWE-1104") for i, t in _DEP_RULES]),
                        outputs=["json", "html", "sarif", "pdf"], exit_codes={"0": "scan completed"}, parameters=["targets", "limits"], **meta))
    ext_cfg = next((e for e in LEGACY if e["id"] == "vibesec"), {})
    out.append(dict(id="vibesec", name=ext_cfg["name"], kind="external", deterministic=True, category="source",
                    available="vibesec" in agent_ext, enabled="vibesec" not in disabled, targets=["file", "directory", "project"],
                    rules=[], outputs=["sarif"], exit_codes={"0": "no findings", "1": "findings"}, parameters=["{target}", "{output}"],
                    limitations=[ext_cfg["note"]]))
    for p in PLANNED:
        installed = shutil.which(p["binary"]) is not None
        out.append(dict(id=p["id"], name=p["name"], kind="planned", deterministic=True, category=p["category"], available=False,
                        enabled=False, targets=["project"], rules=[], outputs=[], exit_codes={}, parameters=[],
                        limitations=[p["reason"], f"Binary detected on API host: {installed} (agent host may differ)"]))
    return out


_TAINT_RULES = [("TNT001", "Tainted data reaches eval/exec", "CWE-95"), ("TNT002", "Tainted data reaches shell/subprocess", "CWE-78"),
                ("TNT003", "Tainted deserialisation", "CWE-502"), ("TNT004", "Tainted file path", "CWE-22"),
                ("TNT005", "Tainted template string", "CWE-1336"), ("TNT006", "Tainted SSRF URL", "CWE-918"),
                ("TNT007", "Tainted redirect", "CWE-601"), ("TNT008", "Tainted SQL query", "CWE-89")]
_DEP_RULES = [("DEP001", "Unpinned dependency"), ("DEP002", "Unsafe version specifier"), ("DEP003", "Dependency from VCS/URL"),
              ("DEP004", "Insecure package index"), ("DEP005", "Network-executing install script")]
