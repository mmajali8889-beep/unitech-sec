from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from unitech_v3.engines import external


@dataclass
class AgentConfig:
    server_url: str
    token: str
    name: str
    approved_roots: list[Path]
    max_concurrent: int = 1
    poll_interval_s: float = 1.0
    heartbeat_s: float = 10.0
    job_memory_mb: int = 1024
    job_timeout_cap_s: int = 3600
    external_engines: dict = field(default_factory=dict)
    verify_tls: bool = True
    log_file: str | None = None


def load(path: str | Path) -> AgentConfig:
    d = json.loads(Path(path).read_text(encoding="utf-8"))
    roots = [Path(p) for p in d["approved_roots"]]
    if not roots:
        raise ValueError("approved_roots must not be empty")
    url = d["server_url"].rstrip("/")
    if not (url.startswith("http://127.0.0.1") or url.startswith("http://localhost") or url.startswith("https://127.0.0.1") or url.startswith("https://localhost")):
        raise ValueError("server_url must be a loopback address")
    for eid, cfg in (d.get("external_engines") or {}).items():
        external.validate_template(cfg["argv"])     # rejects --fix etc. at startup
    return AgentConfig(server_url=url, token=d["token"], name=d.get("name", "agent"), approved_roots=roots,
                       external_engines=d.get("external_engines") or {}, job_memory_mb=int(d.get("job_memory_mb", 1024)),
                       job_timeout_cap_s=int(d.get("job_timeout_cap_s", 3600)), log_file=d.get("log_file"))
