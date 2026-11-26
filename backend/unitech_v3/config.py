"""Runtime settings. Everything is local-only by default."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(f"UNITECH_V3_{name}", default)


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "./data")).resolve())
    host: str = field(default_factory=lambda: _env("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("PORT", "8787")))
    allow_non_loopback: bool = field(default_factory=lambda: _env("ALLOW_NON_LOOPBACK", "0") == "1")
    token_ttl_minutes: int = field(default_factory=lambda: int(_env("TOKEN_TTL_MIN", "60")))
    rate_limit_per_minute: int = field(default_factory=lambda: int(_env("RATE_LIMIT", "240")))
    login_limit_per_minute: int = field(default_factory=lambda: int(_env("LOGIN_LIMIT", "10")))
    lockout_threshold: int = 5
    lockout_minutes: int = 5
    ollama_url: str = field(default_factory=lambda: _env("OLLAMA_URL", "http://127.0.0.1:11434/v1"))
    ollama_model: str = field(default_factory=lambda: _env("OLLAMA_MODEL", "glm-4.7-flash:q4_K_M"))
    frontend_dist: Path = field(default_factory=lambda: Path(_env("FRONTEND_DIST", "../frontend/dist")).resolve())
    start_scheduler: bool = True
    agent_offline_after_s: int = 45
    agent_lost_job_after_s: int = 120
    allow_external_webhooks: bool = False

    @property
    def db_path(self) -> Path:
        return self.data_dir / "unitech_v3.db"

    @property
    def secret_path(self) -> Path:
        return self.data_dir / "jwt.secret"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        if not self.allow_non_loopback and self.host not in ("127.0.0.1", "::1", "localhost"):
            raise RuntimeError(
                "Refusing to bind to a non-loopback address. V3 must not be exposed publicly "
                "(set UNITECH_V3_ALLOW_NON_LOOPBACK=1 only after explicit approval)."
            )
