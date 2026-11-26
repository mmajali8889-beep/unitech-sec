"""SQLite persistence (independent V3 database) with ordered SQL migrations."""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

MIGRATIONS_DIR = Path(__file__).parent / "migrations"


class DB:
    def __init__(self, path: Path):
        self.path = Path(path)

    def conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA busy_timeout=30000")
        return c

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        c = self.conn()
        try:
            c.execute("BEGIN IMMEDIATE")
            yield c
            c.execute("COMMIT")
        except BaseException:
            try:
                c.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            c.close()

    def all(self, sql: str, args: tuple | list = ()) -> list[dict[str, Any]]:
        c = self.conn()
        try:
            return [dict(r) for r in c.execute(sql, args).fetchall()]
        finally:
            c.close()

    def one(self, sql: str, args: tuple | list = ()) -> dict[str, Any] | None:
        rows = self.all(sql, args)
        return rows[0] if rows else None

    def run(self, sql: str, args: tuple | list = ()) -> int:
        c = self.conn()
        try:
            cur = c.execute(sql, args)
            return cur.lastrowid or 0
        finally:
            c.close()

    # ---- settings -------------------------------------------------------
    def get_setting(self, key: str, default: Any = None) -> Any:
        r = self.one("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(r["value"]) if r else default

    def set_setting(self, key: str, value: Any) -> None:
        self.run("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                 (key, json.dumps(value)))

    # ---- migrations -----------------------------------------------------
    def migrate(self) -> list[str]:
        """Apply pending migrations. Each runs in one transaction; never touches foreign databases."""
        c = self.conn()
        applied: list[str] = []
        try:
            c.execute("CREATE TABLE IF NOT EXISTS schema_migrations(version TEXT PRIMARY KEY, applied_at REAL NOT NULL)")
            done = {r[0] for r in c.execute("SELECT version FROM schema_migrations")}
            for f in sorted(MIGRATIONS_DIR.glob("*.sql")):
                if f.stem in done:
                    continue
                script = f.read_text(encoding="utf-8")
                c.execute("BEGIN IMMEDIATE")
                try:
                    for stmt in _split(script):
                        c.execute(stmt)
                    c.execute("INSERT INTO schema_migrations VALUES(?,?)", (f.stem, time.time()))
                    c.execute("COMMIT")
                except BaseException:
                    c.execute("ROLLBACK")
                    raise
                applied.append(f.stem)
        finally:
            c.close()
        return applied


def _split(script: str) -> list[str]:
    return [s.strip() for s in script.split(";") if s.strip()]
