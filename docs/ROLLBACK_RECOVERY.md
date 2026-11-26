# Rollback & recovery

V3 is self-contained: everything it writes is under its **data directory** (`data/` by default): `unitech_v3.db` (+WAL), `jwt.secret`,
`reports/`, and (via `start_local.py`) `agent.config.json`. Production V2 / Canary V2 / PostgreSQL are never touched.

## Remove V3 completely (rollback)
1. Stop the launcher (Ctrl+C) / the API and agent processes.
2. Delete the V3 folder. V2 is unaffected. Scanned projects were never modified (read-only).

## Back up
Stop the API (or use SQLite online backup) and copy `data/unitech_v3.db`, `data/jwt.secret` and `data/reports/`:
```bash
python - <<'PY'
import sqlite3; s=sqlite3.connect("data/unitech_v3.db"); d=sqlite3.connect("data/backup.db"); s.backup(d); d.close()
PY
```
Keep backups outside the repository and treat `jwt.secret` as a credential. Backups are **separate from scan execution** — no backup job runs from the web UI.

## Restore
Stop V3 → replace `unitech_v3.db` (delete stale `-wal`/`-shm` files) and `jwt.secret` → start. Migrations are idempotent
(`python -m unitech_v3.cli migrate`; applied versions are in `schema_migrations`).

## Schema rollback
Migrations are forward-only SQL. Roll back by restoring the pre-upgrade DB copy taken before running `migrate`.

## Incident recovery
* **Lost admin password:** stop the API, run `python -m unitech_v3.cli init-admin --username recovery-admin` (prints a one-time password).
* **Compromised agent token:** admin → `DELETE /api/agents/{id}` (revokes), create a new agent, update the agent config.
* **Leaked API key (n8n):** Settings → API keys → delete. Rotating `jwt.secret` (delete file, restart) invalidates every user session.
* **Suspected audit tampering:** Audit Logs → *Verify chain*; the first broken entry id is reported.
* **Agent crash mid-scan:** the job is closed as `failed` ("agent heartbeat lost") after 120 s; re-run the scan.
