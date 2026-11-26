# UNITECH Security Center V3

Centralised, web-based security scanning and operations platform: **React/TypeScript SOC UI → FastAPI control plane → restricted local agent → read-only scan engines**.
Local-only (127.0.0.1), read-only, no auto-remediation. Arabic RTL / English LTR, dark/light.

> **Status honesty:** the V2 sources (`D:\Security\...`: VibeSec, BEKO Analyzer, Multi-Project Audit, normalizer, importer) were **not available**
> to the build environment, so they are **not audited or integrated** — see [docs/ENGINE_AUDIT.md](docs/ENGINE_AUDIT.md). V3 ships a native
> engine set and a fixed-template adapter for plugging VibeSec in. Intended location on your machine: `D:\Security\UNITECH-SECURITY-V3`.

## Quick start (Linux / macOS)
```bash
pip install -r backend/requirements.txt
(cd frontend && npm ci && npm run build)
python scripts/start_local.py --data-dir ./data --approved-root /path/to/test-projects
# prints a one-time admin password -> open http://127.0.0.1:8787
```
## Windows
```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -ApprovedRoot D:\Security\TestProjects
powershell -File scripts\start.ps1 -ApprovedRoot D:\Security\TestProjects
```
(Windows scripts were not executed in the Linux build environment — review before first use. No elevation is required or requested.)

## Layout
| Path | Purpose |
|---|---|
| `backend/unitech_v3/` | API, DB + migrations, auth/RBAC, audit, services, **engines/** (registry, rules, taint, deps, external adapter) |
| `agent/unitech_agent/` | Restricted agent: path validation, RPC (browse/discover/validate), isolated worker process, heartbeat. Config example: `agent/agent.config.example.json` |
| `frontend/` | 19-page SOC web app |
| `backend/tests`, `e2e/` | pytest suite (66 tests) and Playwright browser workflow (20 checks) |
| `testdata/vulnapp/` | Intentionally vulnerable **non-production** sample project (fake secrets) |
| `docs/` | `ARCHITECTURE`, `ENGINE_AUDIT`, `SECURITY_ASSESSMENT`, `ROLLBACK_RECOVERY`, `USER_GUIDE_EN`, `USER_GUIDE_AR` |

## Verify
`scripts/run_tests.sh` → pytest + TypeScript build + real-browser E2E (starts a throw-away stack on a temp data dir).

## Workflow
Approved project/file → pick engines → validate → queue → agent executes (read-only, hard timeout, cancellable) → normalise + redact → persist →
optional BEKO (sanitized metadata only, unverified) → JSON/HTML/SARIF/PDF reports, schedules, comparisons, risk trend.
