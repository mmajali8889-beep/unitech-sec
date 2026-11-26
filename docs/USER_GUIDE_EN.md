# User guide (English)

1. **Start**: run `scripts/start_local.py` (or `start.ps1`). Note the one-time admin password; open `http://127.0.0.1:8787`; change the password.
2. **Agent**: the launcher starts the local agent. *System Health* must show it **online** with its approved roots. Only those folders can be browsed or scanned.
3. **Register a project**: *Projects → Discover* or *Register* (pick from the approved-directory browser). Paths outside approved roots are rejected.
4. **Scan**: *Scan Center* → project → engines (unavailable engines are greyed out) → *Start scan*; or *File & Directory Scanner* for ad-hoc files/folders.
5. **Watch**: *Live Scan Monitor* shows real progress and events; *Cancel* stops the worker process.
   States: Queued, Running, Completed, **Partially completed** (an engine failed), Failed, Cancelled.
6. **Review**: *Source / Secrets / Dependency / Docker / Vulnerability Management* pages filter findings by severity, status, verification and project. Open a row for remediation; triage with a status and note (persists across re-scans).
7. **BEKO AI**: optional; sends only aggregated rule metadata (preview shown). Output is **unverified** until a human marks it reviewed. If Ollama is offline, scan results are unaffected.
8. **Reports**: *Reports Center* → generate JSON / HTML / SARIF / PDF → download. *Scan History* compares a scan with the previous one (new / fixed / risk delta).
9. **Schedules**: daily or interval scans per project; optional webhook notification (local/private URLs only) in *Settings*.
10. **Admin**: *Users & Permissions* (roles: admin, analyst, viewer, auditor), *Audit Logs* (verify tamper-evident chain), *Security Engines* (enable/disable).

Roles: **admin** everything · **analyst** register/scan/triage/report/schedule/BEKO · **viewer** read-only · **auditor** read-only + audit logs.
