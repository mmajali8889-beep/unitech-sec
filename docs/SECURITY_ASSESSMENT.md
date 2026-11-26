# Security assessment (self-assessment of V3 as built)

Scope: the code in this repository. This is a developer self-assessment, **not** an independent penetration test.

## Mandatory restrictions → how they are enforced (and tested)
| Requirement | Enforcement | Test |
|---|---|---|
| READ_ONLY scanning | Files opened `rb` only; worker runs in a child process; no write APIs exist | `test_scan_does_not_modify_sources`, API workflow compares file bytes before/after |
| No auto-remediation / no `--fix` | No remediation code path; external templates reject `--fix`-style flags | `test_external_template_rejects_dangerous` |
| No arbitrary shell from browser | API has no exec endpoint. Agent runs only native engines or admin-defined argv templates (no shell, placeholders `{target}`/`{output}` only) | template tests; code review |
| No unrestricted filesystem browsing | Browse/validate/discover are agent RPCs limited to `approved_roots`; links/junctions are hidden | `test_agent_online_and_browse_restricted`, `test_browse_hides_symlinks` |
| Symlink / junction escape | `os.path.realpath` containment + lexical link walk + `FILE_ATTRIBUTE_REPARSE_POINT` check; scanner never follows links | `test_pathguard.py`, `test_symlink_and_junction_not_followed` (symlinks tested on Linux; **Windows junctions are implemented via reparse-point attributes but untested here**) |
| Agent re-validates | Even if the DB were tampered, the agent refuses roots outside its config | `test_agent_refuses_unapproved_root_even_if_db_tampered` |
| Docker socket | Never accessed; Docker engine is static file analysis only | by design |
| Credential disclosure | Redaction at the source (agent) **and** again at ingest; reports/AI payloads/webhooks tested for raw secrets | `test_no_raw_secret_in_any_output`, full-workflow & BEKO payload tests |
| No public exposure | Server refuses non-loopback bind unless `UNITECH_V3_ALLOW_NON_LOOPBACK=1`; agent config must point at loopback; BEKO URL and webhooks must be loopback/private | `test_non_loopback_bind_refused`, `test_beko_url_must_be_loopback`, webhook SSRF test |
| V2 / PostgreSQL untouched | Independent SQLite DB in `data/`; no code imports or connects to V2 or PostgreSQL | by design |
| No deletion of scripts/projects | "Delete project" only deactivates the registration | `test_project_deactivate_never_touches_disk` |

## Authentication / authorisation
Argon2id password hashing; password policy (12+ chars, mixed); forced change on first login/reset; lockout after 5 failures (5 min);
login + per-user + per-agent + per-API-key rate limits; JWT HS256 with server-side session table (logout/reset revokes); RBAC with four roles
(`admin`, `analyst`, `viewer`, `auditor`); last-admin protection; agent tokens and n8n keys stored as SHA-256 hashes and shown once;
tamper-evident audit chain; security headers + CSP on the SPA; no stack traces in 500 responses; all request bodies validated by pydantic.

## BEKO / AI
Separate from scanning. Sends only aggregated rule metadata (rule id, severity, category, CWE, static title, count) — **no file paths, snippets,
project names or secrets**; the exact payload is previewed in the UI. Model availability is verified first. Output is labelled
"AI-GENERATED — UNVERIFIED", requires explicit human review marking, and scanner results are unaffected when Ollama is offline (tested).

## Known limitations / residual risks
1. **Legacy engines not integrated** (sources unavailable) — see `ENGINE_AUDIT.md`.
2. Heuristic regex rules produce false positives/negatives; taint tracking is Python-only and intra-procedural.
3. CVE scanning absent (adapters are registered but disabled until verified).
4. Transport is plain HTTP on loopback. If ever proxied, terminate TLS in a reverse proxy and keep the bind on loopback.
5. Resource limits: POSIX uses `RLIMIT_AS/CPU/FSIZE`; **on Windows only the file/byte quotas and the parent-enforced hard kill apply** (a Job Object limit is future work).
6. `JWT` secret and agent token live in files under `data/` (0600 on POSIX); on Windows rely on folder ACLs.
7. Rate limiter and scheduler are in-process (single API process). Do not run multiple workers.
8. No MFA / SSO. Secrets in unrecognised formats may not be redacted; keep `store_snippets` off for highly sensitive trees.
9. PDF report includes the AI text if present (clearly labelled).
10. n8n integration is implemented and tested against the API only — **not tested with a real n8n instance**.
11. The Windows-specific install/start scripts (`*.ps1`) were **not executed** in this Linux environment.
