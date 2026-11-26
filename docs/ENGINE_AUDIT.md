# Phase 1 — Source audit & engine registry (status: PARTIAL — read this first)

## What could not be done
The build environment was a Linux cloud container whose repository was empty. The Windows folders
`D:\Security\UNITECH-SECURITY`, `D:\Security\UNITECH-SECURITY-DELIVERY` and `D:\Security\vibesec2\vibesec` were **not reachable**, and no
copy of the VibeSec scanner, BEKO Security Analyzer, Multi-Project Audit, report normalizer or importer exists in this repository.
Therefore **no audit of those scripts was performed**, their CLI contracts / exit codes / outputs are **unknown**, and they are **not
integrated**. Nothing here claims otherwise. Nothing was executed from those folders (no deployment or key-rotation scripts).

## What was built instead
* A clean-room **native deterministic engine set** (`backend/unitech_v3/engines/`): secrets (10 rules), source (20), config (9),
  docker (11 + HEALTHCHECK), authz (7), Python **taint tracking** (AST, 8 sink classes), dependency hygiene (5).
* A **fixed-template external engine adapter** (`engines/external.py`): an administrator lists an argv template in the agent
  config, with only `{target}` / `{output}` placeholders; output is parsed as SARIF 2.1.0. `--fix`, `--autofix`, `--apply`, `--write`,
  `--in-place`, `--remediate` are rejected at agent start-up and at run time. No shell. Sanitised environment. Tested with a fake scanner.
  **This is the intended hook for VibeSec once its real CLI is verified** (run it with `--format sarif` or add a converter).
* BEKO is implemented as a separate AI layer (Ollama) — see `docs/SECURITY_ASSESSMENT.md`.

## Registry (`GET /api/capabilities`, UI → Security Engines)
| id | kind | targets | output | notes |
|---|---|---|---|---|
| secrets, source, config, docker, authz, taint, deps | native | file / directory / project | normalised findings → json/html/sarif/pdf | deterministic, read-only |
| vibesec | external adapter | file / directory / project | SARIF | **unavailable until configured on agent** |
| pip-audit | built-in tool wrapper (CVE) | project / directory | normalised findings | **verified** (pip-audit 2.10.1, real run found CVEs). Fixed argv, no shell, `--no-deps`. **Network egress** (package names + versions go to PyPI/OSV), so it is off unless the agent config sets `enable_pip_audit: true` |
| osv-scanner, npm-audit | planned CVE scanners | project | — | disabled: not installed/verified |
| beko | AI | finding metadata | markdown | optional, unverified |
| multi-project-audit, report-normalizer, importer | legacy | — | — | superseded natively; legacy code not imported |

Classification (Phase 1 requirement): scanners = native engines (+ vibesec adapter); report processors = normaliser + SARIF importer;
monitoring / administrative / deployment tools = **deliberately excluded** from V3 scan execution.

## To finish Phase 1 (needs your Windows machine)
Point a session at `D:\Security\...`, then: inventory scripts, record CLI/exit codes, fill `external_engines` in the agent config,
and map outputs through `external.parse_sarif` (or add a JSON adapter). Do **not** wire deployment/rotation scripts.
