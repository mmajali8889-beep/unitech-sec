#!/usr/bin/env bash
# Full verification: unit/integration/authorization/path/timeout/redaction tests, TypeScript build, browser E2E.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
( cd "$ROOT/backend" && python3 -m pytest tests -q )
( cd "$ROOT/frontend" && npm run build )
"$ROOT/e2e/run_e2e.sh"
