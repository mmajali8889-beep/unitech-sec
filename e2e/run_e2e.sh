#!/usr/bin/env bash
# Starts a throw-away V3 stack on a temp data dir, runs the browser workflow, tears everything down.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"; PORT="${PORT:-8791}"
if curl -sf "http://127.0.0.1:${PORT:-8791}/api/health" >/dev/null; then echo "port in use" >&2; exit 2; fi
mkdir -p "$TMP/approved" && cp -r "$ROOT/testdata/vulnapp" "$TMP/approved/vulnapp"
export UNITECH_V3_DATA_DIR="$TMP/data" UNITECH_V3_PORT="$PORT" UNITECH_V3_FRONTEND_DIST="$ROOT/frontend/dist" UNITECH_V3_OLLAMA_URL="http://127.0.0.1:9/v1"
export PYTHONPATH="$ROOT/backend:$ROOT/agent"
mkdir -p "$UNITECH_V3_DATA_DIR"
( cd "$ROOT/backend" && python3 -m unitech_v3.cli migrate >/dev/null )
PASS=$(cd "$ROOT/backend" && python3 -m unitech_v3.cli init-admin | sed -E 's/.*: (.*)$/\1/')
TOK=$(cd "$ROOT/backend" && python3 -m unitech_v3.cli create-agent e2e-agent | sed -E 's/.*: (.*)$/\1/')
cat > "$TMP/agent.json" <<JSON
{"name":"e2e-agent","server_url":"http://127.0.0.1:$PORT","token":"$TOK","approved_roots":["$TMP/approved"]}
JSON
( cd "$ROOT/backend" && exec python3 -m unitech_v3.cli serve >"$TMP/api.log" 2>&1 ) & API=$!
( cd "$ROOT/agent" && exec python3 -m unitech_agent --config "$TMP/agent.json" >"$TMP/agent.out" 2>&1 ) & AGT=$!
trap 'kill $API $AGT 2>/dev/null || true' EXIT
for i in $(seq 1 50); do curl -sf "http://127.0.0.1:$PORT/api/health" >/dev/null && break; sleep 0.2; done
sleep 3   # first agent heartbeat

SHOTS="${SHOTS:-$ROOT/e2e/artifacts}"
NODE_PATH="$(npm root -g 2>/dev/null):${NODE_PATH:-}" node "$ROOT/e2e/workflow.mjs" "http://127.0.0.1:$PORT" admin "$PASS" "$TMP/approved/vulnapp" "$SHOTS"
