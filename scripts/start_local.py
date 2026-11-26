"""Local launcher: API (127.0.0.1 only) + restricted agent. Cross-platform (Windows/Linux).

  python scripts/start_local.py --data-dir ./data --approved-root D:\\Security\\TestProjects

First run: creates the V3 database, an admin account (one-time password printed) and an agent token
stored in <data-dir>/agent.config.json. Nothing outside <data-dir> is written.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run_cli(env, *args) -> str:
    return subprocess.run([sys.executable, "-m", "unitech_v3.cli", *args], env=env, cwd=ROOT / "backend", capture_output=True, text=True, check=True).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=str(ROOT / "data"))
    ap.add_argument("--approved-root", action="append", required=True, help="directory the agent may read (repeatable)")
    ap.add_argument("--port", type=int, default=8787)
    ns = ap.parse_args()
    data = Path(ns.data_dir).resolve(); data.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, "UNITECH_V3_DATA_DIR": str(data), "UNITECH_V3_PORT": str(ns.port),
           "PYTHONPATH": os.pathsep.join([str(ROOT / "backend"), str(ROOT / "agent")]),
           "UNITECH_V3_FRONTEND_DIST": str(ROOT / "frontend" / "dist")}
    print(run_cli(env, "migrate"))
    cfg_path = data / "agent.config.json"
    if not (data / ".admin_created").exists():
        out = run_cli(env, "init-admin")
        print(out)
        (data / ".admin_created").write_text("1")
    if not cfg_path.exists():
        out = run_cli(env, "create-agent", "local-agent")
        token = re.search(r"(agt_[\w\-]+)", out).group(1)
        cfg_path.write_text(json.dumps({"name": "local-agent", "server_url": f"http://127.0.0.1:{ns.port}", "token": token,
                                        "approved_roots": [str(Path(r).resolve()) for r in ns.approved_root], "log_file": str(data / "agent.log")}, indent=2))
        try:
            os.chmod(cfg_path, 0o600)
        except OSError:
            pass
    procs = [subprocess.Popen([sys.executable, "-m", "unitech_v3.cli", "serve"], env=env, cwd=ROOT / "backend")]
    time.sleep(2)
    procs.append(subprocess.Popen([sys.executable, "-m", "unitech_agent", "--config", str(cfg_path)], env=env, cwd=ROOT / "agent"))
    print(f"\nUNITECH Security Center V3 -> http://127.0.0.1:{ns.port}  (local only)  Ctrl+C to stop")

    def stop(*_):
        for p in procs:
            p.terminate()
        sys.exit(0)
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    while all(p.poll() is None for p in procs):
        time.sleep(1)
    stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
