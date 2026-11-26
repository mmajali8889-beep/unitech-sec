from __future__ import annotations

import os
import shutil
import socket
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "agent"))
os.environ["PYTHONPATH"] = os.pathsep.join([str(ROOT / "backend"), str(ROOT / "agent"), os.environ.get("PYTHONPATH", "")])

from unitech_v3 import security  # noqa: E402
from unitech_v3.api.app import create_app  # noqa: E402
from unitech_v3.config import Settings  # noqa: E402
from unitech_agent.agent import Agent  # noqa: E402
from unitech_agent.config import AgentConfig  # noqa: E402

PW = "Str0ngPassw0rdXyz"


def free_port() -> int:
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p


class Env:
    pass


@pytest.fixture(scope="session")
def env(tmp_path_factory):
    e = Env()
    base = tmp_path_factory.mktemp("v3")
    e.roots = base / "approved"
    e.roots.mkdir()
    e.outside = base / "outside"
    e.outside.mkdir()
    (e.outside / "secret.txt").write_text("outside data\n")
    e.project = e.roots / "vulnapp"
    shutil.copytree(ROOT / "testdata" / "vulnapp", e.project)
    e.settings = Settings(data_dir=base / "data", port=free_port(), rate_limit_per_minute=100000, login_limit_per_minute=100000, start_scheduler=False)
    app = create_app(e.settings)
    e.ctx = app.state.ctx
    e.db = e.ctx.db
    now = time.time()
    for name, role in (("admin1", "admin"), ("analyst1", "analyst"), ("viewer1", "viewer"), ("auditor1", "auditor")):
        e.db.run("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)", (name, security.hash_password(PW), role, now))
    tok = security.new_secret_token("agt")
    e.agent_token = tok
    e.db.run("INSERT INTO agents(name,token_hash,created_at) VALUES(?,?,?)", ("test-agent", security.token_hash(tok), now))
    cfg = uvicorn.Config(app, host="127.0.0.1", port=e.settings.port, log_level="warning")
    e.server = uvicorn.Server(cfg)
    threading.Thread(target=e.server.run, daemon=True).start()
    e.url = f"http://127.0.0.1:{e.settings.port}"
    for _ in range(100):
        try:
            httpx.get(e.url + "/api/health", timeout=1); break
        except httpx.HTTPError:
            time.sleep(0.1)
    e.agent_cfg = AgentConfig(server_url=e.url, token=tok, name="test-agent", approved_roots=[e.roots], heartbeat_s=1.0, poll_interval_s=0.2,
                              external_engines={})
    e.agent = Agent(e.agent_cfg)
    threading.Thread(target=e.agent.run_forever, daemon=True).start()
    for _ in range(100):
        if e.db.one("SELECT last_seen FROM agents WHERE id=1")["last_seen"]:
            break
        time.sleep(0.1)
    yield e
    e.agent.stop.set()
    e.server.should_exit = True


class Client:
    def __init__(self, env: Env, user: str):
        self.c = httpx.Client(base_url=env.url, timeout=60)
        r = self.c.post("/api/auth/login", json={"username": user, "password": PW})
        assert r.status_code == 200, r.text
        # bootstrap accounts here have must_change_password=0
        self.c.headers["Authorization"] = "Bearer " + r.json()["token"]

    def __getattr__(self, n):
        return getattr(self.c, n)


@pytest.fixture(scope="session")
def admin(env):
    return Client(env, "admin1")


@pytest.fixture(scope="session")
def analyst(env):
    return Client(env, "analyst1")


@pytest.fixture(scope="session")
def viewer(env):
    return Client(env, "viewer1")


@pytest.fixture(scope="session")
def auditor(env):
    return Client(env, "auditor1")


def wait_job(client, jid, timeout=90):
    end = time.time() + timeout
    while time.time() < end:
        j = client.get(f"/api/scans/{jid}").json()
        if j["state"] not in ("queued", "running"):
            return j
        time.sleep(0.2)
    raise AssertionError("job did not finish: " + str(j))


ALL = ["secrets", "source", "config", "docker", "authz", "taint", "deps"]
