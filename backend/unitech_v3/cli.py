"""Administrative CLI (run locally on the server; separate from the web API)."""
from __future__ import annotations

import argparse
import secrets
import string
import sys
import time

from . import security
from .config import Settings
from .db import DB


def _pw() -> str:
    a = string.ascii_letters + string.digits
    while True:
        p = "".join(secrets.choice(a) for _ in range(20))
        if not security.password_policy(p):
            return p


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="unitech_v3.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("migrate")
    a = sub.add_parser("init-admin"); a.add_argument("--username", default="admin")
    g = sub.add_parser("create-agent"); g.add_argument("name")
    sub.add_parser("serve")
    ns = ap.parse_args(argv)
    s = Settings(); s.ensure()
    db = DB(s.db_path)
    applied = db.migrate()
    if ns.cmd == "migrate":
        print("applied:", applied or "nothing (up to date)")
    elif ns.cmd == "init-admin":
        if db.one("SELECT id FROM users WHERE username=?", (ns.username,)):
            print("user exists; nothing changed"); return 1
        pw = _pw()
        db.run("INSERT INTO users(username,display_name,password_hash,role,must_change_password,created_at) VALUES(?,?,?,?,1,?)",
               (ns.username, "Administrator", security.hash_password(pw), "admin", time.time()))
        print(f"Created admin '{ns.username}'. One-time password (change at first login): {pw}")
    elif ns.cmd == "create-agent":
        tok = security.new_secret_token("agt")
        db.run("INSERT INTO agents(name,token_hash,created_at) VALUES(?,?,?)", (ns.name, security.token_hash(tok), time.time()))
        print(f"Agent '{ns.name}' token (shown once): {tok}")
    elif ns.cmd == "serve":
        import uvicorn
        from .api.app import create_app
        uvicorn.run(create_app(s), host=s.host, port=s.port, log_level="info")
    return 0


if __name__ == "__main__":
    sys.exit(main())
