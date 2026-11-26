import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import httpx
import pytest

from conftest import ALL, PW, Client, wait_job

RAW_SECRETS = ["Sup3rS3cretPassw0rd!", "AKIAIOSFODNN7EXAMPLE", "hunter2pass", "zzzzYYYY9999q1w2", "abcd1234efgh5678"]


# ---------------------------------------------------------------- authn / authz
def test_unauthenticated_rejected(env):
    for path in ("/api/projects", "/api/scans", "/api/findings", "/api/audit", "/api/users", "/api/system/health", "/api/dashboard"):
        assert httpx.get(env.url + path).status_code == 401, path
    assert httpx.get(env.url + "/api/projects", headers={"Authorization": "Bearer garbage"}).status_code == 401
    assert httpx.post(env.url + "/api/agent/claim").status_code == 401
    assert httpx.post(env.url + "/api/agent/claim", headers={"Authorization": "Bearer agt_wrong"}).status_code == 401


def test_rbac_matrix(env, admin, analyst, viewer, auditor):
    assert viewer.get("/api/findings").status_code == 200
    assert viewer.post("/api/scans", json={"project_id": 1, "engines": ["secrets"]}).status_code == 403
    assert viewer.post("/api/projects", json={"name": "zz", "path": str(env.project)}).status_code == 403
    assert viewer.get("/api/audit").status_code == 403
    assert viewer.get("/api/users").status_code == 403
    assert viewer.get("/api/browse").status_code == 403
    assert analyst.get("/api/audit").status_code == 403
    assert analyst.get("/api/users").status_code == 403
    assert analyst.put("/api/settings", json={"store_snippets": True}).status_code == 403
    assert analyst.post("/api/agents", json={"name": "evil-agent"}).status_code == 403
    assert auditor.get("/api/audit").status_code == 200
    assert auditor.post("/api/scans", json={"project_id": 1, "engines": ["secrets"]}).status_code == 403
    assert admin.get("/api/users").status_code == 200
    denied = admin.get("/api/audit", params={"outcome": "denied"}).json()
    assert denied["total"] >= 5


def test_token_revoked_on_logout(env):
    c = Client(env, "viewer1")
    assert c.get("/api/auth/me").status_code == 200
    c.post("/api/auth/logout")
    assert c.get("/api/auth/me").status_code == 401


def test_login_lockout_and_rate_limit(env):
    env.db.run("INSERT INTO users(username,password_hash,role,created_at) VALUES('locky','x','viewer',0)")
    from unitech_v3 import security
    env.db.run("UPDATE users SET password_hash=? WHERE username='locky'", (security.hash_password(PW),))
    for _ in range(5):
        assert httpx.post(env.url + "/api/auth/login", json={"username": "locky", "password": "wrong"}).status_code == 401
    assert httpx.post(env.url + "/api/auth/login", json={"username": "locky", "password": PW}).status_code == 423
    # rate limiter
    from unitech_v3.ratelimit import RateLimiter
    rl = RateLimiter()
    assert [rl.allow("k", 3) for _ in range(5)] == [True, True, True, False, False]


def test_login_rate_limit_http(env):
    old = env.ctx.settings.login_limit_per_minute
    env.ctx.settings.login_limit_per_minute = 3
    try:
        codes = [httpx.post(env.url + "/api/auth/login", json={"username": "nobody", "password": "x"}, headers={"X-Forwarded-For": "1.2.3.4"}).status_code for _ in range(6)]
        assert 429 in codes
    finally:
        env.ctx.settings.login_limit_per_minute = old
        env.ctx.limiter._hits.clear()


def test_password_policy_and_force_change(env, admin):
    assert admin.post("/api/users", json={"username": "weakuser", "role": "viewer", "password": "short"}).status_code == 422
    r = admin.post("/api/users", json={"username": "newbie", "role": "viewer", "password": "InitialPassw0rdAA"})
    assert r.status_code == 201
    c = httpx.Client(base_url=env.url)
    tok = c.post("/api/auth/login", json={"username": "newbie", "password": "InitialPassw0rdAA"}).json()["token"]
    c.headers["Authorization"] = "Bearer " + tok
    assert c.get("/api/projects").status_code == 403          # must change password first
    assert c.post("/api/auth/change-password", json={"current_password": "InitialPassw0rdAA", "new_password": "weak"}).status_code == 422
    assert c.post("/api/auth/change-password", json={"current_password": "InitialPassw0rdAA", "new_password": "BrandNewPassw0rd1"}).status_code == 200
    assert c.get("/api/projects").status_code == 200


def test_cannot_remove_last_admin(env, admin):
    users = admin.get("/api/users").json()
    me = next(u for u in users if u["username"] == "admin1")
    env.db.run("UPDATE users SET active=0 WHERE role='admin' AND username!='admin1'")
    assert admin.patch(f"/api/users/{me['id']}", json={"active": False}).status_code == 409
    assert admin.patch(f"/api/users/{me['id']}", json={"role": "viewer"}).status_code == 409


def test_security_headers(env):
    r = httpx.get(env.url + "/api/health")
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"


def test_non_loopback_bind_refused(tmp_path):
    from unitech_v3.config import Settings
    with pytest.raises(RuntimeError):
        Settings(data_dir=tmp_path, host="0.0.0.0").ensure()


# ---------------------------------------------------------------- agent & project registration
def test_agent_online_and_browse_restricted(env, analyst):
    r = analyst.get("/api/browse")
    assert r.status_code == 200 and r.json()["roots"] is True
    r = analyst.get("/api/browse", params={"path": str(env.roots)})
    assert any(e["name"] == "vulnapp" for e in r.json()["entries"])
    for bad in (str(env.outside), "/etc", str(env.roots / ".." / "outside"), "/"):
        assert analyst.get("/api/browse", params={"path": bad}).status_code == 400, bad


def test_browse_hides_symlinks(env, analyst):
    os.symlink(env.outside, env.roots / "escape_link")
    try:
        names = [e["name"] for e in analyst.get("/api/browse", params={"path": str(env.roots)}).json()["entries"]]
        assert "escape_link" not in names
        assert analyst.get("/api/browse", params={"path": str(env.roots / "escape_link")}).status_code == 400
    finally:
        os.unlink(env.roots / "escape_link")


def test_discover_and_register(env, analyst):
    d = analyst.post("/api/projects/discover", json={}).json()
    assert any(c["name"] == "vulnapp" for c in d["candidates"])
    assert analyst.post("/api/projects", json={"name": "Outside", "path": str(env.outside)}).status_code == 400
    assert analyst.post("/api/projects", json={"name": "Trav", "path": str(env.roots / ".." / "outside")}).status_code == 400
    r = analyst.post("/api/projects", json={"name": "vulnapp", "path": str(env.project), "kind": "python"})
    assert r.status_code == 201, r.text
    assert analyst.post("/api/projects", json={"name": "vulnapp2", "path": str(env.project)}).status_code == 409


def pid(analyst):
    return next(p["id"] for p in analyst.get("/api/projects").json() if p["name"] == "vulnapp")


# ---------------------------------------------------------------- full scan workflow
def test_capabilities(analyst):
    caps = analyst.get("/api/capabilities").json()
    ids = {e["id"]: e for e in caps["engines"]}
    assert ids["taint"]["available"] and ids["secrets"]["available"]
    assert not ids["pip-audit"]["available"] and not ids["vibesec"]["available"]
    assert any(l["id"] == "beko" for l in caps["legacy"])


def test_scan_validation(env, analyst):
    p = pid(analyst)
    assert analyst.post("/api/scans", json={"engines": ["secrets"]}).status_code == 422
    assert analyst.post("/api/scans", json={"project_id": p, "adhoc_path": "/x", "engines": ["secrets"]}).status_code == 422
    assert analyst.post("/api/scans", json={"project_id": p, "engines": ["nope"]}).status_code == 422
    assert analyst.post("/api/scans", json={"project_id": p, "engines": ["pip-audit"]}).status_code == 422
    assert analyst.post("/api/scans", json={"project_id": p, "engines": ["secrets"], "targets": ["../x"]}).status_code == 422
    assert analyst.post("/api/scans", json={"project_id": p, "engines": ["secrets"], "targets": ["/etc/passwd"]}).status_code == 422
    assert analyst.post("/api/scans", json={"project_id": 9999, "engines": ["secrets"]}).status_code == 404
    assert analyst.post("/api/scans", json={"adhoc_path": str(env.outside), "engines": ["secrets"]}).status_code == 400
    assert analyst.post("/api/scans", json={"project_id": p, "engines": ["secrets"], "timeout_s": 1}).status_code == 422


def test_full_workflow(env, analyst, viewer, admin):
    p = pid(analyst)
    before = {f: f.read_bytes() for f in env.project.rglob("*") if f.is_file()}
    r = analyst.post("/api/scans", json={"project_id": p, "engines": ALL})
    assert r.status_code == 201 and r.json()["state"] == "queued"
    jid = r.json()["id"]
    j = wait_job(analyst, jid)
    assert j["state"] == "completed", j
    assert j["files_scanned"] >= 5 and j["risk_score"] > 0 and j["progress"] == 1.0
    assert j["summary"]["total"] > 15 and all(s["state"] == "ok" for s in j["engine_status"].values())
    # actual progress events
    ev = analyst.get(f"/api/scans/{jid}/events").json()["events"]
    kinds = [e["kind"] for e in ev]
    assert "start" in kinds and "persist" in kinds and ev[-1]["message"] == "job completed"
    # findings: normalised, redacted, with location + remediation
    fs = analyst.get("/api/findings", params={"job_id": jid, "limit": 1000}).json()
    blob = json.dumps(fs)
    for s in RAW_SECRETS:
        assert s not in blob
    f = next(x for x in fs["items"] if x["rule_id"] == "TNT002")
    assert f["file"] == "app/main.py" and f["line"] == 12 and f["verification"] == "deterministic" and f["remediation"] and f["severity"] == "critical"
    assert all(not os.path.isabs(x["file"]) for x in fs["items"])
    assert viewer.get("/api/findings", params={"category": "docker"}).json()["total"] >= 5
    # source files untouched
    after = {f: f.read_bytes() for f in env.project.rglob("*") if f.is_file()}
    assert before == after
    # reports in all formats
    for fmt, check in (("json", lambda b: json.loads(b)["findings"]), ("sarif", lambda b: json.loads(b)["runs"][0]["results"]),
                       ("html", lambda b: b"<table>" in b), ("pdf", lambda b: b.startswith(b"%PDF"))):
        rep = analyst.post("/api/reports", json={"job_id": jid, "format": fmt})
        assert rep.status_code == 201, rep.text
        body = viewer.get(f"/api/reports/{rep.json()['id']}/download")
        assert body.status_code == 200 and check(body.content if fmt in ("html", "pdf") else body.text)
        for s in RAW_SECRETS:
            assert s.encode() not in body.content
    rid = next(r["id"] for r in analyst.get("/api/reports", params={"job_id": jid}).json() if r["format"] == "sarif")
    sarif = json.loads(viewer.get(f"/api/reports/{rid}/download").text)
    assert sarif["version"] == "2.1.0"
    # triage persists across rescans
    tid = f["id"]
    assert viewer.patch(f"/api/findings/{tid}", json={"status": "accepted"}).status_code == 403
    assert analyst.patch(f"/api/findings/{tid}", json={"status": "false_positive", "note": "reviewed"}).status_code == 200
    j2 = wait_job(analyst, analyst.post("/api/scans", json={"project_id": p, "engines": ALL}).json()["id"])
    f2 = next(x for x in analyst.get("/api/findings", params={"job_id": j2["id"], "rule_id": "TNT002"}).json()["items"])
    assert f2["status"] == "false_positive"
    cmp = analyst.get(f"/api/scans/{j2['id']}/compare").json()
    assert cmp["base"] == jid and cmp["new"] == [] and cmp["fixed"] == [] and cmp["unchanged"] == j["summary"]["total"]
    dash = viewer.get("/api/dashboard").json()
    assert dash["totals"]["projects"] >= 1 and dash["severity"] and dash["job_states"]["completed"] >= 2


def test_selected_files_and_single_file_scan(env, analyst):
    p = pid(analyst)
    j = wait_job(analyst, analyst.post("/api/scans", json={"project_id": p, "engines": ["secrets"], "targets": ["app/main.py", ".env"]}).json()["id"])
    assert j["state"] == "completed" and j["target_kind"] == "files" and j["files_scanned"] == 2
    j = wait_job(analyst, analyst.post("/api/scans", json={"adhoc_path": str(env.project / "app" / "main.py"), "engines": ["taint"]}).json()["id"])
    assert j["target_kind"] == "file" and j["files_scanned"] == 1 and j["summary"]["total"] == 3
    j = wait_job(analyst, analyst.post("/api/scans", json={"adhoc_path": str(env.project / "docker"), "engines": ["docker"]}).json()["id"])
    assert j["target_kind"] == "directory" and j["summary"]["total"] >= 10
    # targets that traverse out are rejected by the agent as well, even if the API were bypassed
    jid = env.db.run("INSERT INTO scan_jobs(project_id,target_kind,target_json,engines_json,state,created_at,agent_id) VALUES(?, 'files', ?, '[\"secrets\"]','queued',?,1)",
                     (p, json.dumps(["../../outside/secret.txt"]), time.time()))
    j = wait_job(analyst, jid)
    assert j["state"] == "failed"


def test_agent_refuses_unapproved_root_even_if_db_tampered(env, analyst):
    jid = env.db.run("INSERT INTO scan_jobs(adhoc_path,target_kind,target_json,engines_json,state,created_at,agent_id) VALUES(?, 'directory','[]','[\"secrets\"]','queued',?,1)",
                     (str(env.outside), time.time()))
    j = wait_job(analyst, jid)
    assert j["state"] == "failed" and "not approved" in j["error"]


def test_partial_state_when_engine_fails(env, analyst, tmp_path):
    p = pid(analyst)
    env.agent.cfg.external_engines = {"vibesec": {"argv": ["no-such-binary-xyz", "{target}"]}}
    env.db.run("UPDATE agents SET engines_json='[\"vibesec\"]' WHERE id=1")   # as if reported by heartbeat
    try:
        r = analyst.post("/api/scans", json={"project_id": p, "engines": ["secrets", "vibesec"]})
        if r.status_code == 201:
            j = wait_job(analyst, r.json()["id"])
            assert j["state"] == "partial" and j["engine_status"]["vibesec"]["state"] == "failed" and j["summary"]["total"] > 0
        else:
            assert r.status_code == 422      # heartbeat overwrote availability (binary missing) - engine correctly unavailable
    finally:
        env.agent.cfg.external_engines = {}


def test_external_engine_cancel_and_timeout(env, analyst, tmp_path):
    slow = tmp_path / "slow.py"
    slow.write_text("import time\ntime.sleep(60)\n")
    env.agent.cfg.external_engines = {"vibesec": {"argv": [sys.executable, str(slow), "{target}", "{output}"]}}
    p = pid(analyst)
    try:
        time.sleep(1.5)  # allow heartbeat to publish engine availability
        # cancellation of a running job
        r = analyst.post("/api/scans", json={"project_id": p, "engines": ["secrets", "vibesec"]})
        assert r.status_code == 201, r.text
        jid = r.json()["id"]
        for _ in range(100):
            if analyst.get(f"/api/scans/{jid}").json()["state"] == "running":
                break
            time.sleep(0.1)
        time.sleep(1.0)
        cr = analyst.post(f"/api/scans/{jid}/cancel")
        assert cr.status_code == 200, (cr.text, analyst.get(f"/api/scans/{jid}").json())
        t0 = time.time()
        j = wait_job(analyst, jid, 30)
        assert j["state"] == "cancelled" and time.time() - t0 < 15
        assert analyst.post(f"/api/scans/{jid}/cancel").status_code == 409
        # timeout (min allowed API timeout is 10s)
        jid = analyst.post("/api/scans", json={"project_id": p, "engines": ["vibesec"], "timeout_s": 10}).json()["id"]
        t0 = time.time()
        j = wait_job(analyst, jid, 60)
        assert j["state"] in ("failed",) and (time.time() - t0) < 40
        assert "vibesec" in json.dumps(j) or "timeout" in (j["error"] or "")
    finally:
        env.agent.cfg.external_engines = {}


def test_cancel_queued_job(env, analyst):
    env.db.run("INSERT OR IGNORE INTO agents(id,name,token_hash,created_at) VALUES(999,'ghost','h999',0)")
    jid = env.db.run("INSERT INTO scan_jobs(project_id,target_kind,target_json,engines_json,state,created_at,agent_id) VALUES(?, 'project','[]','[\"secrets\"]','queued',?,999)",
                     (pid(analyst), time.time()))
    assert analyst.post(f"/api/scans/{jid}/cancel").json()["state"] == "cancelled"


# ---------------------------------------------------------------- BEKO / Ollama
class FakeOllama(BaseHTTPRequestHandler):
    seen: list = []

    def log_message(self, *a): pass

    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"data": [{"id": "glm-4.7-flash:q4_K_M"}]}).encode())

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        FakeOllama.seen.append(json.loads(body))
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        self.wfile.write(json.dumps({"choices": [{"message": {"content": "Prioritise TNT002. (unverified)"}}]}).encode())


def test_beko_offline_keeps_scanner_results(env, analyst):
    env.db.set_setting("beko.url", "http://127.0.0.1:9/v1")      # nothing listens here
    r = analyst.post("/api/scans", json={"project_id": pid(analyst), "engines": ["secrets", "taint"], "beko": True})
    j = wait_job(analyst, r.json()["id"])
    assert j["state"] == "completed" and j["summary"]["total"] > 0
    for _ in range(50):
        j = analyst.get(f"/api/scans/{j['id']}").json()
        if j["beko_state"] != "pending":
            break
        time.sleep(0.2)
    assert j["beko_state"] == "unavailable" and j["state"] == "completed"
    assert analyst.get("/api/findings", params={"job_id": j["id"]}).json()["total"] == j["summary"]["total"]
    st = analyst.get("/api/beko/status").json()
    assert st["reachable"] is False and st["model"] == "glm-4.7-flash:q4_K_M"


def test_beko_sends_only_sanitized_metadata(env, analyst):
    srv = HTTPServer(("127.0.0.1", 0), FakeOllama)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    env.db.set_setting("beko.url", f"http://127.0.0.1:{srv.server_port}/v1")
    try:
        jid = wait_job(analyst, analyst.post("/api/scans", json={"project_id": pid(analyst), "engines": ALL}).json()["id"])["id"]
        assert analyst.get("/api/beko/status").json()["model_available"] is True
        assert analyst.post("/api/beko/analyse", json={"job_id": jid}).status_code == 202
        for _ in range(50):
            a = analyst.get("/api/beko/analyses", params={"job_id": jid}).json()["items"]
            if a:
                break
            time.sleep(0.2)
        assert a[0]["state"] == "ok" and "UNVERIFIED" in a[0]["disclaimer"] and a[0]["human_reviewed"] == 0
        sent = json.dumps(FakeOllama.seen[-1])
        for leak in RAW_SECRETS + ["main.py", "app/", "vulnapp", "echo", "pickle.loads(request", str(env.roots), "SELECT * FROM"]:
            assert leak not in sent, leak
        assert "TNT002" in sent
        assert analyst.post(f"/api/beko/analyses/{a[0]['id']}/review").status_code == 200
    finally:
        srv.shutdown()
        env.db.set_setting("beko.url", "http://127.0.0.1:9/v1")


def test_beko_url_must_be_loopback(env, admin):
    assert admin.put("/api/settings", json={"beko_url": "http://evil.example.com/v1"}).status_code == 422


# ---------------------------------------------------------------- schedules / notifications / n8n / audit
def test_schedule_fires_job(env, analyst, viewer):
    p = pid(analyst)
    assert analyst.post("/api/schedules", json={"name": "bad", "project_id": p, "engines": ["secrets"]}).status_code == 422
    assert viewer.post("/api/schedules", json={"name": "nightly", "project_id": p, "engines": ["secrets"], "daily_at": "02:00"}).status_code == 403
    s = analyst.post("/api/schedules", json={"name": "nightly", "project_id": p, "engines": ["secrets"], "interval_minutes": 5}).json()
    env.db.run("UPDATE schedules SET next_run=? WHERE id=?", (time.time() - 1, s["id"]))
    from unitech_v3 import services
    assert services.scheduler_tick(env.ctx) == 1
    assert services.scheduler_tick(env.ctx) == 0
    sch = analyst.get("/api/schedules").json()[0]
    j = wait_job(analyst, sch["last_job_id"])
    assert j["state"] == "completed" and j["schedule_id"] == s["id"]
    assert analyst.patch(f"/api/schedules/{s['id']}", json={"enabled": False}).json()["enabled"] == 0
    assert analyst.delete(f"/api/schedules/{s['id']}").status_code == 200


def test_next_run_daily():
    from unitech_v3.services import next_run_for
    now = time.time()
    assert 0 < next_run_for(None, "03:30", now) - now <= 86400
    assert next_run_for(15, None, now) == now + 900


def test_webhook_notification_and_ssrf_guard(env, admin, analyst):
    got = []

    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            got.append((dict(self.headers), json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200); self.end_headers()

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert admin.put("/api/settings", json={"webhook_url": "http://example.com/hook"}).status_code == 422   # public host refused
        assert admin.put("/api/settings", json={"notifications_enabled": True, "webhook_url": f"http://127.0.0.1:{srv.server_port}/h", "webhook_secret": "s3cr3t-hook"}).status_code == 200
        wait_job(analyst, analyst.post("/api/scans", json={"project_id": pid(analyst), "engines": ["secrets"]}).json()["id"])
        for _ in range(50):
            if got: break
            time.sleep(0.1)
        hdrs, payload = got[0]
        assert payload["event"] == "scan.finished" and payload["counts"] and "app/main.py" not in json.dumps(payload)
        assert any(k.lower() == "x-unitech-secret" for k in hdrs)
        assert "s3cr3t-hook" not in json.dumps(admin.get("/api/settings").json())
    finally:
        admin.put("/api/settings", json={"notifications_enabled": False})
        srv.shutdown()


def test_n8n_integration(env, admin, analyst):
    assert httpx.post(env.url + "/api/integrations/n8n/scan", json={"project": "vulnapp"}, headers={"X-API-Key": "x"}).status_code == 404   # disabled
    admin.put("/api/settings", json={"n8n_enabled": True})
    key = admin.post("/api/integrations/keys", json={"name": "n8n-main"}).json()["key"]
    assert httpx.post(env.url + "/api/integrations/n8n/scan", json={"project": "vulnapp"}, headers={"X-API-Key": "bad"}).status_code == 401
    assert analyst.post("/api/integrations/keys", json={"name": "zz"}).status_code == 403
    r = httpx.post(env.url + "/api/integrations/n8n/scan", json={"project": "vulnapp", "engines": ["secrets"]}, headers={"X-API-Key": key})
    assert r.status_code == 201
    j = wait_job(analyst, r.json()["job_id"])
    assert httpx.get(env.url + f"/api/integrations/n8n/scans/{j['id']}", headers={"X-API-Key": key}).json()["state"] == "completed"
    # n8n key cannot be used as a user token
    assert httpx.get(env.url + "/api/projects", headers={"Authorization": "Bearer " + key}).status_code == 401
    admin.put("/api/settings", json={"n8n_enabled": False})


def test_audit_log_complete_and_tamper_evident(env, auditor):
    acts = {a["action"] for a in auditor.get("/api/audit", params={"limit": 500}).json()["items"]}
    for a in ("auth.login", "project.register", "scan.create", "scan.finish", "report.create", "authz.denied", "browse", "finding.triage"):
        assert a in acts, a
    assert auditor.get("/api/audit/verify").json()["valid"] is True
    raw = json.dumps(auditor.get("/api/audit", params={"limit": 500}).json())
    assert PW not in raw
    row = env.db.one("SELECT id FROM audit_logs ORDER BY id LIMIT 1 OFFSET 3")
    env.db.run("UPDATE audit_logs SET actor='mallory' WHERE id=?", (row["id"],))
    v = auditor.get("/api/audit/verify").json()
    assert v["valid"] is False and v["broken_at"] == row["id"]


def test_engine_toggle_and_system_health(env, admin, analyst):
    assert admin.patch("/api/engines/taint", json={"enabled": False}).status_code == 200
    assert analyst.post("/api/scans", json={"project_id": pid(analyst), "engines": ["taint"]}).status_code == 422
    admin.patch("/api/engines/taint", json={"enabled": True})
    h = analyst.get("/api/system/health").json()
    assert h["database"]["ok"] and h["agents"][0]["online"] is True and h["bind"].startswith("127.0.0.1")
    assert h["agents"][0]["roots"] == [str(env.roots)]


def test_agent_health_lost_job(env, analyst):
    from unitech_v3 import services
    env.db.run("INSERT INTO agents(id,name,token_hash,created_at,last_seen) VALUES(2,'dead','h2',0,?)", (time.time() - 1000,))
    jid = env.db.run("INSERT INTO scan_jobs(project_id,target_kind,engines_json,state,created_at,started_at,agent_id) VALUES(?, 'project','[\"secrets\"]','running',?,?,2)", (pid(analyst), time.time(), time.time()))
    assert services.health_tick(env.ctx) == 1
    assert analyst.get(f"/api/scans/{jid}").json()["state"] == "failed"


def test_project_deactivate_never_touches_disk(env, admin):
    r = admin.post("/api/projects", json={"name": "tmpproj", "path": str(env.project / "docker")})
    pid_ = r.json()["id"]
    assert admin.delete(f"/api/projects/{pid_}").status_code == 200
    assert (env.project / "docker" / "Dockerfile").exists()


def test_migrations_idempotent(tmp_path):
    from unitech_v3.db import DB
    d = DB(tmp_path / "x.db")
    assert d.migrate() == ["0001_init"] and d.migrate() == []
