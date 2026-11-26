import hashlib
import json
import os
import shutil
import stat
import sys
import threading
import time
from pathlib import Path

import pytest

from unitech_v3.engines import external
from unitech_v3.engines.base import Cancelled, Limits, Timeout
from unitech_v3.engines.scanner import scan
from unitech_v3.engines.taint import analyse_python
from unitech_v3.redact import redact_line, redact_text

ROOT = Path(__file__).resolve().parents[2] / "testdata" / "vulnapp"
ALL = ["secrets", "source", "config", "docker", "authz", "taint", "deps"]
RAW_SECRETS = ["Sup3rS3cretPassw0rd!", "AKIAIOSFODNN7EXAMPLE", "hunter2pass", "zzzzYYYY9999q1w2", "abcd1234efgh5678"]


def tree_hash(p: Path):
    h = hashlib.sha256()
    for f in sorted(p.rglob("*")):
        if f.is_file():
            h.update(str(f.relative_to(p)).encode()); h.update(f.read_bytes()); h.update(str(f.stat().st_mtime_ns).encode())
    return h.hexdigest()


def test_scan_finds_expected_rules():
    r = scan(ROOT, [], ALL, Limits(), lambda: False)
    ids = {f.rule_id for f in r["findings"]}
    for want in ("SEC002", "SEC009", "SEC008", "SEC010", "CFG009", "SRC004", "SRC005", "TNT002", "TNT003", "TNT008", "DKR002", "DKR007", "DKR008", "DKR004", "DEP003"):
        assert want in ids, want
    assert all(s["state"] == "ok" for s in r["engine_status"].values())


def test_scan_does_not_modify_sources(tmp_path):
    p = tmp_path / "proj"; shutil.copytree(ROOT, p)
    before = tree_hash(p)
    scan(p, [], ALL, Limits(), lambda: False)
    assert tree_hash(p) == before


def test_no_raw_secret_in_any_output():
    r = scan(ROOT, [], ALL, Limits(), lambda: False)
    blob = json.dumps([f.to_dict() for f in r["findings"]])
    for s in RAW_SECRETS:
        assert s not in blob


def test_taint_true_and_false_positives():
    bad = '''
from flask import request
import os, sqlite3
@app.route("/x")
def x():
    a = request.args.get("a")
    b = a.strip()
    os.system("echo " + b)
'''
    good = '''
from flask import request
import os, sqlite3
@app.route("/x")
def x():
    n = int(request.args.get("a"))
    os.system("echo %d" % n)
    cur.execute("SELECT 1 WHERE id=?", (request.args.get("i"),))
    os.system("ls")
'''
    assert [f.rule_id for f in analyse_python("a.py", bad, bad.splitlines())] == ["TNT002"]
    assert analyse_python("a.py", good, good.splitlines()) == []


def test_taint_route_param_seed():
    src = 'import subprocess\n@app.get("/f/{name}")\ndef f(name):\n    subprocess.run("cat " + name, shell=True)\n'
    assert any(f.rule_id == "TNT002" for f in analyse_python("a.py", src, src.splitlines()))


def test_redaction_unit():
    for raw in ('password = "Sup3rS3cretPassw0rd!"', "token: ghp_" + "a" * 36, "postgres://u:hunter2pass@h/db", "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"):
        out = redact_line(raw)
        assert "hunter2pass" not in out and "Sup3rS3cret" not in out and "ghp_aaaa" not in out and "abcdefghijklmnopqrstuvwxyz" not in out, out
    assert redact_text("nothing secret here") == "nothing secret here"


def test_timeout_raises(tmp_path):
    for i in range(300):
        (tmp_path / f"f{i}.py").write_text("x=1\n" * 200)
    with pytest.raises(Timeout):
        scan(tmp_path, [], ["source"], Limits(timeout_s=0), lambda: False)


def test_cancel_raises(tmp_path):
    (tmp_path / "a.py").write_text("x=1\n")
    with pytest.raises(Cancelled):
        scan(tmp_path, [], ["source"], Limits(), lambda: True)


def test_symlink_and_junction_not_followed(tmp_path):
    outside = tmp_path / "out"; outside.mkdir(); (outside / "leak.py").write_text('password = "LeakedPassw0rd123"\n')
    proj = tmp_path / "proj"; proj.mkdir(); (proj / "ok.py").write_text("x=1\n")
    os.symlink(outside, proj / "linkdir"); os.symlink(outside / "leak.py", proj / "linkfile.py")
    r = scan(proj, [], ALL, Limits(), lambda: False)
    assert not any("leak" in f.file or "link" in f.file for f in r["findings"])
    assert any("skipped link" in n for n in r["notes"])


def test_target_traversal_rejected(tmp_path):
    from unitech_v3.pathguard import PathDenied
    (tmp_path / "a.py").write_text("x=1\n")
    for t in ("../x", "/etc/passwd", "C:/Windows", "a/../../b"):
        with pytest.raises(PathDenied):
            scan(tmp_path, [t], ["source"], Limits(), lambda: False)


def test_file_limits(tmp_path):
    (tmp_path / "big.py").write_text("x=1\n" * 500_000)
    r = scan(tmp_path, [], ["source"], Limits(max_file_bytes=1000), lambda: False)
    assert r["files_scanned"] == 0 and any("large" in n for n in r["notes"])


def test_engine_failure_isolated(monkeypatch):
    from unitech_v3.engines import taint
    monkeypatch.setattr(taint, "analyse_python", lambda *a: (_ for _ in ()).throw(RuntimeError("boom")))
    r = scan(ROOT, [], ["taint", "secrets"], Limits(), lambda: False)
    assert r["engine_status"]["taint"]["state"] == "failed" and r["engine_status"]["secrets"]["state"] == "ok"
    assert any(f.engine == "secrets" for f in r["findings"])


# ------------------------------------------------------------ external adapter
FAKE = '''
import json,sys
target,out=sys.argv[1],sys.argv[2]
sarif={"version":"2.1.0","runs":[{"results":[{"ruleId":"VS001","level":"error","message":{"text":"fake issue password=\\"Sup3rS3cretPassw0rd!\\""},
 "locations":[{"physicalLocation":{"artifactLocation":{"uri":target+"/app/main.py"},"region":{"startLine":3,"snippet":{"text":"x"}}}}]}]}]}
open(out,"w").write(json.dumps(sarif)); sys.exit(1)
'''


def test_external_adapter_sarif(tmp_path):
    s = tmp_path / "fake.py"; s.write_text(FAKE)
    cfg = {"vibesec": {"argv": [sys.executable, str(s), "{target}", "{output}"]}}
    r = scan(ROOT, [], ["vibesec"], Limits(), lambda: False, None, cfg)
    assert r["engine_status"]["vibesec"]["state"] == "ok"
    f = r["findings"][0]
    assert f.rule_id == "VS001" and f.file == "app/main.py" and f.severity == "high" and "Sup3rS3cret" not in f.title


@pytest.mark.parametrize("argv", [["x", "--fix", "{target}"], ["x", "{target}", "--autofix"], ["x"], ["x", "{bad}", "{target}"]])
def test_external_template_rejects_dangerous(argv):
    with pytest.raises(ValueError):
        external.validate_template(argv)


def test_external_failure_is_partial_not_fatal(tmp_path):
    cfg = {"vibesec": {"argv": ["definitely-not-installed-xyz", "{target}"]}}
    r = scan(ROOT, [], ["secrets", "vibesec"], Limits(), lambda: False, None, cfg)
    assert r["engine_status"]["vibesec"]["state"] == "failed" and r["engine_status"]["secrets"]["state"] == "ok"


# ------------------------------------------------------------ pip-audit CVE engine
CANNED = '{"dependencies":[{"name":"requests","version":"2.19.0","vulns":[{"id":"PYSEC-2018-28","fix_versions":["2.20.0"],"aliases":["CVE-2018-18074"]}]},{"name":"flask","version":"3.0.0","vulns":[]}]}'


def test_pip_audit_parser():
    fs = external.parse_pip_audit(CANNED, "requirements.txt", ["flask==3.0.0", "requests==2.19.0"])
    assert len(fs) == 1 and fs[0].rule_id == "CVE-2018-18074" and fs[0].line == 2 and "2.20.0" in fs[0].remediation and fs[0].verification == "deterministic"


def test_pip_audit_missing_tool_is_failed_engine(monkeypatch, tmp_path):
    monkeypatch.setattr(external, "pip_audit_available", lambda: False)
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    r = scan(tmp_path, [], ["deps", "pip-audit"], Limits(), lambda: False)
    assert r["engine_status"]["pip-audit"]["state"] == "failed" and r["engine_status"]["deps"]["state"] == "ok"


@pytest.mark.skipif(not external.pip_audit_available(), reason="pip-audit not installed")
def test_pip_audit_real(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n")
    r = scan(tmp_path, [], ["pip-audit"], Limits(timeout_s=120), lambda: False)
    if r["engine_status"]["pip-audit"]["state"] == "failed":
        pytest.skip("vulnerability service unreachable: " + r["engine_status"]["pip-audit"]["error"])
    assert any(f.rule_id.startswith("CVE-") for f in r["findings"])
