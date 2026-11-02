"""Practice 3, second part: what the first part left partial or pending.

Taint, documentation against code, dead code, more ecosystems and registry
maintenance, validation and services on the surface, MCP in attack paths and
decoys, the OWASP taxonomy check, the PDF, the isolated scanner process,
What If, replay, pull requests, the digital twin, Blue Team and human
approval of learnt rules. Credential-shaped strings are built at run time.
"""
import json
import os
import random
import subprocess
import sys
import zlib
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analysis import (attacker, canary, deadcode, deps, doc_claims, mcp_audit,  # noqa: E402
                      pdf, surface, taint, trust, twin)

GH = "ghp_" + "Q7w8E9r0T1y2" * 3


def git(repo, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                          cwd=repo, check=True, capture_output=True, text=True).stdout


# ---------------------------------------------------------------------------
# B11 taint
# ---------------------------------------------------------------------------

FLASK = '''import os, subprocess, sqlite3
from flask import Flask, request, redirect
app = Flask(__name__)

@app.route("/u")
def user():
    name = request.args.get("name")
    q = "SELECT * FROM users WHERE name = '%s'" % name
    return sqlite3.connect("x").execute(q).fetchall()

@app.route("/safe")
def safe():
    name = request.args.get("name")
    return sqlite3.connect("x").execute("SELECT * FROM u WHERE n = ?", (name,)).fetchall()

@app.route("/ping")
def ping():
    host = request.form["host"]
    return subprocess.check_output("ping -c1 " + host, shell=True)

@app.route("/n")
def num():
    n = int(request.args.get("n"))
    os.system("echo %d" % n)

def helper(x):
    eval(x)
'''

EXPRESS = '''const { exec } = require("child_process");
app.get("/x", (req, res) => {
  const { cmd } = req.query;
  exec("ls " + cmd);
  const id = req.params.id;
  db.query(`SELECT * FROM t WHERE id = ${id}`);
  db.query("SELECT * FROM t WHERE id = ?", [id]);
});
'''


class TestTaint:
    def kinds(self, texts):
        return {(r["file"], r["line"], r["kind"]) for r in taint.analyze(texts)["raw"]}

    def test_python_flows_and_their_absence(self):
        got = self.kinds({"app.py": FLASK})
        assert ("app.py", 9, "sql") in got
        assert ("app.py", 19, "command") in got
        # bound parameters, int() and a helper with no source: nothing
        lines = {line for _, line, _ in got}
        assert 14 not in lines and 24 not in lines and 27 not in lines

    def test_the_flow_is_recorded_step_by_step(self):
        [sql] = [r for r in taint.analyze({"app.py": FLASK})["raw"] if r["kind"] == "sql"]
        assert [s["step"] for s in sql["flow"]] == ["source", "assign", "sink"]
        assert [s["line"] for s in sql["flow"]] == [7, 8, 9]

    def test_javascript_by_pattern(self):
        got = self.kinds({"server.js": EXPRESS})
        assert ("server.js", 4, "command") in got and ("server.js", 6, "sql") in got
        assert not any(line == 7 for _, line, _ in got)       # parameters passed apart

    def test_findings_say_their_limits_and_stay_potential(self):
        raw = taint.analyze({"app.py": FLASK})["raw"]
        found = taint.to_findings(raw, "es")
        assert all(f["detail"]["assessment"] == "potential" for f in found)
        assert all("mismo fichero" in f["detail"]["limits"] for f in found)
        assert all(f["rule_id"].startswith("taint.py.") for f in found)

    def test_other_languages_are_said_not_analysed(self):
        r = taint.analyze({"main.go": "package main"})
        assert r["not_analysed"] == ["go"] and r["raw"] == []


# ---------------------------------------------------------------------------
# A4 documentation against code
# ---------------------------------------------------------------------------

class TestDocClaims:
    def test_backed_unbacked_and_contradicted(self):
        texts = {
            "README.md": "# Shop\nPasswords are hashed with bcrypt.\n"
                         "All endpoints require authentication.\nThe API is rate limited.\n"
                         "We enforce HTTPS only.\n",
            "app.py": "import bcrypt\nfrom flask_login import login_required\n"
                      "requests.get(u, verify=False)\n",
        }
        r = doc_claims.analyze(texts)
        status = {i["kind"]: i["status"] for i in r["items"]}
        assert status["password_hashing"] == "backed"
        assert status["authentication"] == "backed"
        assert status["rate_limiting"] == "unbacked"
        assert status["tls"] == "contradicted"
        assert r["lowers_confidence"] is True

    def test_spanish_documentation(self):
        r = doc_claims.analyze({"README.es.md": "Todas las rutas requieren autenticación.\n",
                                "app.py": "x = 1\n"}, "es")
        assert r["items"][0]["status"] == "unbacked"
        assert "infraestructura" in r["note"]

    def test_no_claims_no_items(self):
        r = doc_claims.analyze({"README.md": "# A library\n", "a.py": "x=1\n"})
        assert r["items"] == [] and not r["lowers_confidence"]

    def test_it_lowers_trust(self):
        audit = {"language": "en", "findings": [], "modules": [
            {"module": "claims", "status": "ok",
             "detail": {"lowers_confidence": True, "counts": {"unbacked": 2}}}]}
        assert any("documentation claims" in x for x in trust.compute(audit)["limits"])


# ---------------------------------------------------------------------------
# C23 dead code
# ---------------------------------------------------------------------------

class TestDeadCode:
    def test_functions_files_and_blueprints(self):
        texts = {
            "app/main.py": "from app.helpers import used\nfrom flask import Blueprint\n"
                           "admin = Blueprint('admin', __name__)\n"
                           "def run():\n    used()\n",
            "app/helpers.py": "def used():\n    pass\n\ndef forgotten():\n    pass\n",
            "app/orphan_module.py": "def lonely():\n    pass\n",
            "web/util.js": "export function unusedThing() {}\nexport function shared() {}\n",
            "web/index.js": "import { shared } from './util'\nshared()\n",
        }
        r = deadcode.analyze(texts)
        got = {(i["kind"], i["name"]) for i in r["items"]}
        assert ("function", "forgotten") in got
        assert ("file", "orphan_module") in got
        assert ("blueprint", "admin") in got
        assert ("export", "unusedThing") in got
        assert ("function", "used") not in got and ("export", "shared") not in got

    def test_framework_entry_points_are_kept(self):
        texts = {"app.py": "@app.route('/x')\ndef handler_only_flask_calls():\n    pass\n"
                           "def main():\n    pass\n"}
        assert deadcode.analyze(texts)["items"] == []


# ---------------------------------------------------------------------------
# B10 more ecosystems and maintenance
# ---------------------------------------------------------------------------

class TestMoreEcosystems:
    def test_cargo_gem_composer_maven(self):
        texts = {
            "Cargo.lock": '[[package]]\nname = "serde"\nversion = "1.0.1"\n'
                          'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
            "Cargo.toml": '[dependencies]\nserde = "=1.0.1"\nfoo = { git = "https://x/y" }\n',
            "Gemfile.lock": "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (2.2.3)\n\n",
            "composer.lock": '{"packages":[{"name":"monolog/monolog","version":"v2.3.0"}]}',
            "pom.xml": "<dependency><groupId>org.x</groupId><artifactId>y</artifactId>"
                       "<version>1.2</version></dependency>"
                       "<dependency><groupId>a</groupId><artifactId>b</artifactId>"
                       "<version>${v}</version></dependency>",
        }
        inv = deps.inventory(texts)
        purls = {c["purl"] for c in inv["components"]}
        assert {"pkg:cargo/serde@1.0.1", "pkg:gem/rack@2.2.3",
                "pkg:composer/monolog/monolog@2.3.0", "pkg:maven/org.x/y@1.2"} <= purls
        # A version from a property is left out, not guessed.
        assert any(c["purl"] == "pkg:maven/a/b" and c["version"] is None
                   for c in inv["components"])
        assert [s["rule"] for s in inv["signals"]] == ["dep.url_source"]

    def test_abandoned_is_opt_in(self, monkeypatch):
        monkeypatch.delenv("SECAUDIT_ABANDONED_CHECK", raising=False)
        assert deps.abandoned_enabled() is False
        monkeypatch.setenv("SECAUDIT_ABANDONED_CHECK", "1")
        assert deps.abandoned_enabled() is True

    def test_stale_and_deprecated(self):
        comps = [
            {"ecosystem": "PyPI", "name": "oldpkg", "version": "1", "direct": True,
             "line": 1, "manifest": "requirements.txt"},
            {"ecosystem": "npm", "name": "left-pad", "version": "1.3.0", "direct": True,
             "line": 2, "manifest": "package.json"},
            {"ecosystem": "npm", "name": "trans", "version": "1", "direct": False,
             "line": None, "manifest": "package-lock.json"},
        ]
        asked = []

        def fake(url, accept="application/json"):
            asked.append(url)
            if "pypi" in url:
                return {"urls": [{"upload_time_iso_8601": "2019-01-01T00:00:00Z"}],
                        "info": {"version": "1"}}
            return {"modified": "2026-10-01T00:00:00Z", "dist-tags": {"latest": "1.3.0"},
                    "versions": {"1.3.0": {"deprecated": "use String.prototype.padStart"}}}

        now = datetime(2026, 11, 2, tzinfo=timezone.utc)
        r = deps.query_abandoned(comps, fake, now)
        assert r["asked"] == 2 and r["stale"] == 1 and r["deprecated"] == 1
        assert len(asked) == 2                      # transitive ones are not asked
        found = deps.maintenance_findings(comps, "en", {"requirements.txt": "oldpkg==1",
                                                        "package.json": '{\n "left-pad": "1"'})
        rules = {f["rule_id"] for f in found}
        assert rules == {"dep.stale", "dep.deprecated"}
        assert all(f["verification_status"] == "verified" for f in found)

    def test_a_registry_error_is_counted_not_guessed(self):
        comps = [{"ecosystem": "PyPI", "name": "x", "version": "1", "direct": True,
                  "line": 1, "manifest": "r.txt"}]

        def boom(url, accept=""):
            raise OSError("offline")
        r = deps.query_abandoned(comps, boom)
        assert r["errors"] == 1 and "maintenance" not in comps[0]


# ---------------------------------------------------------------------------
# B21 / C27 surface: validation and services
# ---------------------------------------------------------------------------

class TestSurfaceAdditions:
    def test_validation_seen_or_not(self):
        texts = {"app.py": "from flask import Flask, request\napp = Flask(__name__)\n"
                           "@app.post('/a')\ndef a():\n    return request.json\n"
                           "@app.post('/b')\ndef b(item: Item):\n    return item\n"}
        items = {i["path"]: i for i in surface.analyze(texts)["items"]}
        assert items["/a"]["validation"] == "none_seen"
        assert items["/b"]["validation"] == "declared"

    def test_services(self):
        texts = {
            "docker-compose.yml": "services:\n  web:\n    image: acme/web:1\n    ports:\n"
                                  "      - \"8080:80\"\n  db:\n    image: postgres\n"
                                  "    privileged: true\n",
            "app.py": "import boto3\nURL = 'https://api.stripe.com/v1/charges'\n"
                      "r = redis.Redis()\n",
        }
        s = surface.analyze(texts)["services"]
        names = {c["name"]: c for c in s["containers"]}
        assert names["web"]["published_ports"] == ["8080:80"]
        assert names["db"]["privileged"] is True
        assert [h["host"] for h in s["external_hosts"]] == ["api.stripe.com"]
        assert {d["kind"] for d in s["datastores"]} == {"redis"}
        assert {d["kind"] for d in s["third_party"]} >= {"aws", "stripe"}


# ---------------------------------------------------------------------------
# D: MCP in attack paths, decoys and the taxonomy
# ---------------------------------------------------------------------------

def mcp_finding(fid, rule, owasp, assessment="potential"):
    return {"id": fid, "category": "mcp", "rule_id": rule, "verification_status": "verified",
            "epistemic_status": "exists", "assessment": assessment,
            "file": "server.py", "line": fid, "title": rule,
            "detail": {"owasp_mcp": owasp}}


class TestMcpInAttackPaths:
    def test_an_open_server_with_a_shell_tool_is_a_path_to_code_execution(self):
        findings = [mcp_finding(1, "mcp07.network_server_without_auth", "MCP07"),
                    mcp_finding(2, "mcp05.exec_in_tool", "MCP05", "confirmed")]
        r = attacker.analyze(findings, [], [], {}, [{"id": 1, "kind": "code_execution"}])
        anon = [p for p in r["paths"] if p["persona"] == "anonymous"]
        assert anon, r["paths"]
        used = {r["edges"][i].finding_id for i in anon[0]["edges"]} - {None}
        assert used == {1, 2}
        kinds = {(r["edges"][i].explanation or {}).get("kind") for i in anon[0]["edges"]}
        assert "mcp:MCP05" in kinds and "mcp:MCP07" in kinds
        # The confirmed step is solid; the inferred one is tentative.
        by_finding = {r["edges"][i].finding_id: r["edges"][i] for i in anon[0]["edges"]}
        assert by_finding[2].tentative is False and by_finding[1].tentative is True

    def test_a_discarded_mcp_finding_is_no_step(self):
        f = mcp_finding(1, "mcp05.exec_in_tool", "MCP05")
        f["assessment"] = "discarded"
        assert attacker.mcp_edges(f) == []


class TestMcpDecoy:
    def test_the_mcp_tool_decoy_is_planted_and_located(self):
        rng = random.Random(7)
        text = ("import os\nfrom mcp.server.fastmcp import FastMCP\n\n"
                "def existing():\n    return 1\n")
        planted, fn = canary.plant(text, "tools.py", "mcp_tool_exec", rng, set())
        start, end = canary.locate(planted, "tools.py", fn, "mcp_tool_exec")
        lines = planted.split("\n")
        assert lines[start - 1].lstrip().startswith("@") and ".tool()" in lines[start - 1]
        assert "shell=True" in "\n".join(lines[start - 1:end])
        decoy = canary.Decoy("tools.py", "mcp_tool_exec", fn, start, end)
        assert canary.found(decoy, [{"file": "tools.py", "line": start + 3}])
        # The auditor's own MCP rules see it too.
        r = mcp_audit.analyze({"tools.py": planted})
        assert any(f["rule_id"] == "mcp05.exec_in_tool" for f in r["findings"])


OFFICIAL = "".join(f"<li>MCP{n:02d}:2025 - {name}</li>" for n, name in [
    (1, "Token Mismanagement &amp; Secret Exposure"), (2, "Privilege Escalation via Scope Creep"),
    (3, "Tool Poisoning"), (4, "Software Supply Chain Attacks &amp; Dependency Tampering"),
    (5, "Command Injection &amp; Execution"), (6, "Prompt Injection via Contextual Payloads"),
    (7, "Insufficient Authentication &amp; Authorization"), (8, "Lack of Audit and Telemetry"),
    (9, "Shadow MCP Servers"), (10, "Context Injection &amp; Over-Sharing")])


class TestTaxonomyCheck:
    def test_matches_the_official_names(self):
        r = mcp_audit.check_taxonomy(lambda url: OFFICIAL)
        assert r["checked"] and r["matches"] and r["categories_found"] == 10

    def test_a_renamed_category_is_reported(self):
        page = OFFICIAL.replace("Tool Poisoning", "Tool Shadowing")
        r = mcp_audit.check_taxonomy(lambda url: page)
        assert not r["matches"]
        assert r["differences"] == [{"id": "MCP03", "ours": "Tool Poisoning",
                                     "official": "Tool Shadowing"}]

    def test_no_network_is_said(self):
        def offline(url):
            raise OSError("no route")
        r = mcp_audit.check_taxonomy(offline)
        assert r["checked"] is False and "no route" in r["error"]


# ---------------------------------------------------------------------------
# B15 PDF
# ---------------------------------------------------------------------------

class TestPdf:
    def test_a_well_formed_pdf(self):
        audit = {"repo_url": "https://github.com/a/b", "commit_sha": "c" * 40,
                 "language": "es",
                 "findings": [{"title": "Inyección (SQL) \\ ñ", "severity": "high",
                               "file": "a.py", "line": 3, "code_snippet": 'q = "(" + x',
                               "verification_status": "verified",
                               "epistemic_status": "exists", "category": "injection"}]
                 * 80}
        body = pdf.to_pdf(audit, {"coverage": {"score": 0.5, "band": "medium", "reasons": []},
                                  "limits": ["no es garantía"]}, "0.3.0")
        assert body.startswith(b"%PDF-1.4") and body.rstrip().endswith(b"%%EOF")
        # The xref table points at every object.
        xref = int(body.rsplit(b"startxref\n", 1)[1].split(b"\n")[0])
        assert body[xref:xref + 4] == b"xref"
        count = int(body[xref:].split(b"\n")[1].split()[1])
        offsets = [int(l[:10]) for l in body[xref:].split(b"\n")[3:2 + count]]
        for n, off in enumerate(offsets, 1):
            assert body[off:].startswith(f"{n} 0 obj".encode())
        assert b"/Count " in body and body.count(b"/Type /Page ") > 1
        # Parentheses and backslashes are escaped, accents kept in WinAnsi.
        assert b"Inyecci\xf3n \\(SQL\\) \\\\ \xf1" in body
        assert b"/JavaScript" not in body and b"/OpenAction" not in body


# ---------------------------------------------------------------------------
# B19 the isolated scanner process
# ---------------------------------------------------------------------------

class TestScanProcess:
    def test_every_scanner_answers_from_a_child_process(self, tmp_path):
        from web import scanproc
        (tmp_path / "app.py").write_text(FLASK)
        (tmp_path / "README.md").write_text("Passwords are hashed with bcrypt.\n")
        git(tmp_path, "init", "-q")
        git(tmp_path, "add", ".")
        git(tmp_path, "commit", "-qm", "x")
        r = scanproc.run_scan(tmp_path, "en", 10)
        for key in ("secrets", "dependencies", "mcp", "surface", "taint", "claims",
                    "deadcode"):
            assert r[key] is not None, (key, r["errors"])
        assert r["errors"] == {}
        assert any(f["rule_id"] == "taint.py.sql" for f in r["taint"]["findings"])

    def test_the_child_gets_no_secret_from_the_environment(self, tmp_path, monkeypatch):
        from web import scanproc
        seen = {}

        def fake_run(cmd, **kw):
            seen.update(kw)

            class R:
                returncode, stdout, stderr = 0, "{}", ""
            return R()
        monkeypatch.setenv("SECAUDIT_SECRET_KEY", "master")
        monkeypatch.setenv("DATABASE_URL", "postgres://u:p@db/x")
        monkeypatch.setattr(scanproc.subprocess, "run", fake_run)
        scanproc.run_scan(tmp_path, "en", 10)
        assert "SECAUDIT_SECRET_KEY" not in seen["env"] and "DATABASE_URL" not in seen["env"]
        assert seen["cwd"] == scanproc.ROOT and seen["timeout"] >= 30

    def test_a_crash_or_a_timeout_is_a_scan_error(self, tmp_path, monkeypatch):
        from web import scanproc

        def slow(cmd, **kw):
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])
        monkeypatch.setattr(scanproc.subprocess, "run", slow)
        with pytest.raises(scanproc.ScanError, match="longer than"):
            scanproc.run_scan(tmp_path, "en", 10)


# ---------------------------------------------------------------------------
# C29 What If: the patch itself
# ---------------------------------------------------------------------------

class TestWhatIfPatchChecks:
    @pytest.mark.parametrize("patch, message", [
        ("", "empty"),
        ("hello", "not a unified diff"),
        ("--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-a\n+b\n", "outside"),
        ("--- a/.git/config\n+++ b/.git/config\n@@ -1 +1 @@\n-a\n+b\n", "outside"),
        ("diff --git a/l b/l\nnew file mode 120000\n--- /dev/null\n+++ b/l\n@@ -0,0 +1 @@\n+/etc\n",
         "symlinks"),
        ("--- a/x\n+++ b/x\nGIT binary patch\n", "binary"),
    ])
    def test_refused(self, patch, message):
        from web import whatif
        with pytest.raises(whatif.WhatIfError, match=message):
            whatif.check_patch(patch)


# ---------------------------------------------------------------------------
# C34 twin
# ---------------------------------------------------------------------------

class TestTwin:
    def test_nodes_links_and_unknowns(self):
        audit = {
            "commit_sha": "c" * 40,
            "modules": [{"module": "surface", "detail": {
                "items": [{"kind": "endpoint", "file": "app/views.py", "line": 3,
                           "method": "GET", "path": "/u", "auth": "none_seen",
                           "validation": "none_seen", "touches": ["database"],
                           "confidence": "high"}],
                "not_inventoried": ["go"],
                "services": {"containers": [{"name": "db", "file": "compose.yml",
                                             "image": "postgres", "published_ports": [],
                                             "privileged": True, "host_network": False}],
                             "datastores": [], "external_hosts": [], "third_party": []}}},
                {"module": "dependencies", "detail": {"osv": {"queried": False}}}],
            "components": [{"ecosystem": "PyPI", "name": "flask", "direct": True,
                            "manifest": "requirements.txt", "vulns": None}],
            "findings": [{"id": 9, "title": "SQLi", "file": "app/views.py", "line": 4,
                          "verification_status": "verified", "assessment": "potential",
                          "severity": "high"}],
            "attack": {"nodes": [], "edges": [], "paths": []},
        }
        tw = twin.build(audit, [{"file": "app/views.py", "audited": True},
                                {"file": "app/big.py", "audited": False}])
        by_id = {n["id"]: n for n in tw["nodes"]}
        entry = by_id["entry:0"]
        assert "no authentication seen on this entry" in entry["uncertainty"]
        assert "no input validation seen" in entry["uncertainty"]
        assert "1 file(s) not fully read" in by_id["area:app"]["uncertainty"]
        assert any("OSV off" in u for u in by_id["dep:PyPI:flask"]["uncertainty"])
        assert "runs privileged" in by_id["service:db"]["uncertainty"]
        assert by_id["gap:go"]["uncertainty"]
        rels = {(e["from"], e["to"], e["rel"]) for e in tw["edges"]}
        assert ("finding:9", "entry:0", "affects") in rels
        assert ("entry:0", "asset:database", "touches") in rels
        assert ("boundary:untrusted", "entry:0", "crosses") in rels
        assert "not an executable copy" in tw["note"]


# ---------------------------------------------------------------------------
# Through the app
# ---------------------------------------------------------------------------

from tests.test_web_api import (SECRET, client, clean_backend_env, deliver,  # noqa: E402,F401
                                sign_in, signed_in, stub_audit, webhook_secret)
from web import db as web_db  # noqa: E402
from web import gitclone as web_gitclone  # noqa: E402
from web import main as web_main  # noqa: E402
from web import models as web_models  # noqa: E402
from web import whatif as web_whatif  # noqa: E402


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "shop"
    r.mkdir()
    (r / "app.py").write_text(
        'API_KEY = "sk-test-000000000000"\n\n'
        'def get_user(cur, name):\n'
        '    return cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n')
    (r / "README.md").write_text("All endpoints require authentication.\n")
    (r / "tests").mkdir()
    (r / "tests" / "test_app.py").write_text("def test_get_user():\n    pass\n")
    (r / ".mcp.json").write_text(json.dumps({"mcpServers": {"gh": {
        "command": "npx", "args": ["-y", "@acme/gh-mcp"], "env": {"GITHUB_TOKEN": GH}}}}))
    git(r, "init", "-q")
    git(r, "add", ".")
    git(r, "commit", "-qm", "init")
    return r


@pytest.fixture
def from_repo(monkeypatch, repo):
    def fake_clone(url, dest, timeout=120, branch=None):
        return web_gitclone.clone_repo(f"file://{repo}", dest)

    def fake_at_commit(url, dest, sha, timeout=120):
        web_gitclone.clone_repo(f"file://{repo}", dest)
        subprocess.run(["git", "-C", str(dest), "checkout", "-q", "--detach", sha],
                       check=True, capture_output=True)
        return sha
    monkeypatch.setattr(web_main, "clone_repo", fake_clone)
    monkeypatch.setattr(web_main, "clone_at_commit", fake_at_commit)
    monkeypatch.setattr(web_whatif, "clone_at_commit", fake_at_commit)
    return repo


def run_audit(client, **body):
    r = client.post("/api/audits", json={"repo_url": "https://github.com/acme/shop", **body})
    assert r.status_code == 202, r.text
    audit = client.get(f"/api/audits/{r.json()['id']}").json()
    assert audit["status"] == "done", audit.get("error")
    return audit


class TestThroughTheAppB:
    def test_new_modules_run_isolated_and_report(self, client, signed_in, stub_audit,
                                                 from_repo):
        audit = run_audit(client)
        modules = {m["module"]: m for m in audit["modules"]}
        for name in ("secrets", "dependencies", "mcp", "taint", "surface", "claims",
                     "deadcode"):
            assert modules[name]["status"] == "ok", (name, modules[name])
            assert modules[name]["detail"]["isolated"] is True
        claims = modules["claims"]["detail"]
        assert claims["items"][0]["kind"] == "authentication"
        assert claims["items"][0]["status"] == "unbacked"
        tr = client.get(f"/api/audits/{audit['id']}/trust").json()
        assert any("documentation claims" in x for x in tr["limits"])

    def test_pdf_twin_blue_team_and_no_leak(self, client, signed_in, stub_audit, from_repo):
        audit = run_audit(client)
        aid = audit["id"]
        r = client.get(f"/api/audits/{aid}/report.pdf")
        assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
        assert r.content.startswith(b"%PDF")
        tw = client.get(f"/api/audits/{aid}/twin").json()
        assert tw["counts"].get("finding") and tw["counts"].get("area")
        f = next(x for x in audit["findings"] if x["category"] == "injection")
        bt = client.get(f"/api/audits/{aid}/findings/{f['id']}/blue-team").json()
        assert bt["validated"] is False and "NOT VALIDATED" in bt["label"]
        assert GH.encode() not in r.content and GH not in json.dumps(tw)

    def test_what_if_measures_a_fix_without_touching_the_original(
            self, client, signed_in, stub_audit, from_repo):
        audit = run_audit(client)
        sqli = next(f for f in audit["findings"] if f["category"] == "injection"
                    and not f.get("source"))
        app = from_repo / "app.py"
        before = app.read_text()
        app.write_text(before.replace('\'" + name + "\'")', '?", (name,))'))
        patch = git(from_repo, "diff")
        git(from_repo, "checkout", "--", "app.py")
        head = git(from_repo, "rev-parse", "HEAD")
        r = client.post(f"/api/audits/{audit['id']}/what-if",
                        json={"finding_id": sqli["id"], "patch": patch})
        assert r.status_code == 200, r.text
        w = r.json()
        assert w["status"] == "ok", w["result"]
        res = w["result"]
        assert res["cited_code_still_present"] is False
        assert res["verdict"] == "promising"
        assert res["tests"]["run"] is False and res["tests"]["candidates"] == [
            "tests/test_app.py"]
        assert res["original_untouched"] is True
        # The original repository is exactly as it was.
        assert app.read_text() == before and git(from_repo, "rev-parse", "HEAD") == head
        assert git(from_repo, "status", "--porcelain") == ""
        listed = client.get(f"/api/audits/{audit['id']}/what-if").json()
        assert listed[0]["id"] == w["id"]

    def test_what_if_refuses_a_patch_outside_the_repository(self, client, signed_in,
                                                            stub_audit, from_repo):
        audit = run_audit(client)
        fid = audit["findings"][0]["id"]
        r = client.post(f"/api/audits/{audit['id']}/what-if", json={
            "finding_id": fid,
            "patch": "--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n"})
        assert r.status_code == 400

    def test_what_if_reports_a_patch_that_weakens_a_control(self, client, signed_in,
                                                            stub_audit, from_repo):
        audit = run_audit(client)
        sqli = next(f for f in audit["findings"] if f["category"] == "injection")
        (from_repo / "app.py").write_text((from_repo / "app.py").read_text()
                                          + "\nCORS_ALLOW_ALL_ORIGINS = True\n")
        patch = git(from_repo, "diff")
        git(from_repo, "checkout", "--", "app.py")
        w = client.post(f"/api/audits/{audit['id']}/what-if",
                        json={"finding_id": sqli["id"], "patch": patch}).json()
        res = w["result"]
        assert res["cited_code_still_present"] is True
        assert res["verdict"] == "introduces_issues"
        assert res["drift"][0]["rule"] == "cors_any_origin"

    def test_replay_and_reproducibility(self, client, signed_in, stub_audit, from_repo):
        audit = run_audit(client)
        (from_repo / "app.py").write_text("x = 1\n")
        git(from_repo, "commit", "-qam", "moved on")
        r = client.post(f"/api/audits/{audit['id']}/replay")
        assert r.status_code == 202
        replay = client.get(f"/api/audits/{r.json()['id']}").json()
        assert replay["status"] == "done", replay.get("error")
        # The same commit, not the branch tip.
        assert replay["commit_sha"] == audit["commit_sha"]
        assert replay["replay_of"] == audit["id"] and replay["trigger"] == "replay"
        rep = client.get(f"/api/audits/{replay['id']}/reproducibility").json()
        assert rep["same_commit"] and rep["rules_agree"] is True
        assert rep["agreement"] == 1.0
        diff = client.get(f"/api/audits/{replay['id']}/diff").json()
        assert diff["previous_audit"] == audit["id"] and diff["new"] == []
        assert client.get(f"/api/audits/{audit['id']}/reproducibility").status_code == 404

    def test_compare_with_a_chosen_base_and_an_exact_commit(self, client, signed_in,
                                                            stub_audit, from_repo):
        first = git(from_repo, "rev-parse", "HEAD").strip()
        (from_repo / "app.py").write_text((from_repo / "app.py").read_text()
                                          + "\nDEBUG = True\n")
        git(from_repo, "commit", "-qam", "debug on")
        second = git(from_repo, "rev-parse", "HEAD").strip()
        audit = run_audit(client, base_ref=first, commit=second)
        assert audit["commit_sha"] == second and audit["base_ref"] == first
        drift_run = next(m for m in audit["modules"] if m["module"] == "drift")
        assert drift_run["detail"]["compared"] is True
        assert any(d["rule"] == "debug_on" for d in drift_run["detail"]["drift"])

    def test_bad_refs_are_refused(self, client, signed_in):
        for body in ({"base_ref": "main; rm -rf /"}, {"commit": "abc"},
                     {"branch": "--upload-pack=x"}):
            r = client.post("/api/audits", json={"repo_url": "https://github.com/acme/x",
                                                 **body})
            assert r.status_code == 400, body


class TestPullRequestWebhook:
    def payload(self, head, base, owner="acme", action="opened"):
        return {"action": action, "number": 7, "pull_request": {
            "number": 7,
            "head": {"sha": head, "ref": "feature",
                     "repo": {"clone_url": f"https://github.com/{owner}/shop.git"}},
            "base": {"sha": base, "ref": "main"}}}

    def test_a_pull_request_is_audited_at_its_head_against_its_base(
            self, client, webhook_secret, stub_audit, from_repo):
        base = git(from_repo, "rev-parse", "HEAD").strip()
        (from_repo / "app.py").write_text((from_repo / "app.py").read_text()
                                          + "\nCORS_ALLOW_ALL_ORIGINS = True\n")
        git(from_repo, "commit", "-qam", "open cors")
        head = git(from_repo, "rev-parse", "HEAD").strip()
        r = deliver(client, self.payload(head, base), event="pull_request")
        assert r.status_code == 202, r.text
        session = web_db.get_session()
        audit = session.get(web_models.Audit, r.json()["id"])
        assert audit.status == "done", audit.error
        assert (audit.pr_number, audit.base_ref, audit.commit_sha) == (7, base, head)
        drift_run = next(m for m in audit.module_runs if m.module == "drift")
        assert drift_run.detail["pr_number"] == 7
        assert [d["rule"] for d in drift_run.detail["drift"]] == ["cors_any_origin"]
        session.close()

    def test_a_fork_outside_the_allowlist_is_ignored(self, client, webhook_secret,
                                                     monkeypatch):
        monkeypatch.setenv(web_gitclone.ALLOWED_OWNERS_ENV, "acme")
        r = deliver(client, self.payload("a" * 40, "b" * 40, owner="evil"),
                    event="pull_request")
        assert r.status_code == 200 and r.json()["status"] == "ignored"

    def test_closing_a_pull_request_audits_nothing(self, client, webhook_secret):
        r = deliver(client, self.payload("a" * 40, "b" * 40, action="closed"),
                    event="pull_request")
        assert r.status_code == 200 and r.json()["status"] == "ignored"


# ---------------------------------------------------------------------------
# C33 the labelled corpus is actually run
# ---------------------------------------------------------------------------

class TestBenchmarkCorpus:
    def test_the_corpus_runs_and_is_scored(self):
        from pathlib import Path
        from analysis import benchmark
        root = Path(__file__).resolve().parent.parent / "benchmark"
        r = benchmark.run_corpus(root)
        total = r["total"]
        assert total["labels"] >= benchmark.SMALL_SAMPLE and total["sample_note"] is None
        assert {c["kind"] for c in r["cases"]} == {"vulnerable", "clean"}
        assert all(c["deceptions"] for c in r["cases"] if c["kind"] == "clean")
        assert total["true_positives"] + total["false_negatives"] == total["labels"]
        assert r["measured"].startswith("deterministic scanners only")

    def test_no_credential_shaped_string_is_stored_in_the_corpus(self):
        from pathlib import Path
        from analysis import secrets_scan
        root = Path(__file__).resolve().parent.parent / "benchmark" / "corpus"
        texts = {str(p.relative_to(root)): p.read_text() for p in root.rglob("*")
                 if p.is_file()}
        found, _ = secrets_scan.scan(texts, "en")
        assert [f for f in found if f["rule_id"] != "secret.assigned_secret"] == []


class TestSignalEvidence:
    def test_a_manifest_signal_cites_the_line_as_written(self, tmp_path):
        from analysis import evidence
        texts = {"Cargo.toml": '[dependencies]\npatched = { git = "https://x/y" }\n',
                 "package-lock.json": '{"packages": {"node_modules/a": {"version": "1",\n'
                                      '"resolved": "http://registry.npmjs.org/a/-/a-1.tgz"}}}'}
        for k, v in texts.items():
            (tmp_path / k).write_text(v)
        inv = deps.inventory(texts)
        found = deps.signal_findings(inv["signals"], "en", texts)
        evidence.verify_findings(tmp_path, found, None)
        assert {f["rule_id"] for f in found} == {"dep.url_source", "dep.insecure_resolved"}
        assert all(f["verification_status"] == "verified" for f in found), found


# ---------------------------------------------------------------------------
# Practice 3, part 3: Gradle, Maven properties, inter-procedural taint
# ---------------------------------------------------------------------------

POM = """<project><parent><version>9.9</version></parent><version>2.0.0</version>
<properties><spring.version>5.3.1</spring.version><alias>${spring.version}</alias>
<loop>${loop}</loop></properties>
<dependencyManagement><dependencies><dependency><groupId>m</groupId>
<artifactId>n</artifactId><version>3.1</version></dependency></dependencies>
</dependencyManagement>
<dependencies>
<dependency><groupId>org.springframework</groupId><artifactId>core</artifactId>
<version>${spring.version}</version></dependency>
<dependency><groupId>x</groupId><artifactId>j</artifactId><version>${alias}</version></dependency>
<dependency><groupId>me</groupId><artifactId>self</artifactId><version>${project.version}</version></dependency>
<dependency><groupId>m</groupId><artifactId>n</artifactId></dependency>
<dependency><groupId>u</groupId><artifactId>k</artifactId><version>${from.parent}</version></dependency>
<dependency><groupId>c</groupId><artifactId>c</artifactId><version>${loop}</version></dependency>
</dependencies></project>"""

GRADLE = '''def okVersion = "4.12.0"
val kotlinV = "1.9.0"
repositories { maven { url "http://repo.corp/maven" } }
dependencies {
  implementation "com.squareup.okhttp3:okhttp:$okVersion"
  implementation("org.jetbrains.kotlin:kotlin-stdlib:${kotlinV}")
  testImplementation 'junit:junit:4.13.2'
  api group: 'com.google.guava', name: 'guava', version: '32.1.2-jre'
  implementation 'org.x:dynamic:1.+'
  implementation "org.y:unknown:$elsewhere"
}
'''


class TestJvmManifests:
    def test_maven_properties_are_resolved_only_when_literal(self):
        got = {c["name"]: c["version"] for c in deps.parse_pom("pom.xml", POM)}
        assert got == {"org.springframework:core": "5.3.1", "x:j": "5.3.1",
                       "me:self": "2.0.0", "m:n": "3.1", "u:k": None, "c:c": None}

    def test_gradle_is_read_not_run(self):
        comps, signals = deps.parse_gradle("build.gradle", GRADLE)
        got = {c["name"]: (c["version"], c["scope"]) for c in comps}
        assert got["com.squareup.okhttp3:okhttp"] == ("4.12.0", "runtime")
        assert got["org.jetbrains.kotlin:kotlin-stdlib"] == ("1.9.0", "runtime")
        assert got["junit:junit"] == ("4.13.2", "dev")
        assert got["com.google.guava:guava"] == ("32.1.2-jre", "runtime")
        # A dynamic or unknown version is left out, not guessed.
        assert got["org.x:dynamic"][0] is None and got["org.y:unknown"][0] is None
        assert [s["rule"] for s in signals] == ["dep.insecure_resolved"]

    def test_version_catalog_and_lockfile(self):
        catalog = ('[versions]\nktor = "2.3.4"\n[libraries]\n'
                   'ktor-core = { module = "io.ktor:ktor-server-core", version.ref = "ktor" }\n'
                   'plain = "a.b:c:1.0"\n')
        inv = deps.inventory({
            "gradle/libs.versions.toml": catalog,
            "gradle.lockfile": "io.ktor:ktor-server-core:2.3.4=runtimeClasspath\n"
                               "org.slf4j:slf4j-api:2.0.9=runtimeClasspath\n"
                               "junit:junit:4.13=testRuntimeClasspath\nempty=\n"})
        by = {c["purl"]: c for c in inv["components"]}
        assert by["pkg:maven/io.ktor/ktor-server-core@2.3.4"]["direct"] is True
        assert by["pkg:maven/org.slf4j/slf4j-api@2.0.9"]["direct"] is False
        assert by["pkg:maven/junit/junit@4.13"]["scope"] == "dev"
        assert "pkg:maven/a.b/c@1.0" in by


HELPERS = '''import os, subprocess
from flask import request, Flask
app = Flask(__name__)

def shell(c):
    return subprocess.check_output(c, shell=True)

def where(q):
    return "SELECT * FROM t WHERE x = '" + q + "'"

def name_param():
    return request.args.get("n")

def wrap(v):
    shell(v)

def as_int(v):
    return int(v)

@app.route("/a")
def a():
    shell(request.args["h"])

@app.route("/b")
def b(db):
    q = where(request.args["q"])
    db.execute(q)

@app.route("/c")
def c():
    os.system("echo " + name_param())

@app.route("/d")
def d():
    wrap(request.form["x"])

@app.route("/e")
def e():
    n = as_int(request.form["x"])
    shell("echo %d" % n)

@app.route("/f")
def f():
    shell("uptime")
'''


class TestInterproceduralTaint:
    def flows(self):
        return {(r["kind"], r["flow"][0]["line"], r["line"]): r
                for r in taint.analyze({"app.py": HELPERS})["raw"]}

    def test_into_and_out_of_helpers(self):
        got = self.flows()
        assert ("command", 22, 6) in got                 # a() → shell()
        assert ("sql", 26, 27) in got                    # where() returns the input
        assert ("command", 12, 31) in got                # name_param() reads it
        assert ("command", 35, 6) in got                 # d() → wrap() → shell()
        chain = got[("command", 35, 6)]["flow"]
        assert [s["step"] for s in chain] == ["source", "call", "call", "sink"]
        assert got[("command", 22, 6)]["confidence"] == "low"

    def test_sanitised_helpers_and_constants_stay_quiet(self):
        sources = {k[1] for k in self.flows()}
        assert 39 not in sources and 40 not in sources   # e(): as_int() is int()
        assert 44 not in sources                         # f(): a constant

    def test_two_callers_are_two_findings(self):
        found = taint.to_findings(taint.analyze({"app.py": HELPERS})["raw"], "en")
        anchors = [f["anchor"] for f in found if f["line"] == 6]
        assert len(anchors) == len(set(anchors)) == 2


class TestTwinSimulation:
    def inputs(self):
        return {"findings": [mcp_finding(1, "mcp07.network_server_without_auth", "MCP07"),
                             mcp_finding(2, "mcp05.exec_in_tool", "MCP05")],
                "divergences": [], "leverage": [], "agent": {"capabilities": [],
                                                              "combinations": []},
                "jewels": [{"id": 1, "kind": "code_execution"}]}

    def anon(self, rows):
        return [p for p in rows if p["persona"] == "anonymous"]

    def test_fixing_a_step_closes_the_path(self):
        r = twin.simulate(self.inputs(), fix_findings=[2])
        assert self.anon(r["closed"]) and not self.anon(r["remaining"])
        assert r["opened"] == [] and "nothing ran" in r["note"]

    def test_confirming_makes_a_hypothetical_path_solid(self):
        r = twin.simulate(self.inputs(), confirm_findings=[1, 2])
        [change] = [c for c in r["changed"] if c["persona"] == "anonymous"]
        assert change["before"]["tentative"] is True and change["after"]["tentative"] is False

    def test_the_inputs_are_not_modified(self):
        inputs = self.inputs()
        twin.simulate(inputs, fix_findings=[1], confirm_findings=[2])
        assert [f["assessment"] for f in inputs["findings"]] == ["potential", "potential"]

    def test_through_the_app(self, client, signed_in, stub_audit, from_repo):
        audit = run_audit(client)
        path = f"/api/audits/{audit['id']}/twin/simulate"
        assert client.post(path, json={}).status_code == 400
        assert client.post(path, json={"fix_findings": [999999]}).status_code == 400
        ids = [f["id"] for f in audit["findings"]]
        r = client.post(path, json={"fix_findings": ids})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["before"] - len(body["closed"]) == body["after"] - len(body["opened"])
        assert body["opened"] == [] and body["after"] <= body["before"]
        # Nothing about the audit changed.
        again = client.get(f"/api/audits/{audit['id']}").json()
        assert len(again["findings"]) == len(ids)


# ---------------------------------------------------------------------------
# JavaScript/TypeScript on a syntax tree
# ---------------------------------------------------------------------------

HARD_JS = '''const { exec } = require("child_process");
function runIt(c) {
  exec(c);
}
router.post("/contrib", function (q, s) {
  const pre = q.body.preTax;
  const total = eval(pre);
  db.collection("x").find({ $where: "this.a == " + q.body.a }, function (err, docs) {
    s.send("<b>" + pre + "</b>");
  });
  runIt("ls " + q.body.dir);
  const n = parseInt(q.body.n);
  exec("echo " + n);
  const m = /x(\\d)/.exec(q.body.s);
  el.innerHTML = q.query.html;
  const { a: alias, b } = q.body;
  exec(`cat ${alias}`);
  setTimeout(() => exec("ls"), 10);
  db.query("SELECT * FROM t WHERE id = ?", [b]);
});
'''

HARD_TS = '''import { Request, Response } from "express";
export async function handler(req: Request, res: Response): Promise<void> {
  const id: string = req.params.id as string;
  await prisma.$queryRawUnsafe(`SELECT * FROM t WHERE id = ${id}`);
  await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`;
  res.redirect(req.query.to as string);
}
'''


@pytest.mark.skipif(not taint.taint_js.AVAILABLE, reason="tree-sitter not installed")
class TestJavaScriptTree:
    def got(self, name, text):
        return {(r["kind"], r["line"]) for r in taint.analyze({name: text})["raw"]}

    def test_closures_helpers_nosql_and_renamed_parameters(self):
        got = self.got("app.js", HARD_JS)
        assert ("code", 7) in got                       # eval of a body field
        assert ("nosql", 8) in got                      # $where built from input
        assert ("response", 9) in got                   # closure + renamed response
        assert ("command", 3) in got                    # through the runIt() helper
        assert ("template", 15) in got                  # innerHTML assignment
        assert ("command", 17) in got                   # destructured and renamed

    def test_what_is_not_a_flow(self):
        lines = {line for _, line in self.got("app.js", HARD_JS)}
        assert 13 not in lines                          # parseInt
        assert 14 not in lines                          # RegExp#exec
        assert 18 not in lines                          # a constant command
        assert 19 not in lines                          # bound parameters

    def test_typescript(self):
        got = self.got("h.ts", HARD_TS)
        assert ("sql", 4) in got and ("redirect", 6) in got
        assert not any(line == 5 for _, line in got)   # tagged template is parameterised
        assert taint.analyze({"h.ts": HARD_TS})["js_parser"] == "tree-sitter"

    def test_without_the_parser_it_falls_back_to_patterns(self, monkeypatch):
        monkeypatch.setattr(taint.taint_js, "AVAILABLE", False)
        r = taint.analyze({"server.js": EXPRESS})
        assert r["js_parser"] == "pattern"
        assert {x["confidence"] for x in r["raw"]} == {"low"}


# ---------------------------------------------------------------------------
# Reporting back on the pull request
# ---------------------------------------------------------------------------

from web import prnotify as web_prnotify  # noqa: E402


class FakeGitHub:
    """Records the calls; answers like GitHub would."""

    def __init__(self, existing=None, fail=None):
        self.calls, self.existing, self.fail = [], existing or [], fail

    def open(self, req, timeout=None):
        method, url = req.get_method(), req.full_url
        body = json.loads(req.data) if req.data else None
        self.calls.append((method, url, body, dict(req.header_items())))
        if self.fail and self.fail in url:
            import urllib.error
            raise urllib.error.HTTPError(url, 403, "forbidden", {}, None)
        payload = self.existing if method == "GET" else {"id": 1}

        class R:
            def __enter__(s):
                return s

            def __exit__(s, *a):
                return False

            def read(s, n=-1):
                return json.dumps(payload).encode()
        return R()


DIFF = {"new": [{"title": "SQL injection in [login](http://evil) @someone", "severity": "high",
                 "assessment": "potential", "file": "app/db.py", "line": 12},
                {"title": "Discarded", "severity": "critical", "assessment": "discarded",
                 "file": "x.py", "line": 1}],
        "fixed": [{"title": "old"}], "persisting": [], "reintroduced": []}


class TestPullRequestReport:
    def test_summary_says_no_where(self):
        body, state, desc = web_prnotify.report(DIFF, [], "en", "summary",
                                                "https://s.example/#summary/a", "a" * 40,
                                                "b" * 40)
        assert web_prnotify.MARKER in body and "**1** new" in body and "**1** fixed" in body
        assert "app/db.py" not in body and "SQL injection" not in body
        assert state == "failure" and "secure" not in desc

    def test_full_lists_new_findings_defused(self):
        body, state, _ = web_prnotify.report(DIFF, [], "es", "full", None, "a" * 40, None)
        assert "app/db.py:12" in body and "Discarded" not in body
        assert "](http" not in body and "@someone" not in body     # no link, no mention
        assert "```" not in body

    def test_no_new_high_and_no_drift_succeeds(self):
        quiet = {"new": [], "fixed": [], "persisting": [], "reintroduced": []}
        _, state, desc = web_prnotify.report(quiet, [], "en", "summary", None, "a" * 40, None)
        assert state == "success" and "no new high" in desc
        _, state, _ = web_prnotify.report(quiet, [{"rule": "cors_any_origin"}], "en",
                                          "summary", None, "a" * 40, None)
        assert state == "failure"

    def test_off_unless_both_mode_and_token(self, monkeypatch):
        monkeypatch.delenv(web_prnotify.MODE_ENV, raising=False)
        monkeypatch.setenv(web_prnotify.TOKEN_ENV, "t")
        assert not web_prnotify.enabled()
        monkeypatch.setenv(web_prnotify.MODE_ENV, "summary")
        monkeypatch.delenv(web_prnotify.TOKEN_ENV)
        assert not web_prnotify.enabled()

    def test_an_existing_comment_is_edited_not_duplicated(self, monkeypatch):
        monkeypatch.setenv(web_prnotify.MODE_ENV, "summary")
        monkeypatch.setenv(web_prnotify.TOKEN_ENV, "write-token")
        gh = FakeGitHub(existing=[{"id": 5, "body": "hi"},
                                  {"id": 9, "body": f"{web_prnotify.MARKER}\nold"}])
        r = web_prnotify.notify("acme/shop", 7, "a" * 40, DIFF, [], "en", None, None, gh)
        methods = [(m, u.split("/repos/acme/shop")[1]) for m, u, _, _ in gh.calls]
        assert methods == [("GET", "/issues/7/comments?per_page=100&page=1"),
                           ("PATCH", "/issues/comments/9"),
                           ("POST", "/statuses/" + "a" * 40)]
        assert r["comment"] == "updated" and r["state"] == "failure"
        assert gh.calls[-1][2]["context"] == "secaudit"
        assert all(h.get("Authorization") == "Bearer write-token" for *_, h in gh.calls)

    def test_a_bad_repository_name_is_never_called(self, monkeypatch):
        monkeypatch.setenv(web_prnotify.MODE_ENV, "full")
        monkeypatch.setenv(web_prnotify.TOKEN_ENV, "t")
        gh = FakeGitHub()
        r = web_prnotify.notify("../../user", 7, "a" * 40, DIFF, [], "en", None, None, gh)
        assert r["posted"] is False and gh.calls == []

    def test_through_the_webhook(self, client, webhook_secret, stub_audit, from_repo,
                                 monkeypatch):
        monkeypatch.setenv(web_prnotify.MODE_ENV, "summary")
        monkeypatch.setenv(web_prnotify.TOKEN_ENV, "write-token")
        monkeypatch.setenv("SECAUDIT_PUBLIC_URL", "https://secaudit.example")
        gh = FakeGitHub()
        real = web_prnotify.Writer.__init__
        monkeypatch.setattr(web_prnotify.Writer, "__init__",
                            lambda self, repo, token, opener=None: real(self, repo, token, gh))
        base = git(from_repo, "rev-parse", "HEAD").strip()
        (from_repo / "app.py").write_text((from_repo / "app.py").read_text()
                                          + "\nCORS_ALLOW_ALL_ORIGINS = True\n")
        git(from_repo, "commit", "-qam", "open cors")
        head = git(from_repo, "rev-parse", "HEAD").strip()
        payload = TestPullRequestWebhook().payload(head, base)
        payload["pull_request"]["base"]["repo"] = {"full_name": "acme/shop"}
        r = deliver(client, payload, event="pull_request")
        assert r.status_code == 202
        session = web_db.get_session()
        audit = session.get(web_models.Audit, r.json()["id"])
        assert audit.pr_repo == "acme/shop"
        run = next(m for m in audit.module_runs if m.module == "pr_report")
        session.close()
        assert run.status == "ok" and run.detail["state"] == "failure"   # CORS opened
        assert "write-token" not in json.dumps(run.detail)
        post = [c for c in gh.calls if c[0] == "POST" and "/issues/7/comments" in c[1]]
        assert post and f"https://secaudit.example/#summary/{audit.id}" in post[0][2]["body"]
        assert GH not in post[0][2]["body"]

    def test_a_github_failure_leaves_the_audit_done(self, client, webhook_secret, stub_audit,
                                                    from_repo, monkeypatch):
        monkeypatch.setenv(web_prnotify.MODE_ENV, "summary")
        monkeypatch.setenv(web_prnotify.TOKEN_ENV, "t")
        gh = FakeGitHub(fail="/issues/")
        real = web_prnotify.Writer.__init__
        monkeypatch.setattr(web_prnotify.Writer, "__init__",
                            lambda self, repo, token, opener=None: real(self, repo, token, gh))
        head = git(from_repo, "rev-parse", "HEAD").strip()
        payload = TestPullRequestWebhook().payload(head, head)
        payload["pull_request"]["base"]["repo"] = {"full_name": "acme/shop"}
        r = deliver(client, payload, event="pull_request")
        session = web_db.get_session()
        audit = session.get(web_models.Audit, r.json()["id"])
        run = next(m for m in audit.module_runs if m.module == "pr_report")
        assert audit.status == "done" and run.status == "error" and "403" in run.error
        session.close()


# ---------------------------------------------------------------------------
# The What If sandbox
# ---------------------------------------------------------------------------

from web import sandbox as web_sandbox  # noqa: E402


class TestSandbox:
    def test_off_by_default(self, monkeypatch):
        monkeypatch.delenv(web_sandbox.MODE_ENV, raising=False)
        assert not web_sandbox.enabled()
        assert web_sandbox.status() == {"available": False, "reason": "off"}

    def test_runner_detection(self, tmp_path):
        assert web_sandbox.detect(tmp_path) is None
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_a.py").write_text("def test_a(): pass\n")
        (tmp_path / "requirements.txt").write_text("flask\n")
        py = web_sandbox.detect(tmp_path)
        assert py["kind"] == "python" and py["install"][-2:] == ["-r", "requirements.txt"]
        (tmp_path / "package.json").write_text('{"scripts": {"test": "jest"}}')
        node = web_sandbox.detect(tmp_path)
        assert node["kind"] == "node" and "--ignore-scripts" in node["install"]

    def test_the_container_is_locked_down(self, tmp_path, monkeypatch):
        seen = []

        def fake(cmd, **kw):
            seen.append((cmd, kw))

            class R:
                returncode, stdout, stderr = 0, "1 passed", ""
            return R()
        monkeypatch.setattr(web_sandbox.subprocess, "run", fake)
        monkeypatch.setattr(web_sandbox, "docker_bin", lambda: "/usr/bin/docker")
        monkeypatch.setenv("SECAUDIT_SECRET_KEY", "master")
        web_sandbox._docker(tmp_path, "python:3.12-slim", ["python", "-m", "pytest"], False, 60)
        cmd, kw = seen[0]
        joined = " ".join(cmd)
        for flag in ("--network none", "--read-only", "--cap-drop ALL",
                     "--security-opt no-new-privileges", "--user 65534:65534",
                     "--pull=never", "--pids-limit 256"):
            assert flag in joined, flag
        assert "SECAUDIT_SECRET_KEY" not in kw["env"] and "master" not in joined
        assert f"{tmp_path}:/work:rw" in joined
        web_sandbox._docker(tmp_path, "python:3.12-slim", ["pip", "install"], True, 60)
        assert "--network bridge" in " ".join(seen[1][0])

    def test_through_the_app_it_runs_in_the_background(self, client, signed_in, stub_audit,
                                                       from_repo, monkeypatch):
        monkeypatch.setenv(web_sandbox.MODE_ENV, "docker")
        monkeypatch.setattr(web_sandbox, "docker_bin", lambda: "/usr/bin/docker")
        calls = []

        def fake_tests(before, after, scratch):
            calls.append((before.name, after.name))
            assert not (before / ".git").exists()
            return {"run": True, "kind": "python", "regressed": True,
                    "broken_by_patch": ["tests/test_app.py::test_get_user"],
                    "before": {"passed": True}, "after": {"passed": False}}
        monkeypatch.setattr(web_sandbox, "run_tests", fake_tests)
        audit = run_audit(client)
        sqli = next(f for f in audit["findings"] if f["category"] == "injection")
        app = from_repo / "app.py"
        app.write_text(app.read_text().replace('\'" + name + "\'")', '?", (name,))'))
        patch = git(from_repo, "diff")
        git(from_repo, "checkout", "--", "app.py")
        r = client.post(f"/api/audits/{audit['id']}/what-if",
                        json={"finding_id": sqli["id"], "patch": patch})
        assert r.status_code == 202 and r.json()["status"] == "running"
        done = client.get(f"/api/audits/{audit['id']}/what-if").json()[0]
        assert done["status"] == "ok" and calls == [("original", "repo")]
        assert done["result"]["verdict"] == "introduces_issues"     # a test broke
        assert done["result"]["tests"]["candidates"] == ["tests/test_app.py"]


def _docker_ready():
    try:
        return web_sandbox.docker_bin() and subprocess.run(
            ["docker", "image", "inspect", "python:3.12-slim"], capture_output=True,
            timeout=20).returncode == 0 and os.environ.get("SECAUDIT_TEST_DOCKER") == "1"
    except Exception:
        return False


@pytest.mark.skipif(not _docker_ready(),
                    reason="needs Docker, python:3.12-slim and SECAUDIT_TEST_DOCKER=1")
class TestSandboxForReal:
    def test_isolation_from_inside(self, tmp_path, monkeypatch):
        monkeypatch.setenv(web_sandbox.MODE_ENV, "docker")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_iso.py").write_text(
            "import os, socket\n"
            "def test_nobody():\n    assert os.getuid() == 65534\n"
            "def test_no_network():\n"
            "    try:\n        socket.create_connection(('1.1.1.1', 53), timeout=2)\n"
            "        assert False, 'network reachable'\n"
            "    except OSError:\n        pass\n"
            "def test_read_only():\n"
            "    try:\n        open('/etc/x', 'w')\n        assert False\n"
            "    except OSError:\n        pass\n")
        work = tmp_path.parent / f"{tmp_path.name}-work"
        web_sandbox._copy(tmp_path, work)          # as run_tests does: readable by nobody
        # No pytest in the image without the install step: run the file directly.
        r = web_sandbox._docker(work, "python:3.12-slim",
                                ["python", "-c", "import tests.test_iso as t; "
                                 "t.test_nobody(); t.test_no_network(); t.test_read_only(); "
                                 "print('isolated')"], False, 120)
        assert r["exit"] == 0 and "isolated" in r["output"], r
