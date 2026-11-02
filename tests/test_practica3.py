"""The practice-3 modules: assessment, evidence chain, trust, secrets, dependencies,
surface, drift, exports, replay, benchmark — alone and through the web app.

Credential-shaped strings are built at run time; none is written literally.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analysis import (assessment, benchmark, deps, drift, evidence_chain,  # noqa: E402
                      reports, secrets_scan, surface, trust)

AWS = "AKIA" + "2E0A8F3B244C9986"[:16]
GH = "ghp_" + "Q7w8E9r0T1y2" * 3
HIGH_ENTROPY = "f9Kx2" + "LmQ7pRt4VwZ"


def git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   cwd=repo, check=True, capture_output=True)


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------

class TestAssessment:
    @pytest.mark.parametrize("finding, expected", [
        ({"verification_status": "unverified"}, "unverifiable"),
        ({"verification_status": "verified", "epistemic_status": "refuted"}, "discarded"),
        ({"verification_status": "verified", "epistemic_status": "corroborated"}, "confirmed"),
        ({"verification_status": "verified", "epistemic_status": "reachable"}, "potential"),
        ({"verification_status": "verified", "epistemic_status": "exists"}, "potential"),
        ({"verification_status": "verified", "detail": {"assessment": "confirmed"}}, "confirmed"),
        ({"verification_status": "verified", "detail": {"needs_dynamic_test": True,
                                                        "assessment": "confirmed"}},
         "unverifiable"),
        ({"verification_status": "unverified", "detail": {"assessment": "confirmed"}},
         "unverifiable"),
    ])
    def test_one_word(self, finding, expected):
        assert assessment.assess(finding) == expected

    def test_labels_in_both_languages(self):
        assert assessment.LABELS["es"]["unverifiable"].startswith("NO VERIFICABLE")
        assert assessment.LABELS["es"]["confirmed"] == "CONFIRMADO"


# ---------------------------------------------------------------------------
# Evidence chain
# ---------------------------------------------------------------------------

FINDING = {
    "id": 7, "title": "SQL injection", "severity": "high", "category": "injection",
    "file": "app.py", "line": 4, "line_end": 4, "code_snippet": "cur.execute(q)",
    "verification_status": "verified", "epistemic_status": "corroborated",
    "hypothesis": {"source": "app.py:view — request.args", "sink": "app.py:find — execute",
                   "path": [], "preconditions": ["the route needs no login"],
                   "complete": True,
                   "attempts": [{"method": "reachability", "result": "survived",
                                 "note": "route /find", "evidence": {}},
                                {"method": "sanitizer", "result": "survived", "note": None,
                                 "evidence": {}}]},
}
AUDIT = {"id": "a1", "repo_url": "https://github.com/x/y.git", "commit_sha": "c" * 40}


class TestEvidenceChain:
    def test_every_link(self):
        c = evidence_chain.build(FINDING, AUDIT)
        assert c["anchor"]["commit_sha"] == "c" * 40
        assert c["anchor"]["snippet_sha256"] == evidence_chain.snippet_hash("cur.execute(q)")
        assert c["conclusion"]["assessment"] == "confirmed"
        assert c["conclusion"]["cwe"] == "CWE-74"
        assert c["flow"]["sink"].endswith("execute")
        assert {x["check"] for x in c["checks"]} == {"evidence", "reachability", "sanitizer"}
        statuses = {x["condition"]: x["status"] for x in c["counterfactuals"]}
        assert statuses["the route needs no login"] == "unknown"
        assert "verified" in statuses.values()
        assert any("dynamic" in u for u in c["unknowns"])

    def test_the_hash_detects_a_change_and_promises_no_more(self):
        c = evidence_chain.build(FINDING, AUDIT)
        assert c["sha256"] == evidence_chain.digest(c)
        c["anchor"]["line"] = 5
        assert c["sha256"] != evidence_chain.digest(c)
        assert "not make it true" in c["integrity_note"]

    def test_a_refuted_hypothesis_is_listed_as_discarded(self):
        f = json.loads(json.dumps(FINDING))
        f["epistemic_status"] = "refuted"
        f["hypothesis"]["attempts"][1]["result"] = "refuted"
        c = evidence_chain.build(f, AUDIT, language="es")
        assert c["conclusion"]["label"] == "DESCARTADO"
        assert c["discarded_hypotheses"][0]["by"] == "sanitizer"


# ---------------------------------------------------------------------------
# Trust
# ---------------------------------------------------------------------------

class TestTrust:
    def test_dimensions_are_kept_apart(self):
        audit = {"status": "done", "findings": [dict(FINDING)], "modules": [],
                 "coverage": {"files": 2, "audited": 1, "high_risk_not_audited": 1},
                 "canary": {"planted": 3, "found": 3, "integrity_score": 1.0},
                 "divergences": []}
        rows = [{"file": "a.py", "audited": True, "reason": "audited", "risk_tier": 3},
                {"file": ".github/workflows/x.yml", "audited": False,
                 "reason": "out of budget", "risk_tier": 1}]
        t = trust.compute(audit, rows)
        assert t["coverage"]["score"] < 0.79
        assert t["evidence"]["band"] == "high"
        assert t["adversarial"]["score"] == 1.0
        assert any("not a guarantee" in x for x in t["limits"])
        assert "overall" not in t

    def test_a_clean_audit_from_a_blind_auditor(self):
        t = trust.compute({"status": "done", "findings": [], "modules": [],
                           "canary": {"planted": 3, "found": 1}, "divergences": []})
        assert t["unreliable_clean"] is True
        assert t["evidence"]["score"] is None

    def test_spanish(self):
        t = trust.compute({"language": "es", "findings": [], "modules": []})
        assert t["limits"][0].startswith("Una auditoría sin alertas")


# ---------------------------------------------------------------------------
# Secrets and their timeline
# ---------------------------------------------------------------------------

class TestSecrets:
    def test_known_formats_confirmed_generic_potential(self):
        texts = {"config.py": f'AWS = "{AWS}"\napi_key = "{HIGH_ENTROPY}"\n'
                              f'token = request.headers.get("x")\npassword = "changeme123"\n'}
        found, summary = secrets_scan.scan(texts)
        by_kind = {f["detail"]["secret_kind"]: f for f in found}
        assert set(by_kind) == {"aws_access_key_id", "assigned_secret"}
        assert by_kind["aws_access_key_id"]["detail"]["assessment"] == "confirmed"
        assert by_kind["assigned_secret"]["detail"]["assessment"] == "potential"
        dumped = json.dumps(found)
        assert AWS not in dumped and HIGH_ENTROPY not in dumped
        assert secrets_scan.mask(AWS) in dumped

    def test_fixtures_are_downgraded(self):
        found, _ = secrets_scan.scan({"tests/test_x.py": f'K = "{GH}"\n'})
        assert found[0]["severity"] == "medium"
        assert found[0]["detail"]["assessment"] == "potential"

    def test_the_masked_snippet_still_passes_the_evidence_check(self, tmp_path):
        from analysis import evidence
        (tmp_path / "c.py").write_text(f'TOKEN = "{GH}"\n')
        found, _ = secrets_scan.scan({"c.py": (tmp_path / "c.py").read_text()})
        evidence.verify_findings(tmp_path, found, None)
        assert found[0]["verification_status"] == "verified"
        assert found[0]["line"] == 1

    def test_timeline_first_seen_and_removed(self, tmp_path):
        repo = tmp_path / "r"
        repo.mkdir()
        git(repo, "init", "-q")
        (repo / "a.py").write_text(f'K = "{AWS}"\n')
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "add")
        (repo / "a.py").write_text("K = None\n")
        git(repo, "commit", "-qam", "remove")
        t = secrets_scan.timeline(repo)
        assert t["commits_read"] == 2
        s = t["secrets"][0]
        assert s["kind"] == "aws_access_key_id"
        assert s["present_at_head"] is False
        assert s["first_commit"] and s["removed_in"]
        assert s["recommendation"] == "revoke_and_rotate"
        assert AWS not in json.dumps(t)


# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------

LOCK = {"lockfileVersion": 3, "packages": {
    "": {"name": "x"},
    "node_modules/left-pad": {"version": "1.3.0",
                              "resolved": "https://registry.npmjs.org/left-pad/-/x.tgz"},
    "node_modules/@corp/util": {"version": "2.0.0",
                                "resolved": "https://npm.corp.example/@corp/util/-/x.tgz"},
    "node_modules/debug": {"version": "4.3.4", "dev": True,
                           "resolved": "https://registry.npmjs.org/debug/-/x.tgz"}}}


class TestDependencies:
    def texts(self):
        return {"requirements.txt": "--extra-index-url https://pkgs.corp/simple\n"
                                    "flask==2.0.1\nunused-lib==1.0\n",
                "package.json": json.dumps({"dependencies": {"left-pad": "^1.3.0",
                                                             "@corp/util": "2.0.0"},
                                            "devDependencies": {"debug": "4.3.4"}}),
                "package-lock.json": json.dumps(LOCK),
                "app.py": "import flask\n", "index.js": "require('left-pad')\n"}

    def test_inventory_direct_and_transitive(self):
        inv = deps.inventory(self.texts())
        names = {(c["ecosystem"], c["name"], c["version"]): c for c in inv["components"]}
        assert names[("npm", "left-pad", "1.3.0")]["direct"] is True
        assert names[("npm", "debug", "4.3.4")]["scope"] == "dev"
        assert names[("PyPI", "flask", "2.0.1")]["purl"] == "pkg:pypi/flask@2.0.1"
        rules = {s["rule"] for s in inv["signals"]}
        assert {"dep.extra_index_url", "dep.mixed_registries"} <= rules

    def test_ghosts(self):
        t = self.texts()
        inv = deps.inventory(t)
        ghosts = {g["name"] for g in deps.ghost_dependencies(inv["components"], t,
                                                             inv["manifests"])}
        assert "unused-lib" in ghosts and "flask" not in ghosts and "left-pad" not in ghosts

    def test_cyclonedx(self):
        inv = deps.inventory(self.texts())
        bom = deps.to_cyclonedx(inv["components"], "r", "abc", "0.3.0")
        assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
        assert all(c["purl"].startswith("pkg:") for c in bom["components"])

    def test_osv_only_asks_exact_versions_and_keeps_the_references(self):
        inv = deps.inventory(self.texts())
        calls = []

        def http(method, url, body=None):
            calls.append((method, url, body))
            if url.endswith("/querybatch"):
                return {"results": [{"vulns": [{"id": "GHSA-xxxx"}]}
                                    if q["package"]["name"] == "flask" else {}
                                    for q in body["queries"]]}
            return {"id": "GHSA-xxxx", "aliases": ["CVE-2023-30861"], "summary": "cookie",
                    "database_specific": {"severity": "HIGH"}}

        result = deps.query_osv(inv["components"], http)
        asked = [q["package"]["name"] for q in calls[0][2]["queries"]]
        assert "unused-lib" in asked and "left-pad" in asked
        assert all(q["version"] for q in calls[0][2]["queries"])
        assert result["queried"] and result["vulnerable"] == 1
        found = deps.vulnerability_findings(inv["components"])
        assert found[0]["severity"] == "high"
        assert found[0]["detail"]["aliases"] == ["CVE-2023-30861"]
        assert found[0]["detail"]["references"][0].startswith("https://osv.dev/")

    def test_osv_failure_is_said(self):
        inv = deps.inventory(self.texts())

        def http(*a, **k):
            raise OSError("no network")
        r = deps.query_osv(inv["components"], http)
        assert r["queried"] is False and "no network" in r["error"]

    def test_osv_is_off_by_default(self, monkeypatch):
        monkeypatch.delenv("SECAUDIT_OSV_CHECK", raising=False)
        assert deps.osv_enabled() is False


# ---------------------------------------------------------------------------
# Surface and drift
# ---------------------------------------------------------------------------

class TestSurface:
    def test_endpoints_auth_and_boundaries(self):
        r = surface.analyze({
            "app.py": "from flask import Flask\napp = Flask(__name__)\n"
                      "@app.route('/admin', methods=['POST'])\ndef admin():\n"
                      "    return db.execute('x')\n"
                      "@app.get('/me')\n@login_required\ndef me():\n    return 1\n",
            "tests/test_app.py": "@app.get('/x')\ndef t(): pass\n",
            "main.go": "package main\n"})
        by_path = {i["path"]: i for i in r["items"]}
        assert by_path["/admin"]["auth"] == "none_seen"
        assert by_path["/admin"]["touches"] == ["database"]
        assert by_path["/me"]["auth"] == "declared"
        assert "/x" not in by_path
        assert r["not_inventoried"] == ["go"]
        assert r["boundaries"][0]["to"] == "database"


class TestDrift:
    def test_controls_weakened_between_commits(self, tmp_path):
        repo = tmp_path / "r"
        (repo / ".github/workflows").mkdir(parents=True)
        git(tmp_path, "init", "-q", "r")
        (repo / "app.py").write_text("@login_required\ndef a():\n    pass\n")
        (repo / ".github/workflows/ci.yml").write_text("on: push\n")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "1")
        base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True,
                              text=True).stdout.strip()
        (repo / "app.py").write_text("def a():\n    pass\nCORS_ALLOW_ALL_ORIGINS = True\n")
        (repo / ".github/workflows/ci.yml").write_text("on: pull_request_target\n")
        git(repo, "commit", "-qam", "2")
        r = drift.compare(repo, base)
        rules = {d["rule"] for d in r["drift"]}
        assert {"auth_check_removed", "cors_any_origin", "pull_request_target"} <= rules
        assert r["workflows_changed"] == [".github/workflows/ci.yml"]

    def test_a_moved_check_is_not_a_removal(self, tmp_path):
        repo = tmp_path / "r"
        repo.mkdir()
        git(tmp_path, "init", "-q", "r")
        (repo / "app.py").write_text("@login_required\ndef a():\n    pass\n")
        git(repo, "add", ".")
        git(repo, "commit", "-qm", "1")
        base = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True,
                              text=True).stdout.strip()
        (repo / "app.py").write_text("x = 1\n\n@login_required\ndef a():\n    return 2\n")
        git(repo, "commit", "-qam", "2")
        assert drift.compare(repo, base)["drift"] == []

    def test_an_unknown_base_is_said(self, tmp_path):
        repo = tmp_path / "r"
        repo.mkdir()
        git(tmp_path, "init", "-q", "r")
        r = drift.compare(repo, "f" * 40)
        assert r["compared"] is False and "history" in r["reason"]

    def test_finding_diff(self):
        prev = [{"fingerprint": "a"}, {"fingerprint": "b"}]
        cur = [{"fingerprint": "b"}, {"fingerprint": "c"}, {"fingerprint": "z"}]
        d = drift.finding_diff(prev, cur, {"z"})
        assert [f["fingerprint"] for f in d["new"]] == ["c"]
        assert [f["fingerprint"] for f in d["fixed"]] == ["a"]
        assert [f["fingerprint"] for f in d["reintroduced"]] == ["z"]


# ---------------------------------------------------------------------------
# Exports and benchmark
# ---------------------------------------------------------------------------

EXPORT_AUDIT = {
    **AUDIT, "status": "done", "language": "en", "branch": "main",
    "findings": [dict(FINDING, fingerprint="f1"),
                 {"id": 8, "title": "<script>alert(1)</script>", "severity": "low",
                  "category": "mcp", "file": "s.py", "line": 2,
                  "code_snippet": "</pre><img src=x onerror=alert(1)>",
                  "verification_status": "verified", "epistemic_status": "exists",
                  "fingerprint": "f2", "rule_id": "mcp08.no_logging", "source": "rule",
                  "detail": {"owasp_mcp": "MCP08", "cwe": "CWE-778",
                             "assessment": "potential", "mitigation": "log calls"}}],
    "modules": []}


class TestExports:
    def test_sarif(self):
        s = reports.to_sarif(EXPORT_AUDIT, "0.3.0")
        assert s["version"] == "2.1.0"
        run = s["runs"][0]
        assert run["versionControlProvenance"][0]["revisionId"] == "c" * 40
        r0, r1 = run["results"]
        assert r0["locations"][0]["physicalLocation"]["region"]["startLine"] == 4
        assert r0["properties"]["assessment"] == "confirmed"
        assert r1["ruleId"] == "mcp08.no_logging"
        assert "MCP08" in run["tool"]["driver"]["rules"][r1["ruleIndex"]]["properties"]["tags"]
        assert "cvss" not in json.dumps(s).lower().replace("no cvss", "")

    def test_html_escapes_everything_and_runs_no_script(self):
        t = trust.compute(EXPORT_AUDIT)
        h = reports.to_html(EXPORT_AUDIT, t, "0.3.0")
        assert "<script" not in h and "<img" not in h
        assert "&lt;script&gt;" in h
        for view in ('id="exec"', 'id="dev"', 'id="analyst"'):
            assert view in h
        assert "NOT VALIDATED" in h

    def test_json_report_carries_the_chain(self):
        r = reports.to_json_report(EXPORT_AUDIT, trust.compute(EXPORT_AUDIT), "0.3.0")
        assert r["findings"][0]["evidence_chain"]["anchor"]["commit_sha"] == "c" * 40
        assert r["findings"][1]["blue_team"]["validated"] is False

    def test_replay(self):
        m = reports.replay_manifest(EXPORT_AUDIT, {"backend": "ollama"}, {"secaudit": "x"},
                                    [{"rule_id": "r", "validated": True, "yaml": "rules: []"}],
                                    "0.3.0")
        assert m["commit_sha"] == "c" * 40 and m["not_reproducible"]
        assert len(m["immune_rules"][0]["sha256"]) == 64


class TestBenchmark:
    def test_precision_recall(self):
        labels = {"expected": [{"file": "app.py", "category": "injection"},
                               {"file": "other.py"}]}
        s = benchmark.score(labels, EXPORT_AUDIT)
        assert s["true_positives"] == 1 and s["false_negatives"] == 1
        assert s["false_positives"] == 1
        assert s["precision"] == 0.5 and s["recall"] == 0.5
        assert "small sample" in s["sample_note"]

    def test_clean_control(self):
        s = benchmark.score({"expected": [], "kind": "clean"},
                            {"findings": [{"verification_status": "unverified"}]})
        assert s["false_positives"] == 0 and s["unverifiable"] == 1
        agg = benchmark.aggregate([s])
        assert agg["clean_false_positives"] == 0


# ---------------------------------------------------------------------------
# Through the web app
# ---------------------------------------------------------------------------

from tests.test_web_api import (client, clean_backend_env, sign_in,  # noqa: E402,F401
                                stub_audit, signed_in)
from web import gitclone as web_gitclone  # noqa: E402
from web import main as web_main  # noqa: E402

MCP_CONFIG = {"mcpServers": {"gh": {"command": "npx", "args": ["-y", "@acme/gh-mcp"],
                                    "env": {"GITHUB_TOKEN": GH}}}}


@pytest.fixture
def mcp_repo(tmp_path):
    repo = tmp_path / "mcprepo"
    repo.mkdir()
    (repo / "app.py").write_text(
        'API_KEY = "sk-test-000000000000"\n\n'
        'def get_user(cur, name):\n'
        '    return cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n')
    (repo / ".mcp.json").write_text(json.dumps(MCP_CONFIG, indent=2))
    (repo / "requirements.txt").write_text("--extra-index-url https://pkgs.corp/simple\n"
                                           "flask==2.0.1\n")
    (repo / "deploy.py").write_text(f'AWS_KEY = "{AWS}"\n')
    git(repo, "init", "-q")
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "init")
    return repo


@pytest.fixture
def audited(client, signed_in, stub_audit, mcp_repo, monkeypatch):
    def fake_clone(url, dest, timeout=120, branch=None):
        return web_gitclone.clone_repo(f"file://{mcp_repo}", dest)
    monkeypatch.setattr(web_main, "clone_repo", fake_clone)
    r = client.post("/api/audits", json={"repo_url": "https://github.com/acme/mcp"})
    assert r.status_code == 202, r.text
    audit = client.get(f"/api/audits/{r.json()['id']}").json()
    assert audit["status"] == "done", audit.get("error")
    return audit


class TestThroughTheApp:
    def test_rule_findings_are_stored_beside_the_models(self, audited):
        by_rule = {f.get("rule_id"): f for f in audited["findings"]}
        mcp = by_rule["mcp01.literal_secret_in_config"]
        assert mcp["source"] == "rule"
        assert mcp["verification_status"] == "verified"
        assert mcp["assessment"] == "confirmed"
        assert mcp["detail"]["owasp_mcp"] == "MCP01"
        assert "mcp04.unpinned_package" in by_rule
        assert "dep.extra_index_url" in by_rule
        assert by_rule["secret.aws_access_key_id"]["line"] == 1
        model = [f for f in audited["findings"] if not f.get("source")]
        assert len(model) == 2 and all("assessment" in f for f in model)
        modules = {m["module"]: m for m in audited["modules"]}
        for name in ("secrets", "dependencies", "mcp", "surface", "drift"):
            assert modules[name]["status"] == "ok", (name, modules[name])
        assert modules["mcp"]["detail"]["taxonomy"]["name"].startswith("OWASP MCP Top 10")
        assert modules["drift"]["detail"]["compared"] is False

    def test_no_secret_reaches_any_output(self, client, audited):
        aid = audited["id"]
        outputs = [json.dumps(audited)]
        for path in ("trust", "report.sarif", "report.json", "report.html", "components",
                     "sbom.cdx.json", "diff", "replay.json"):
            r = client.get(f"/api/audits/{aid}/{path}")
            assert r.status_code == 200, (path, r.text)
            outputs.append(r.text)
        for f in audited["findings"]:
            r = client.get(f"/api/audits/{aid}/findings/{f['id']}/evidence-chain")
            assert r.status_code == 200
            outputs.append(r.text)
        joined = "\n".join(outputs)
        assert GH not in joined and AWS not in joined

    def test_the_html_report_is_locked_down(self, client, audited):
        r = client.get(f"/api/audits/{audited['id']}/report.html")
        assert "default-src 'none'" in r.headers["content-security-policy"]
        assert "script-src" not in r.headers["content-security-policy"]

    def test_sbom_and_components(self, client, audited):
        bom = client.get(f"/api/audits/{audited['id']}/sbom.cdx.json").json()
        assert any(c["name"] == "flask" and c["version"] == "2.0.1" for c in bom["components"])

    def test_someone_elses_audit_reads_as_absent(self, client, audited):
        sign_in(client, github_id=999, login="other")
        for path in ("trust", "report.sarif", "report.html", "diff", "replay.json",
                     "sbom.cdx.json"):
            assert client.get(f"/api/audits/{audited['id']}/{path}").status_code == 404

    def test_history_and_diff_after_a_second_audit(self, client, audited, mcp_repo):
        (mcp_repo / "deploy.py").write_text("AWS_KEY = None\n")
        git(mcp_repo, "commit", "-qam", "rotate")
        r = client.post("/api/audits", json={"repo_url": "https://github.com/acme/mcp"})
        second = client.get(f"/api/audits/{r.json()['id']}").json()
        d = client.get(f"/api/audits/{second['id']}/diff").json()
        assert d["previous_audit"] == audited["id"]
        assert any(f["title"].startswith("Hardcoded credential") for f in d["fixed"])
        assert d["changes"]["compared"] is True
        secrets = next(m for m in second["modules"] if m["module"] == "secrets")
        timeline = secrets["detail"]["timeline"]["secrets"]
        aws = next(s for s in timeline if s["kind"] == "aws_access_key_id")
        assert aws["present_at_head"] is False
        h = client.get(f"/api/projects/{second['project_id']}/history").json()
        assert [a["audit_id"] for a in h["audits"]] == [audited["id"], second["id"]]
        assert h["audits"][1]["fixed"] >= 1

    def test_mcp_catalog(self, client, signed_in):
        r = client.get("/api/mcp/catalog?language=es")
        assert len(r.json()["categories"]) == 10


class TestRepoOwnerAllowlist:
    def test_an_owner_outside_the_list_is_refused(self, client, signed_in, monkeypatch):
        monkeypatch.setenv(web_gitclone.ALLOWED_OWNERS_ENV, "KristinaSabitova, acme")
        r = client.post("/api/audits", json={"repo_url": "https://github.com/evil/x"})
        assert r.status_code == 403
        assert "kristinasabitova" in r.json()["detail"]

    def test_case_does_not_matter(self, monkeypatch):
        monkeypatch.setenv(web_gitclone.ALLOWED_OWNERS_ENV, "acme")
        web_gitclone.check_repo_owner("https://github.com/ACME/x.git")

    def test_empty_means_any(self, monkeypatch):
        monkeypatch.delenv(web_gitclone.ALLOWED_OWNERS_ENV, raising=False)
        web_gitclone.check_repo_owner("https://github.com/anyone/x")


class TestScanBounds:
    def test_the_total_scan_is_bounded_and_says_so(self, tmp_path, monkeypatch):
        from analysis import parallax
        for i in range(5):
            (tmp_path / f"f{i}.py").write_text("x" * 100)
        monkeypatch.setenv("SECAUDIT_MAX_SCAN_FILES", "3")
        texts = parallax.repository_texts(tmp_path)
        assert len(texts) == 3 and texts.truncated
        assert any("scan budget" in s for s in texts.skipped)
