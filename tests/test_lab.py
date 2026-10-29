"""End to end over the lab: every module, through the server, on real git history.

The lab and its clean control are built by tests/lab/make_lab.py — the same
script that makes the public repositories — and audited through the API the
way production does: clone, evidence, falsifiability, parallax, memory,
leverage and the attacker's view, stored and read back. Only the model is
stood in for, with what a model answers for the lab (tests/lab/EXPECTED.md).
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent / "lab"))

import make_lab  # noqa: E402
from tests.test_web_api import (FakeBackend, clean_backend_env, client,  # noqa: F401
                                signed_in)
from web import engine as web_engine
from web import gitclone as web_gitclone
from web import main as web_main

LAB_URL = "https://github.com/KristinaSabitova/secaudit-lab"
CLEAN_URL = "https://github.com/KristinaSabitova/secaudit-lab-clean"


def f(category, file, snippet, title, severity, source, sink, pre=(), description=""):
    # As a model answers: it claims the evidence, which the server then checks.
    return {"category": category, "file": file, "code_snippet": snippet, "title": title,
            "severity": severity, "description": description or title,
            "anchor": sink.split(":")[1].split(" ")[0], "verification_status": "verified",
            "hypothesis": {"source": source, "sink": sink, "path": [],
                           "preconditions": list(pre)}}


SEARCH_SQLI = f(
    "injection", "src/db.py",
    """query = "SELECT id, name, price FROM products WHERE name LIKE '%" + term + "%'\"""",
    "SQL injection in product search", "high",
    "src/app.py:search_products — request.args.get('q')",
    "src/db.py:search_products — connect().execute(query)")

STAGE_1 = [SEARCH_SQLI]

STAGE_2 = [
    # Three low findings that only together are critical.
    f("authz", "src/app.py", 'session["role"] = "user"',
      "Debug route hands out a session without authentication", "low",
      "src/app.py:debug_session", 'src/app.py:debug_session — session["user_id"] = 0',
      ["none: the route is open to anyone"]),
    f("authz", "src/app.py", "session[key] = value",
      "Profile update lets a user set their own role", "low",
      "src/app.py:update_profile — request.form",
      "src/app.py:update_profile — session[key] = value",
      ["a signed-in session"],
      "Every form field is written into the session, role included: privilege escalation."),
    f("injection", "src/backup.py",
      'result = subprocess.run(f"echo backup {label}", shell=True,',
      "Command injection in the backup label", "low",
      "src/app.py:admin_backup — request.form['label']",
      "src/backup.py:make_backup — subprocess.run(shell=True)",
      ["only reachable with an admin session"],
      "The label reaches a shell command."),
    # Prepared false positives: module 2 has to refute them.
    f("injection", "src/db.py",
      'query = f"SELECT id, total, status FROM orders WHERE id = {order_id} AND user_id = ?"',
      "SQL injection in order lookup", "medium",
      "src/app.py:show_order — order_id from the URL",
      "src/db.py:order_for — connect().execute(query, (user_id,))"),
    f("injection", "src/legacy.py",
      'return connect().execute("SELECT * FROM " + table).fetchall()',
      "SQL injection in table export", "medium",
      "src/legacy.py:export_table — table", "src/legacy.py:export_table — execute"),
    # The fixed pattern, back in another place.
    f("injection", "src/db.py",
      """query = f"SELECT id, body FROM reviews WHERE body LIKE '%{term}%'\"""",
      "SQL injection in review search", "high",
      "src/app.py:search_reviews — request.args.get('q')",
      "src/db.py:search_reviews — connect().execute(query)"),
]


@pytest.fixture(scope="module")
def repos(tmp_path_factory):
    root = tmp_path_factory.mktemp("lab")
    lab, clean = root / "secaudit-lab", root / "secaudit-lab-clean"
    shas = make_lab.make_lab(lab)
    make_lab.make_clean(clean)
    subprocess.run(["git", "branch", "stage-1", shas["stage-1"]], cwd=lab, check=True)
    for repo in (lab, clean):
        subprocess.run(["git", "config", "uploadpack.allowAnySHA1InWant", "true"],
                       cwd=repo, check=True)
    return {"lab": lab, "clean": clean, "shas": shas}


@pytest.fixture
def server(client, signed_in, repos, monkeypatch):
    """Clones go to the local lab; the model answers what it is told to."""
    monkeypatch.setenv("SECAUDIT_CANARIES", "0")
    monkeypatch.setenv("SECAUDIT_MAX_REFUTATIONS", "0")      # no devil's advocate
    answer = {"findings": []}
    source = {LAB_URL: repos["lab"], CLEAN_URL: repos["clean"]}
    branch_of = {"value": None}

    def clone(url, dest, timeout=120, branch=None):
        return web_gitclone.clone_repo(f"file://{source[url.removesuffix('.git')]}", dest,
                                       branch=branch_of["value"])

    monkeypatch.setattr(web_main, "clone_repo", clone)
    # In this process, so that the stand-in model is the one asked.
    monkeypatch.setattr(web_main, "run_audit", lambda project, config=None, credentials=None:
                        web_engine.run_audit_in_process(project, config or {}, 10))
    monkeypatch.setattr(web_engine.engine, "select_backend",
                        lambda flag, config=None: FakeBackend(json.dumps(answer["findings"])))

    def audit(url, findings, branch=None):
        answer["findings"], branch_of["value"] = findings, branch
        r = client.post("/api/audits", json={"repo_url": url, "language": "es"})
        assert r.status_code == 202, r.text
        detail = client.get(f"/api/audits/{r.json()['id']}").json()
        assert detail["status"] == "done", detail.get("error")
        return detail

    return audit


def by_title(detail):
    return {x["title"]: x for x in detail["findings"]}


def module(detail, name):
    return {r["module"]: r for r in detail["modules"]}[name]


class TestTheLab:
    def test_every_module_finds_its_case(self, server, client, repos):
        first = server(LAB_URL, STAGE_1, branch="stage-1")
        assert by_title(first)["SQL injection in product search"]["epistemic_status"] \
            == "reachable"
        # The owner declares what matters most besides what is suggested.
        r = client.post(f"/api/projects/{first['project_id']}/crown-jewels",
                        json={"kind": "code_execution", "target": "el servidor de la tienda"})
        assert r.status_code == 201

        second = server(LAB_URL, STAGE_2)
        found = by_title(second)

        # Module 1, parallax: hidden instructions, a hook that runs on its own,
        # and the padding of near-identical files.
        kinds = {(d["kind"], d["file"]) for d in second["divergences"]}
        assert ("hidden_content", "CLAUDE.md") in kinds
        assert ("unexpected_execution", ".claude/settings.json") in kinds
        padding = [d for d in second["divergences"]
                   if (d.get("evidence") or {}).get("technique") == "padding"]
        assert padding, second["divergences"]

        # Module 2, falsifiability: the real ones hold, the prepared ones fall.
        for title in ("Command injection in the backup label",
                      "SQL injection in review search"):
            assert found[title]["epistemic_status"] == "reachable", title
        assert found["SQL injection in order lookup"]["epistemic_status"] == "refuted"
        assert found["SQL injection in table export"]["epistemic_status"] == "refuted"

        # Module 3, memory: the search was fixed, by the fix commit.
        old = by_title(client.get(f"/api/audits/{first['id']}").json())
        assert old["SQL injection in product search"]["fix_commit"] == repos["shas"]["fix"]
        assert module(second, "immune")["detail"]["fixed"] == 1
        assert found["SQL injection in review search"]["provenance"]["origin_commit"] \
            == repos["shas"]["reviews"]

        # Module 4, leverage: the deploy workflow, much leverage and no watch.
        lev = {r["file"]: r for r in second["leverage"]}
        deploy = lev[".github/workflows/deploy.yml"]
        assert deploy["leverage"] >= 0.7 and deploy["oversight"] < 0.3
        assert second["agent_capabilities"]

        # Module 5, the attacker: three low findings, one critical path.
        attack = second["attack"]
        nodes = {n["id"]: n for n in attack["nodes"]}
        edges = {e["id"]: e for e in attack["edges"]}
        [path] = [p for p in attack["paths"] if p["persona"] == "anonymous"
                  and nodes[p["target"]]["key"] == "executes_code"]
        steps = [edges[i]["finding_id"] for i in path["edges"] if edges[i]["finding_id"]]
        chain = ("Debug route hands out a session without authentication",
                 "Profile update lets a user set their own role",
                 "Command injection in the backup label")
        assert steps == [found[t]["id"] for t in chain]
        assert path["severity"] == "critical"
        for t in chain:
            assert found[t]["severity"] == "low"
            assert found[t]["contextual_severity"] == "critical", t
            assert "anonymous" in found[t]["personas"]
        # Refuted findings are on no path.
        assert "contextual_severity" not in found["SQL injection in order lookup"]
        cut = module(second, "attacker")["detail"]["min_cut"]
        cuts = {tuple(c) for x in cut for c in x["cuts"]}
        assert ("anonymous", "code_execution") in cuts


class TestTheCleanControl:
    def test_nothing_to_report(self, server):
        detail = server(CLEAN_URL, [])
        assert detail["divergences"] == []
        assert detail["agent_capabilities"] == []
        assert detail["attack"]["paths"] == []
        lev = {r["file"]: r for r in detail["leverage"]}
        assert all(r["oversight"] > 0 for r in lev.values())
        assert all(r["status"] == "ok" for r in detail["modules"]), detail["modules"]
