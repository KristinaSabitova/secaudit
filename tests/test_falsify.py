"""Module 2: findings as hypotheses, and the attempts to refute them.

The acceptance set is a small application with real flaws and with prepared
false positives. The real ones must end reachable or corroborated; the false
ones refuted or inconclusive — never the other way round.
"""
import json
import os
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from analysis import falsify
from analysis.falsify import (CORROBORATED, EXISTS, INCONCLUSIVE, REACHABLE,
                              REFUTED, Index, assess, normalize_hypothesis)

VIEWS = '''\
from flask import Flask, request
from . import db

app = Flask(__name__)
TABLE = "users"


@app.route("/user")
def show_user():
    name = request.args["name"]
    return db.find_user(name)


@app.route("/order")
def show_order():
    order_id = int(request.args["id"])
    return db.find_order(order_id)


@app.route("/report")
def report():
    return db.count_rows()


@app.route("/search")
def search():
    term = request.args["q"]
    return db.search(term)


@app.route("/run")
def run_job():
    cmd = request.args["cmd"]
    return jobs.launch(cmd)
'''

DB = '''\
import sqlite3

TABLE = "users"


def find_user(name):
    cur = sqlite3.connect("app.db").cursor()
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return cur.execute(query).fetchall()


def find_order(order_id):
    cur = sqlite3.connect("app.db").cursor()
    return cur.execute("SELECT * FROM orders WHERE id = " + str(order_id))


def count_rows():
    cur = sqlite3.connect("app.db").cursor()
    query = "SELECT count(*) FROM " + TABLE
    return cur.execute(query).fetchone()


def search(term):
    cur = sqlite3.connect("app.db").cursor()
    return cur.execute("SELECT * FROM items WHERE name LIKE ?", (term,))


def legacy_lookup(name):
    cur = sqlite3.connect("app.db").cursor()
    return cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
'''

JOBS = '''\
import subprocess


def launch(cmd):
    return subprocess.check_output(cmd, shell=True)
'''

TEMPLATE = '''\
<p>{{ name }}</p>
'''


@pytest.fixture
def lab(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "views.py").write_text(VIEWS)
    (tmp_path / "app" / "db.py").write_text(DB)
    (tmp_path / "app" / "jobs.py").write_text(JOBS)
    (tmp_path / "app" / "page.html").write_text(TEMPLATE)
    return tmp_path


def line_of(lab, file, text):
    for n, line in enumerate((lab / file).read_text().splitlines(), 1):
        if text in line:
            return n
    raise AssertionError(text)


def finding(lab, file, snippet, source, sink, category="injection", devil=None):
    line = line_of(lab, file, snippet)
    return {"file": file, "line": line, "line_end": line, "code_snippet": snippet,
            "category": category, "verification_status": "verified",
            "hypothesis": {"source": source, "sink": sink, "path": [],
                           "preconditions": []},
            "devil_advocate": devil}


HOLDS = {"verdict": "holds", "argument": "nothing stops it", "citations": []}


def results(outcome):
    return {a["method"]: a["result"] for a in outcome["attempts"]}


class TestTheRealFlawsSurvive:
    def test_concatenated_input_reaching_a_query(self, lab):
        f = finding(lab, "app/db.py", "return cur.execute(query).fetchall()",
                    "app/views.py:show_user — request.args['name']",
                    "app/db.py:find_user — cur.execute(query)", devil=HOLDS)
        outcome = assess(lab, f)
        assert results(outcome) == {"callgraph": "survived", "sanitizer": "survived",
                                    "reachability": "survived",
                                    "devil_advocate": "survived"}
        assert outcome["status"] == CORROBORATED
        chain = outcome["attempts"][2]["evidence"]["chain"]
        assert chain == ["app/views.py:show_user", "app/db.py:find_user"]

    def test_without_the_devil_it_is_reachable_not_corroborated(self, lab):
        f = finding(lab, "app/db.py", "return cur.execute(query).fetchall()",
                    "app/views.py:show_user", "cur.execute in find_user")
        assert assess(lab, f)["status"] == REACHABLE

    def test_a_command_built_from_a_parameter(self, lab):
        f = finding(lab, "app/jobs.py", "return subprocess.check_output(cmd, shell=True)",
                    "app/views.py:run_job — request.args['cmd']",
                    "subprocess.check_output in app/jobs.py:launch")
        outcome = assess(lab, f)
        assert results(outcome)["sanitizer"] == "survived"
        assert outcome["status"] == REACHABLE


class TestTheFalsePositivesFall:
    def test_input_cast_to_int_before_the_query(self, lab):
        """find_order concatenates, but what it is given went through int()."""
        f = finding(lab, "app/views.py", 'order_id = int(request.args["id"])',
                    "request.args['id'] in show_order",
                    "cur.execute in app/db.py:find_order")
        f["line"] = line_of(lab, "app/views.py", "return db.find_order(order_id)")
        outcome = assess(lab, f)
        # The sink function is show_order here: the call is find_order(order_id),
        # and order_id is int(...).
        assert results(outcome)["sanitizer"] == "refuted"
        assert outcome["attempts"][1]["evidence"]["through"] == ["int"]
        assert outcome["status"] == REFUTED

    def test_a_query_made_only_of_literals(self, lab):
        f = finding(lab, "app/db.py", "return cur.execute(query).fetchone()",
                    "app/views.py:report", "cur.execute in app/db.py:count_rows")
        outcome = assess(lab, f)
        assert results(outcome)["sanitizer"] == "refuted"
        assert outcome["attempts"][1]["evidence"]["value"] == "constant"
        assert outcome["status"] == REFUTED

    def test_a_parameterised_query(self, lab):
        f = finding(lab, "app/db.py",
                    'return cur.execute("SELECT * FROM items WHERE name LIKE ?", (term,))',
                    "app/views.py:search — request.args['q']",
                    "cur.execute in app/db.py:search")
        outcome = assess(lab, f)
        assert outcome["attempts"][1]["evidence"]["value"] == "parameterised"
        assert outcome["status"] == REFUTED

    def test_dead_code(self, lab):
        f = finding(lab, "app/db.py",
                    "return cur.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)",
                    "the name argument of app/db.py:legacy_lookup",
                    "cur.execute in legacy_lookup")
        outcome = assess(lab, f)
        assert results(outcome)["reachability"] == "refuted"
        assert outcome["status"] == REFUTED

    def test_a_devil_who_quotes_real_code_refutes(self, lab):
        devil = {"verdict": "false_positive",
                 "argument": "the template escapes it",
                 "citations": [{"file": "app/page.html", "code_snippet": "<p>{{ name }}</p>"}]}
        f = finding(lab, "app/page.html", "<p>{{ name }}</p>", "request.args['name']",
                    "the template", category="xss", devil=devil)
        outcome = assess(lab, f)
        assert results(outcome) == {"devil_advocate": "refuted"}
        assert outcome["status"] == REFUTED
        assert outcome["attempts"][0]["evidence"]["citations"][0]["line"] == 1


class TestWhatTheCallerPasses:
    def test_a_parameter_cast_by_every_caller_is_sanitised(self, lab):
        """The sink is in find_order; the int() is in the route that calls it."""
        f = finding(lab, "app/db.py",
                    'return cur.execute("SELECT * FROM orders WHERE id = " + str(order_id))',
                    "app/views.py:show_order", "cur.execute in app/db.py:find_order")
        outcome = assess(lab, f)
        assert results(outcome)["sanitizer"] == "refuted"
        assert outcome["attempts"][1]["evidence"]["through"] == ["int"]

    def test_one_caller_passing_raw_input_is_enough(self, lab):
        (lab / "app" / "admin.py").write_text(
            "from . import db\n\n@app.route('/admin/order')\n"
            "def admin_order():\n    return db.find_order(request.args['id'])\n")
        f = finding(lab, "app/db.py",
                    'return cur.execute("SELECT * FROM orders WHERE id = " + str(order_id))',
                    "app/views.py:show_order", "cur.execute in app/db.py:find_order")
        assert results(assess(lab, f))["sanitizer"] == "survived"

    def test_a_route_parameter_comes_from_outside(self, tmp_path):
        (tmp_path / "v.py").write_text(
            "@app.route('/<name>')\ndef page(name):\n"
            "    return cur.execute('SELECT ' + name)\n\npage('fixed')\n")
        f = {"file": "v.py", "line": 3, "line_end": 3, "category": "injection",
             "verification_status": "verified",
             "code_snippet": "return cur.execute('SELECT ' + name)",
             "hypothesis": {"source": "v.py:page", "sink": "cur.execute"}}
        assert results(assess(tmp_path, f))["sanitizer"] == "survived"


SESSIONS = '''\
from flask import Flask, jsonify, request, session

app = Flask(__name__)


@app.route("/debug/impersonate")
def impersonate():
    session["user"] = request.args.get("user", "guest")
    return {"ok": True}


@app.route("/admin/export")
def export_users():
    if "user" not in session:
        return {"error": "sign in"}, 401
    return jsonify(db().execute("SELECT id, email FROM users").fetchall())
'''


class TestFlowsThroughStoredState:
    def test_reading_the_request_is_not_the_sink(self, tmp_path):
        (tmp_path / "app.py").write_text(SESSIONS)
        f = finding(tmp_path, "app.py", 'session["user"] = request.args.get',
                    'app.py:impersonate — request.args.get("user")',
                    'app.py:impersonate — session["user"] = ...', category="authz")
        outcome = assess(tmp_path, f)
        assert results(outcome)["sanitizer"] == "inconclusive"
        assert outcome["status"] == REACHABLE

    def test_two_routes_joined_by_the_session_are_not_refuted(self, tmp_path):
        (tmp_path / "app.py").write_text(SESSIONS)
        f = finding(tmp_path, "app.py", "return jsonify(db()",
                    'app.py:impersonate — request.args.get("user")',
                    "app.py:export_users — jsonify(rows)", category="authz")
        outcome = assess(tmp_path, f)
        assert results(outcome)["callgraph"] == "inconclusive"
        assert outcome["status"] != REFUTED


class TestDeadCodeWithoutAHypothesis:
    def test_a_flow_finding_in_dead_code_is_refuted(self, lab):
        f = finding(lab, "app/db.py",
                    "return cur.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)",
                    "", "")
        f["hypothesis"] = None
        outcome = assess(lab, f)
        assert outcome["status"] == REFUTED
        assert results(outcome) == {"reachability": "refuted"}
        assert outcome["hypothesis"]["complete"] is False

    def test_a_query_of_constants_is_refuted_without_one(self, lab):
        f = finding(lab, "app/db.py", "return cur.execute(query).fetchone()", "", "")
        f["hypothesis"] = None
        outcome = assess(lab, f)
        assert results(outcome) == {"sanitizer": "refuted"}
        assert outcome["status"] == REFUTED

    def test_a_secret_in_dead_code_still_stands(self, lab):
        f = finding(lab, "app/db.py",
                    "return cur.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)",
                    "", "", category="secrets")
        f["hypothesis"] = None
        assert assess(lab, f)["status"] == EXISTS

    def test_live_code_without_a_hypothesis_records_nothing(self, lab):
        f = finding(lab, "app/db.py", "return cur.execute(query).fetchall()", "", "")
        f["hypothesis"] = None
        assert assess(lab, f)["attempts"] == []


class TestTheDevilIsChecked:
    def test_a_refutation_quoting_invented_code_does_not_count(self, lab):
        devil = {"verdict": "false_positive", "argument": "it is escaped",
                 "citations": [{"file": "app/db.py",
                                "code_snippet": "name = escape(name)"}]}
        f = finding(lab, "app/db.py", "return cur.execute(query).fetchall()",
                    "app/views.py:show_user", "cur.execute in find_user", devil=devil)
        outcome = assess(lab, f)
        # A failed attempt to refute is still an attempt it survived.
        assert results(outcome)["devil_advocate"] == "survived"
        assert outcome["status"] == CORROBORATED
        assert not outcome["attempts"][3]["evidence"]["citations"][0]["found"]

    def test_a_citation_outside_the_checkout_is_not_read(self, lab, tmp_path_factory):
        outside = tmp_path_factory.mktemp("out") / "x.py"
        outside.write_text("safe = True\n")
        devil = {"verdict": "false_positive", "argument": "a",
                 "citations": [{"file": os.path.relpath(outside, lab),
                                "code_snippet": "safe = True"}]}
        assert falsify.check_devil(lab, devil)["result"] == "survived"

    def test_an_answer_that_is_not_a_verdict_is_ignored(self, lab):
        assert falsify.check_devil(lab, {"verdict": "maybe"}) is None
        assert falsify.check_devil(lab, "false_positive") is None


class TestWhatIsNotAttempted:
    def test_an_unverified_finding_does_not_exist_yet(self, lab):
        f = finding(lab, "app/db.py", "return cur.execute(query).fetchall()",
                    "show_user", "find_user")
        f["verification_status"] = "unverified"
        assert assess(lab, f) == {"hypothesis": normalize_hypothesis(f["hypothesis"]),
                                  "attempts": [], "status": None, "note": None}

    def test_without_a_complete_hypothesis_it_stays_at_exists(self, lab):
        f = finding(lab, "app/db.py", "return cur.execute(query).fetchall()", "", "x")
        outcome = assess(lab, f)
        assert outcome["status"] == EXISTS and not outcome["attempts"]
        assert "no complete hypothesis" in outcome["note"]

    def test_other_languages_stay_at_exists_and_say_so(self, lab):
        (lab / "app" / "server.js").write_text("db.query('x' + req.query.q)\n")
        f = finding(lab, "app/server.js", "db.query('x' + req.query.q)",
                    "req.query.q", "db.query", devil=HOLDS)
        outcome = assess(lab, f)
        assert outcome["status"] == EXISTS
        assert "Python only" in outcome["note"]


class TestTheIndex:
    def test_entry_points_are_recognised(self, tmp_path):
        (tmp_path / "views.py").write_text(textwrap.dedent('''
            from django.views import View
            from django.urls import path

            class Profile(View):
                def get(self, request):
                    return helper()

            def helper():
                return 1

            def listed(request):
                return 2

            urlpatterns = [path("x", listed)]

            @click.command()
            def cli():
                pass

            def main():
                pass

            if __name__ == "__main__":
                main()
        '''))
        entries = {f.qualname for f in Index(tmp_path).entries()}
        assert entries == {"Profile.get", "listed", "cli", "main"}

    def test_a_function_passed_by_name_is_linked(self, tmp_path):
        (tmp_path / "a.py").write_text(textwrap.dedent('''
            @app.route("/")
            def index():
                return pool.submit(work)

            def work():
                return 1
        '''))
        index = Index(tmp_path)
        work = index.by_name["work"][0]
        assert index.from_entry(work)

    def test_a_broken_file_does_not_stop_the_rest(self, tmp_path):
        (tmp_path / "bad.py").write_text("def (:\n")
        (tmp_path / "good.py").write_text("def ok():\n    pass\n")
        assert [f.name for f in Index(tmp_path).functions] == ["ok"]

    def test_the_code_is_parsed_never_imported(self, tmp_path):
        marker = tmp_path / "EXECUTED"
        (tmp_path / "evil.py").write_text(
            f"open({str(marker)!r}, 'w').write('x')\ndef f():\n    pass\n")
        Index(tmp_path)
        assert not marker.exists()


class TestTheHypothesisShape:
    def test_fields_are_trimmed_and_capped(self):
        h = normalize_hypothesis({"source": "  a\n b ", "sink": "c" * 900,
                                  "path": ["x", "", 3], "preconditions": "no"})
        assert h == {"source": "a b", "sink": "c" * 500, "path": ["x", "3"],
                     "preconditions": [], "complete": True}

    def test_nothing_is_none(self):
        assert normalize_hypothesis(None) is None
        assert normalize_hypothesis({"source": "", "sink": ""}) is None

    def test_a_source_alone_is_incomplete(self):
        assert normalize_hypothesis({"source": "a"})["complete"] is False


class TestContext:
    def test_the_functions_of_the_flow_are_shown_numbered(self, lab):
        f = finding(lab, "app/db.py", "return cur.execute(query).fetchall()",
                    "app/views.py:show_user", "find_user")
        text = falsify.context_for(lab, f, Index(lab))
        assert "--- app/db.py" in text and "--- app/views.py" in text
        assert "|     query = " in text
        assert "count_rows" not in text


class TestTheEngineCarriesIt:
    def test_the_prompt_asks_for_a_hypothesis(self):
        import secaudit
        prompt = secaudit.build_diff_prompt(None, "all", None, "es")
        assert '"hypothesis"' in prompt and "path.py:function" in prompt

    def test_a_secret_in_the_hypothesis_is_masked(self):
        import secaudit
        _, findings = secaudit.classify([{
            "category": "secrets", "file": "a.py", "anchor": "K",
            "hypothesis": {"source": 'api_key = "sk-live-abcdef0123456789"',
                           "sink": "requests.get", "path": [], "preconditions": []},
        }], {})
        assert "sk-live" not in findings[0].hypothesis["source"]
        assert findings[0].hypothesis["complete"]

    def test_the_devils_answer_is_attached_only_to_what_it_was_asked(self, lab):
        import secaudit

        class Backend(secaudit.AuditBackend):
            prompts = []

            def run(self, project, prompt, timeout=3600):
                self.prompts.append(prompt)
                return json.dumps([
                    {"id": 1, "verdict": "holds", "argument": "x", "citations": []},
                    {"id": 7, "verdict": "false_positive", "argument": "y"}])

        f = finding(lab, "app/db.py", "return cur.execute(query).fetchall()",
                    "app/views.py:show_user", "find_user")
        f["severity"] = "high"
        plain = dict(f, hypothesis=None)
        usage = secaudit.devils_advocate(lab, Backend(), [plain, f])
        assert usage["requested"] == 1
        assert f["devil_advocate"]["verdict"] == "holds"
        assert plain["devil_advocate"] is None
        assert "### id 1" in Backend.prompts[0] and "### id 2" not in Backend.prompts[0]
