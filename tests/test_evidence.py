"""Checking a finding's snippet against the file it claims to quote."""
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import secaudit
from analysis.evidence import check, locate

SOURCE = '''import sqlite3

API_KEY = "sk-live-abcdef0123456789"


def get_user(cur, name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return cur.execute(query)


def get_admin(cur, name):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    return cur.execute(query)
'''


@pytest.fixture
def project(tmp_path):
    (tmp_path / "app.py").write_text(SOURCE)
    return tmp_path


def finding(**fields):
    base = {"file": "app.py", "verification_status": "verified",
            "verification_note": "", "line": None, "chunk": None,
            "code_snippet": ""}
    base.update(fields)
    return base


class TestCorrectSnippets:
    def test_an_exact_quote_is_found_with_its_lines(self, project):
        result = check(project, finding(code_snippet=(
            "def get_user(cur, name):\n"
            "    query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
            "    return cur.execute(query)")))
        assert result == {"line": 6, "line_end": 8}

    def test_reindentation_does_not_count_against_it(self, project):
        result = check(project, finding(code_snippet=(
            "def   get_user(cur,  name):\n"
            "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"")))
        assert result == {"line": 6, "line_end": 7}

    def test_blank_lines_are_skipped(self, project):
        result = check(project, finding(code_snippet=(
            "    return cur.execute(query)\n\n\ndef get_admin(cur, name):")))
        assert result == {"line": 8, "line_end": 11}

    def test_a_quote_may_start_and_end_mid_line(self, project):
        result = check(project, finding(code_snippet=(
            "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"\n"
            "    return cur.execute(")))
        assert result["line"] == 7 and result["line_end"] == 8

    def test_the_excerpts_line_numbers_are_ignored(self, project):
        result = check(project, finding(code_snippet=(
            "    6| def get_user(cur, name):\n"
            "    7|     query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"")))
        assert result == {"line": 6, "line_end": 7}

    def test_the_occurrence_nearest_the_reported_line_wins(self, project):
        snippet = "query = \"SELECT * FROM users WHERE name = '\" + name + \"'\""
        assert check(project, finding(code_snippet=snippet, line=11))["line"] == 12
        assert check(project, finding(code_snippet=snippet, line=1))["line"] == 7

    def test_a_redacted_secret_is_matched_by_its_hash(self, project):
        redacted = secaudit.redact_secrets('API_KEY = "sk-live-abcdef0123456789"')
        assert "sk-live" not in redacted
        assert check(project, finding(code_snippet=redacted)) == {
            "line": 3, "line_end": 3}

    def test_an_unverified_finding_still_gets_its_lines(self, project):
        result = check(project, finding(
            verification_status="unverified",
            code_snippet="return cur.execute(query)"))
        assert result == {"line": 8, "line_end": 8}


class TestAlteredSnippets:
    def test_one_changed_character_is_not_evidence(self, project):
        result = check(project, finding(code_snippet=(
            "query = \"SELECT * FROM users WHERE name = '\" + nam + \"'\"")))
        assert result["verification_status"] == "unverified"
        assert "does not appear in app.py" in result["verification_note"]
        assert result["line"] is None

    def test_an_elision_is_not_evidence(self, project):
        result = check(project, finding(code_snippet=(
            "def get_user(cur, name):\n    ...\n    return cur.execute(query)")))
        assert result["verification_status"] == "unverified"

    def test_lines_in_the_wrong_order_are_not_evidence(self, project):
        result = check(project, finding(code_snippet=(
            "    return cur.execute(query)\n"
            "    query = \"SELECT * FROM users WHERE name = '\" + name + \"'\"")))
        assert result["verification_status"] == "unverified"

    def test_a_masked_value_with_the_wrong_hash_is_not_evidence(self, project):
        result = check(project, finding(
            code_snippet='API_KEY = "[REDACTED:000000]"'))
        assert result["verification_status"] == "unverified"

    def test_a_very_short_quote_must_be_a_whole_line(self, project):
        """'name' is inside half the file; it proves nothing by itself."""
        assert check(project, finding(code_snippet="name"))[
            "verification_status"] == "unverified"


class TestHallucinatedSnippets:
    def test_code_that_is_nowhere_in_the_file(self, project):
        result = check(project, finding(
            code_snippet="eval(request.args['expr'])", line=7))
        assert result["verification_status"] == "unverified"
        assert result["line"] is None, "the model's line is never stored as is"

    def test_a_file_that_does_not_exist(self, project):
        result = check(project, finding(file="app/views.py",
                                        code_snippet="return cur.execute(query)"))
        assert "does not exist" in result["verification_note"]

    def test_a_path_outside_the_checkout(self, project, tmp_path_factory):
        outside = tmp_path_factory.mktemp("outside") / "secret.py"
        outside.write_text("return cur.execute(query)\n")
        rel = os.path.relpath(outside, project)
        result = check(project, finding(file=rel,
                                        code_snippet="return cur.execute(query)"))
        assert result["verification_status"] == "unverified"

    def test_a_symlink_out_of_the_checkout_is_not_followed(self, project,
                                                           tmp_path_factory):
        outside = tmp_path_factory.mktemp("outside") / "secret.py"
        outside.write_text("return cur.execute(query)\n")
        (project / "link.py").symlink_to(outside)
        result = check(project, finding(file="link.py",
                                        code_snippet="return cur.execute(query)"))
        assert result["verification_status"] == "unverified"

    def test_a_dotfile_path_is_not_mangled(self, project):
        (project / ".env").write_text("DEBUG=true\nSECRET_KEY=dev\n")
        assert check(project, finding(file="./.env",
                                      code_snippet="DEBUG=true")) == {
            "line": 1, "line_end": 1}


class TestWhatWasSent:
    MANIFEST = [
        {"index": 1, "files": [{"file": "other.py", "start": 1, "end": 3}]},
        {"index": 2, "files": [{"file": "app.py", "start": 1, "end": 8}]},
    ]

    def test_a_file_the_request_was_not_shown(self, project):
        result = check(project, finding(code_snippet="return cur.execute(query)",
                                        chunk=1), self.MANIFEST)
        assert "was not among the files sent" in result["verification_note"]

    def test_the_request_that_was_shown_it(self, project):
        assert check(project, finding(code_snippet="return cur.execute(query)",
                                      chunk=2), self.MANIFEST) == {
            "line": 8, "line_end": 8}

    def test_lines_past_what_was_sent_are_not_evidence(self, project):
        """app.py was sent only up to line 8; get_admin starts at 11."""
        result = check(project, finding(code_snippet="def get_admin(cur, name):",
                                        chunk=2), self.MANIFEST)
        assert result["verification_status"] == "unverified"


class TestLocate:
    def test_an_empty_snippet_is_nowhere(self):
        assert locate("   \n\n", "x = 1\n") is None

    def test_a_window_reports_lines_of_the_whole_file(self):
        assert locate("b = 2", "a = 1\nb = 2\n", first_line=40) == (41, 41)


class TestTheCLIUsesIt:
    def test_a_differential_audit_records_checked_lines(self, project, tmp_path,
                                                        monkeypatch, capsys):
        import json
        from types import SimpleNamespace

        monkeypatch.setattr(secaudit, "_STATE_DIR", tmp_path / "state")
        monkeypatch.setattr(secaudit, "load_config", dict)

        class Backend(secaudit.AuditBackend):
            def run(self, project, prompt, timeout=3600):
                return json.dumps([
                    {"category": "injection", "file": "app.py",
                     "anchor": "get_user", "severity": "high", "title": "t",
                     # Off by one: what is stored is where it really is.
                     "description": "d", "line": 7,
                     "code_snippet": "return cur.execute(query)",
                     "verification_status": "verified"},
                    {"category": "xss", "file": "app.py", "anchor": "nowhere",
                     "severity": "high", "title": "t2", "description": "d",
                     "code_snippet": "res.send(req.query.q)",
                     "verification_status": "verified"},
                ])

        args = SimpleNamespace(stack=None, scope="all", language="en",
                               print_prompt=False, json=True, all=True,
                               output=None)
        secaudit.run_differential(args, project, Backend())
        out = {f["title"]: f for f in json.loads(capsys.readouterr().out)}
        assert out["t"]["line"] == 8 and out["t"]["line_end"] == 8
        assert out["t"]["verification_status"] == "verified"
        assert out["t2"]["verification_status"] == "unverified"
        assert out["t2"]["line"] is None
