"""Module 3: provenance, fixes from history, and rules validated against it."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from analysis import immune

LOCAL_SEMGREP = Path.home() / ".local/share/secaudit-semgrep/bin/semgrep"


def find_semgrep() -> str | None:
    found = os.environ.get("SEMGREP_BIN") or shutil.which("semgrep")
    if not found and LOCAL_SEMGREP.exists():
        found = str(LOCAL_SEMGREP)
    return found


@pytest.fixture
def semgrep(monkeypatch):
    found = find_semgrep()
    if not found:
        pytest.skip("semgrep is not installed")
    monkeypatch.setenv("SEMGREP_BIN", found)
    return found


VULNERABLE = ('import sqlite3\n\n'
              'def get_user(conn, name):\n'
              '    cur = conn.cursor()\n'
              '    cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
              '    return cur.fetchone()\n')
FIXED = VULNERABLE.replace('"SELECT * FROM users WHERE name = \'" + name + "\'"',
                           '"SELECT * FROM users WHERE name = ?", (name,)')
SNIPPET = 'cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")'
RULE = {"id": "sql concat", "message": "SQL built by concatenation",
        "severity": "error",
        "patterns": [{"pattern": '$C.execute("..." + $X + "...")'}]}


def git(repo, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t",
                           *args], cwd=repo, check=True, capture_output=True,
                          text=True).stdout.strip()


def commit(repo, files: dict, message: str, *body: str) -> str:
    for path, text in files.items():
        (repo / path).parent.mkdir(parents=True, exist_ok=True)
        (repo / path).write_text(text)
    git(repo, "add", "-A")
    extra = [a for b in body for a in ("-m", b)]
    git(repo, "commit", "-qm", message, *extra)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def history(tmp_path):
    """add the bug (declaring an AI) -> unrelated commit -> fix it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    shas = {"bug": commit(repo, {"app/db.py": VULNERABLE}, "add db",
                          "Co-Authored-By: Claude <noreply@anthropic.com>")}
    shas["docs"] = commit(repo, {"README.md": "# shop\n"}, "docs")
    shas["fix"] = commit(repo, {"app/db.py": FIXED}, "bind the name")
    return repo, shas


def previous_finding(**over):
    f = {"id": 7, "fingerprint": "abcdef0123456789", "file": "app/db.py",
         "code_snippet": SNIPPET, "verification_status": "verified",
         "epistemic_status": "reachable", "title": "SQL injection",
         "category": "injection"}
    f.update(over)
    return f


class TestProvenance:
    def test_the_commit_that_wrote_the_line_and_its_trailer(self, history):
        repo, shas = history
        origin = immune.provenance(repo, "app/db.py", 5, 5, shas["docs"])
        assert origin["origin_commit"] == shas["bug"]
        assert origin["origin_confidence"] == "high"
        assert origin["ai_declared"] is True

    def test_lines_from_several_commits_are_medium_and_the_oldest_wins(self, history):
        repo, shas = history
        origin = immune.provenance(repo, "app/db.py", 1, 6)
        assert origin["commits"] == 2
        assert origin["origin_confidence"] == "medium"
        assert origin["origin_commit"] == shas["bug"]

    def test_the_edge_of_a_shallow_clone_is_low(self, history, tmp_path):
        repo, shas = history
        clone = tmp_path / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{repo}",
                        str(clone)], check=True)
        origin = immune.provenance(clone, "app/db.py", 1, 6)
        assert origin["origin_confidence"] == "low" and origin["shallow"]

    def test_no_lines_no_provenance(self, history):
        repo, _ = history
        assert immune.provenance(repo, "app/db.py", 0, 0) is None
        assert immune.provenance(repo, "nope.py", 1, 2) is None

    @pytest.mark.parametrize("message, declared", [
        ("fix\n\nCo-authored-by: GitHub Copilot <copilot@github.com>", True),
        ("fix\n\nAssisted-by: Cursor", True),
        ("feat: x\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)", True),
        ("fix\n\nCo-authored-by: Ana García <ana@example.com>", False),
        ("refactor the claude_client wrapper", False),
    ])
    def test_declared_ai_participation(self, message, declared):
        assert immune.ai_declared(message) is declared


class TestFindFixed:
    def test_the_fix_and_the_commit_before_it(self, history):
        repo, shas = history
        [fixed] = immune.find_fixed(repo, [previous_finding()], shas["bug"])
        assert fixed["fix_commit"] == shas["fix"]
        assert fixed["vulnerable_commit"] == shas["docs"]
        assert SNIPPET in fixed["before"] and "+" in fixed["diff"]

    def test_still_in_the_code_is_not_fixed(self, history):
        repo, shas = history
        still = previous_finding(code_snippet="cur = conn.cursor()")
        assert immune.find_fixed(repo, [still], shas["bug"]) == []

    def test_only_findings_shown_to_hold(self, history):
        repo, shas = history
        for weak in (previous_finding(epistemic_status="exists"),
                     previous_finding(epistemic_status="refuted"),
                     previous_finding(verification_status="unverified")):
            assert immune.find_fixed(repo, [weak], shas["bug"]) == []

    def test_a_previous_commit_outside_the_history_is_said(self, history):
        repo, _ = history
        [fixed] = immune.find_fixed(repo, [previous_finding()], "0" * 40)
        assert fixed["fix_commit"] is None and "SECAUDIT_HISTORY_DEPTH" in fixed["reason"]


class TestRules:
    def test_a_rule_is_given_our_id_and_the_files_language(self):
        rule = immune.normalize_rule(RULE, "abcdef0123", "app/db.py")
        assert rule["id"] == "secaudit-immune-abcdef01-sql-concat"
        assert rule["languages"] == ["python"] and rule["severity"] == "ERROR"

    @pytest.mark.parametrize("raw", [
        {"message": "m"},                                       # no pattern
        {"pattern": "a", "patterns": [{"pattern": "b"}]},       # two
        {"patterns": [{"pattern": "a"}, {"paths": {"include": ["*"]}}]},
        {"patterns": [{"metavariable-regex": {"metavariable": "$X",
                                              "regex": "a", "fix": "b"}}]},
        "pattern: a",
    ])
    def test_anything_but_pattern_operators_is_not_a_rule(self, raw):
        assert immune.normalize_rule(raw, "f", "app.py") is None

    def test_extra_top_level_keys_are_dropped(self):
        rule = immune.normalize_rule(dict(RULE, fix="safe()", paths={"x": 1}),
                                     "f", "app.py")
        assert "fix" not in rule and "paths" not in rule

    def test_a_file_semgrep_cannot_read_has_no_rule(self):
        assert immune.normalize_rule(RULE, "f", "notes.txt") is None

    def test_the_yaml_export(self):
        rule = immune.normalize_rule(dict(RULE, message="two\nlines"), "f", "a.py")
        text = immune.to_yaml([rule])
        assert text.startswith("rules:\n  - id: ")
        assert '      - pattern: "$C.execute(\\"...\\" + $X + \\"...\\")"' in text
        assert "    message: |\n      two\n      lines" in text


class TestSemgrep:
    def test_a_rule_that_catches_the_bug_and_spares_the_fix(self, history, semgrep):
        repo, shas = history
        rule = immune.normalize_rule(RULE, "abcdef01", "app/db.py")
        v = immune.validate(repo, rule, "app/db.py", shas["docs"], shas["fix"])
        assert v["validated"] and (v["before"], v["after"]) == (1, 0)

    def test_a_rule_that_also_matches_the_fix_is_not_kept(self, history, semgrep):
        repo, shas = history
        loose = immune.normalize_rule({"pattern": "$C.execute(...)"}, "f", "app/db.py")
        v = immune.validate(repo, loose, "app/db.py", shas["docs"], shas["fix"])
        assert not v["validated"] and v["reason"] == "it still matches the fix"

    def test_a_rule_that_misses_the_bug_is_not_kept(self, history, semgrep):
        repo, shas = history
        blind = immune.normalize_rule({"pattern": "os.system(...)"}, "f", "app/db.py")
        v = immune.validate(repo, blind, "app/db.py", shas["docs"], shas["fix"])
        assert not v["validated"] and v["before"] == 0

    def test_a_broken_rule_is_an_error_not_a_pass(self, history, semgrep):
        repo, shas = history
        broken = immune.normalize_rule({"pattern": "$C.execute(("}, "f", "app/db.py")
        v = immune.validate(repo, broken, "app/db.py", shas["docs"], shas["fix"])
        assert not v["validated"] and v.get("error")

    def test_a_fix_semgrep_cannot_parse_proves_nothing(self, history, semgrep):
        repo, shas = history
        broken = commit(repo, {"app/db.py": FIXED.replace("(name,)", "(name,")}, "typo")
        rule = immune.normalize_rule(RULE, "abcdef01", "app/db.py")
        v = immune.validate(repo, rule, "app/db.py", shas["fix"], broken)
        assert not v["validated"] and "parse" in v["error"]

    def test_a_scan_finds_the_bug_written_again(self, history, semgrep):
        repo, _ = history
        again = FIXED + ('\ndef by_mail(conn, mail):\n'
                         '    conn.cursor().execute("SELECT 1 WHERE m = \'" + mail + "\'")\n')
        commit(repo, {"app/db.py": again}, "lookup by mail")
        rule = immune.normalize_rule(RULE, "abcdef01", "app/db.py")
        [m] = immune.run_semgrep([rule], repo)
        assert (m["rule"], m["file"], m["line"]) == (rule["id"], "app/db.py", 9)
        assert "mail" in immune.snippet_at(repo, "app/db.py", m["line"], m["line_end"])
