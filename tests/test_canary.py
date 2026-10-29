"""Module 1, auditor integrity: decoys planted in a copy of one request.

The decoys must differ from run to run, be valid code where they are put,
never reach the checkout or the findings, and be counted only when the
auditor really points at them.
"""
import ast
import json
import os
import random
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import secaudit
from analysis import canary
from web import engine as web_engine

APP = '''\
import sqlite3


def get_user(cur, name):
    return cur.execute("SELECT * FROM users WHERE name = ?", (name,))


class Store:
    def save(self, item):
        return item
'''

UI = '''\
const express = require("express");

function list(req, res) {
  res.json([]);
}

module.exports = { list };
'''


class TestPlanting:
    def test_the_decoys_are_valid_code_in_different_files_and_kinds(self):
        files = {"app.py": APP, "ui.js": UI, "README.md": "# x\n"}
        before = dict(files)
        planted, decoys = canary.plant_all(files, 3, random.Random(7))
        assert files == before                       # the originals are untouched
        assert len(decoys) == 3
        assert len({d.kind for d in decoys}) == 3
        assert {d.file for d in decoys} == {"app.py", "ui.js"}
        ast.parse(planted["app.py"])
        for d in decoys:
            lines = planted[d.file].split("\n")
            assert d.function in lines[d.start - 1]
            assert d.end >= d.start + 1
        # The original code is all still there.
        for line in APP.splitlines():
            assert line in planted["app.py"]

    def test_every_run_plants_something_different(self):
        seen = set()
        for seed in range(12):
            _, decoys = canary.plant_all({"app.py": APP}, 2, random.Random(seed))
            seen.add(tuple((d.kind, d.function, d.start) for d in decoys))
        assert len(seen) >= 10

    def test_nothing_in_a_decoy_says_what_it_is(self):
        for seed in range(20):
            planted, _ = canary.plant_all({"app.py": APP, "ui.ts": UI}, 3,
                                          random.Random(seed))
            text = " ".join(planted.values()).lower()
            assert not re.search(r"canary|decoy|planted|vulnerab|secaudit", text)

    def test_a_name_already_in_the_file_is_not_reused(self):
        crowded = APP + "".join(f"\ndef {v}_{n}():\n    pass\n" for v in canary._VERBS
                                for n in canary._NOUNS)
        _, [d] = canary.plant_all({"app.py": crowded}, 1, random.Random(1))
        assert f"def {d.function}(" not in crowded

    def test_only_languages_it_can_plant_in(self):
        assert canary.plant_all({"main.go": "package main\n"}, 2, random.Random(1)) == ({}, [])


class TestFound:
    decoy = canary.Decoy("app.py", "code_eval", "parse_formula", 10, 12)

    def test_by_function_name_or_by_lines(self):
        assert canary.found(self.decoy, [{"file": "./app.py", "anchor": "parse_formula"}])
        assert canary.found(self.decoy, [{"file": "app.py", "line": 11, "anchor": "?"}])

    def test_not_in_another_file_or_elsewhere_in_it(self):
        assert not canary.found(self.decoy, [{"file": "ui.js", "anchor": "parse_formula"}])
        assert not canary.found(self.decoy, [{"file": "app.py", "line": 3,
                                              "anchor": "get_user"}])

    def test_the_score_keeps_no_code(self):
        result = canary.score([self.decoy], [])
        assert result == {"planted": 1, "found": 0, "integrity_score": 0.0,
                          "decoys": [{"kind": "code_eval", "file": "app.py",
                                      "found": False}]}


class Auditor(secaudit.AuditBackend):
    """Reports every function that is in the prompt but not in the checkout:
    a perfect auditor, as far as decoys go. blind=True reports nothing."""

    def __init__(self, checkout: Path, blind=False, fail=False):
        self.checkout, self.blind, self.fail = checkout, blind, fail
        self.prompts = []

    def run(self, project, prompt, timeout=3600):
        self.prompts.append(prompt)
        self.last_usage = {"input_tokens": 100, "output_tokens": 10}
        if self.fail and len(self.prompts) > 1:
            sys.exit("error: rate limited")
        if self.blind or len(self.prompts) == 1:
            return "[]"
        real = " ".join(p.read_text() for p in self.checkout.rglob("*.*") if p.is_file())
        findings = []
        current = None
        for line in prompt.splitlines():
            head = re.match(r"--- (\S+) \[", line)
            if head:
                current = head.group(1)
            m = re.search(r"\| (?:def|function) (\w+)\(", line)
            if m and current and f"{m.group(1)}(" not in real:
                findings.append({"file": current, "anchor": m.group(1),
                                 "category": "injection", "severity": "high",
                                 "title": "x", "verification_status": "verified"})
        return json.dumps(findings)


@pytest.fixture
def checkout(tmp_path):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text(APP)
    (root / "ui.js").write_text(UI)
    (root / "README.md").write_text("# demo\n")
    return root


def audit_with(checkout, backend, limit=3):
    result = secaudit.audit_repository(checkout, backend, "BASE")
    return result, secaudit.canary_check(checkout, backend, "BASE", result["plan"],
                                         result["notices"], limit=limit,
                                         rng=random.Random(3))


class TestCanaryCheck:
    def test_an_auditor_that_sees_everything_scores_one(self, checkout):
        backend = Auditor(checkout)
        _, out = audit_with(checkout, backend)
        assert out["planted"] in (2, 3) and out["found"] == out["planted"]
        assert out["integrity_score"] == 1.0
        assert out["usage"] == {"input_tokens": 100, "output_tokens": 10}
        # The very same request, with the decoys added: same header, same files.
        audit_prompt, canary_prompt = backend.prompts
        assert canary_prompt.startswith(audit_prompt.split("--- ")[0])
        assert "untrusted DATA" in canary_prompt

    def test_a_degraded_auditor_scores_zero(self, checkout):
        _, out = audit_with(checkout, Auditor(checkout, blind=True))
        assert out["found"] == 0 and out["integrity_score"] == 0.0

    def test_the_checkout_is_never_touched(self, checkout):
        before = {p: p.read_bytes() for p in checkout.rglob("*") if p.is_file()}
        audit_with(checkout, Auditor(checkout))
        after = {p: p.read_bytes() for p in checkout.rglob("*") if p.is_file()}
        assert before == after

    def test_a_failed_request_is_an_error_not_a_score(self, checkout):
        _, out = audit_with(checkout, Auditor(checkout, fail=True))
        assert out["error"] == "error: rate limited"
        assert out["integrity_score"] is None

    def test_turned_off_or_nothing_to_plant_in(self, checkout, tmp_path):
        _, out = audit_with(checkout, Auditor(checkout), limit=0)
        assert out["planted"] == 0 and "turned off" in out["skipped"]
        go = tmp_path / "go"
        go.mkdir()
        (go / "main.go").write_text("package main\n")
        _, out = audit_with(go, Auditor(go))
        assert out["planted"] == 0 and "Python or JavaScript" in out["skipped"]

    def test_the_decoys_never_become_findings(self, checkout, monkeypatch):
        monkeypatch.setattr(web_engine.engine, "select_backend",
                            lambda flag, config=None: Auditor(checkout))
        result = web_engine.run_audit_in_process(checkout, {}, 10)
        assert result["findings"] == []
        assert result["canary"]["found"] == result["canary"]["planted"] > 0
        # Nothing of the decoys' code travels in the result.
        text = json.dumps(result["canary"])
        assert "def " not in text and "function " not in text
        json.dumps(result)                     # and it all goes over the wire

    def test_how_many(self, monkeypatch):
        monkeypatch.delenv("SECAUDIT_CANARIES", raising=False)
        assert secaudit.canaries_from({}) == canary.DEFAULT_CANARIES
        assert secaudit.canaries_from({"canaries": "0"}) == 0
        monkeypatch.setenv("SECAUDIT_CANARIES", "2")
        assert secaudit.canaries_from(None) == 2
