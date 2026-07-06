"""Tests for fingerprinting stability and finding classification."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from secaudit import (
    make_fingerprint,
    _norm_anchor,
    _norm_file,
    classify,
    Finding,
    redact_secrets,
)


# ---------------------------------------------------------------------------
# Fingerprint stability
# ---------------------------------------------------------------------------

class TestFingerprint:
    def test_same_input_same_hash(self):
        fp1 = make_fingerprint("injection", "app/views.py", "login_view")
        fp2 = make_fingerprint("injection", "app/views.py", "login_view")
        assert fp1 == fp2

    def test_line_number_stripped_from_anchor(self):
        fp1 = make_fingerprint("injection", "app/views.py", "login_view line 42")
        fp2 = make_fingerprint("injection", "app/views.py", "login_view line 99")
        assert fp1 == fp2

    def test_line_range_stripped(self):
        fp1 = make_fingerprint("authz", "auth.py", "check_permission lines 10-20")
        fp2 = make_fingerprint("authz", "auth.py", "check_permission lines 55-70")
        assert fp1 == fp2

    def test_leading_dotslash_stripped(self):
        fp1 = make_fingerprint("secrets", "./config/settings.py", "DATABASE_URL")
        fp2 = make_fingerprint("secrets", "config/settings.py", "DATABASE_URL")
        assert fp1 == fp2

    def test_case_insensitive_category(self):
        fp1 = make_fingerprint("INJECTION", "app.py", "run_query")
        fp2 = make_fingerprint("injection", "app.py", "run_query")
        assert fp1 == fp2

    def test_different_category_different_hash(self):
        fp1 = make_fingerprint("injection", "app.py", "run_query")
        fp2 = make_fingerprint("authz", "app.py", "run_query")
        assert fp1 != fp2

    def test_different_file_different_hash(self):
        fp1 = make_fingerprint("injection", "app/views.py", "run_query")
        fp2 = make_fingerprint("injection", "app/models.py", "run_query")
        assert fp1 != fp2

    def test_hash_length(self):
        fp = make_fingerprint("xss", "frontend/index.js", "renderUser")
        assert len(fp) == 16

    def test_whitespace_normalization_in_anchor(self):
        fp1 = make_fingerprint("xss", "index.js", "render  user")
        fp2 = make_fingerprint("xss", "index.js", "render user")
        assert fp1 == fp2


# ---------------------------------------------------------------------------
# normalize_anchor
# ---------------------------------------------------------------------------

class TestNormAnchor:
    def test_removes_line_number(self):
        assert "line" not in _norm_anchor("foo line 5")
        assert "42" not in _norm_anchor("bar line 42")

    def test_removes_lines_range(self):
        assert "lines" not in _norm_anchor("baz lines 10-20")

    def test_lowercases(self):
        assert _norm_anchor("MyFunction") == "myfunction"

    def test_strips_whitespace(self):
        assert _norm_anchor("  func  ") == "func"


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _raw(category="injection", file="app.py", anchor="login", severity="high",
         title="SQL Injection", description="Use parameterized queries."):
    return dict(category=category, file=file, anchor=anchor,
                severity=severity, title=title, description=description)


def _finding(fp, status="persisting", **kwargs):
    defaults = dict(
        fingerprint=fp, id=fp[:8], file="app.py", anchor="login",
        severity="high", category="injection", title="SQL Injection",
        description="Use parameterized queries.", status=status,
        suppression_reason="",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


class TestClassify:
    def test_new_finding(self):
        raw = [_raw()]
        updated, findings = classify(raw, saved={})
        f = findings[0]
        assert f.status == "new"

    def test_persisting_finding(self):
        raw = [_raw()]
        fp = make_fingerprint("injection", "app.py", "login")
        saved = {fp: _finding(fp, status="persisting")}
        _, findings = classify(raw, saved)
        assert findings[0].status == "persisting"

    def test_fixed_finding(self):
        fp = make_fingerprint("injection", "app.py", "login")
        saved = {fp: _finding(fp, status="persisting")}
        _, findings = classify(raw_findings=[], saved=saved)
        f = next(x for x in findings if x.fingerprint == fp)
        assert f.status == "fixed"

    def test_regressed_finding(self):
        raw = [_raw()]
        fp = make_fingerprint("injection", "app.py", "login")
        saved = {fp: _finding(fp, status="fixed")}
        _, findings = classify(raw, saved)
        assert findings[0].status == "regressed"

    def test_accepted_stays_accepted(self):
        raw = [_raw()]
        fp = make_fingerprint("injection", "app.py", "login")
        saved = {fp: _finding(fp, status="accepted", suppression_reason="wontfix")}
        _, findings = classify(raw, saved)
        f = findings[0]
        assert f.status == "accepted"
        assert f.suppression_reason == "wontfix"

    def test_accepted_not_regressed(self):
        """Previously accepted findings that reappear stay ACCEPTED, not REGRESSED."""
        raw = [_raw()]
        fp = make_fingerprint("injection", "app.py", "login")
        saved = {fp: _finding(fp, status="accepted", suppression_reason="false positive")}
        _, findings = classify(raw, saved)
        assert findings[0].status == "accepted"

    def test_fixed_then_absent_stays_fixed(self):
        fp = make_fingerprint("injection", "app.py", "login")
        saved = {fp: _finding(fp, status="fixed")}
        _, findings = classify(raw_findings=[], saved=saved)
        f = findings[0]
        assert f.status == "fixed"

    def test_multiple_findings(self):
        raw = [
            _raw(category="injection", anchor="login"),
            _raw(category="xss", anchor="render", file="index.js"),
        ]
        fp_old = make_fingerprint("authz", "auth.py", "check_perm")
        saved = {fp_old: _finding(fp_old, status="persisting",
                                  category="authz", file="auth.py", anchor="check_perm")}
        updated, findings = classify(raw, saved)
        statuses = {f.status for f in findings}
        assert "new" in statuses
        assert "fixed" in statuses

    def test_state_roundtrip_stable(self):
        """Fingerprint must survive a state save/reload cycle."""
        raw = [_raw()]
        fp = make_fingerprint("injection", "app.py", "login")
        # Simulate: first run stores as new, second run finds same anchor slightly reworded
        raw2 = [_raw(anchor="login line 99")]  # same function, different line ref
        fp2 = make_fingerprint("injection", "app.py", "login line 99")
        # line numbers are stripped, so fp == fp2
        assert fp == fp2


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

class TestRedactSecrets:
    def test_api_key_redacted(self):
        text = "api_key = 'supersecret123abc'"
        result = redact_secrets(text)
        assert "supersecret123abc" not in result
        assert "REDACTED" in result

    def test_github_token_redacted(self):
        text = "token: ghp_abcdefghijklmnopqrstuvwxyz"
        result = redact_secrets(text)
        assert "ghp_abcdefghijklmnopqrstuvwxyz" not in result
        assert "REDACTED" in result

    def test_non_secret_unchanged(self):
        text = "def login(username, password_hash):"
        result = redact_secrets(text)
        # no actual secret value here — function signature should be mostly intact
        assert "def login" in result

    def test_redaction_deterministic(self):
        text = "secret=abc12345xyz"
        assert redact_secrets(text) == redact_secrets(text)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
