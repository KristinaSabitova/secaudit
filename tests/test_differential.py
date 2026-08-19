"""Tests for fingerprinting stability and finding classification."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from secaudit import (
    make_fingerprint,
    _norm_anchor,
    _norm_file,
    build_diff_prompt,
    classify,
    Finding,
    MAX_SNIPPET_CHARS,
    redact_secrets,
    verify_evidence,
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
         title="SQL Injection", description="Use parameterized queries.",
         code_snippet='cur.execute("SELECT * FROM u WHERE n = " + name)',
         verification_status="verified", verification_note=""):
    return dict(category=category, file=file, anchor=anchor,
                severity=severity, title=title, description=description,
                code_snippet=code_snippet,
                verification_status=verification_status,
                verification_note=verification_note)


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


# ---------------------------------------------------------------------------
# Evidence behind a finding
# ---------------------------------------------------------------------------

class TestVerifyEvidence:
    def test_file_plus_snippet_is_verified(self):
        status, note = verify_evidence(_raw())
        assert status == "verified"
        assert note == ""

    def test_no_snippet_is_unverified(self):
        status, note = verify_evidence(_raw(code_snippet=""))
        assert status == "unverified"
        assert "code evidence" in note

    def test_no_file_is_unverified(self):
        status, note = verify_evidence(_raw(file=""))
        assert status == "unverified"
        assert "file" in note

    def test_the_model_saying_unverified_is_believed(self):
        status, note = verify_evidence(_raw(
            verification_status="unverified",
            verification_note="no matching code found for the pattern"))
        assert status == "unverified"
        assert note == "no matching code found for the pattern"

    def test_an_unverified_finding_keeps_a_reason_even_when_none_is_given(self):
        _, note = verify_evidence(_raw(verification_status="unverified",
                                       verification_note=""))
        assert note

    def test_an_unknown_status_is_not_taken_as_verified(self):
        status, note = verify_evidence(_raw(verification_status="probably"))
        assert status == "unverified"
        assert "probably" in note

    def test_a_missing_status_field_is_not_verified(self):
        raw = _raw()
        del raw["verification_status"]
        assert verify_evidence(raw)[0] == "unverified"


class TestClassifyEvidence:
    def test_the_snippet_survives_classification(self):
        _, findings = classify([_raw()], saved={})
        assert "SELECT * FROM u" in findings[0].code_snippet
        assert findings[0].verification_status == "verified"

    def test_a_generic_finding_is_kept_but_marked(self):
        """A category description with nothing behind it is not confirmed."""
        generic = _raw(category="csrf", file="", anchor="", code_snippet="",
                       title="CSRF protection",
                       description="State-changing endpoints need a token.")
        _, findings = classify([generic], saved={})
        assert findings[0].verification_status == "unverified"
        assert findings[0].verification_note
        assert findings[0].title == "CSRF protection"      # reported, not dropped

    def test_a_secret_in_a_snippet_is_redacted(self):
        raw = _raw(category="secrets", anchor="API_KEY",
                   code_snippet='API_KEY = "ghp_abcdefghijklmnopqrstuvwxyz"')
        _, findings = classify([raw], saved={})
        assert "ghp_abcdefghijklmnopqrstuvwxyz" not in findings[0].code_snippet
        assert "REDACTED" in findings[0].code_snippet

    def test_a_snippet_in_any_category_is_redacted(self):
        raw = _raw(code_snippet='conn = connect(password="hunter2000000")')
        _, findings = classify([raw], saved={})
        assert "hunter2000000" not in findings[0].code_snippet

    def test_an_oversized_snippet_is_capped(self):
        _, findings = classify([_raw(code_snippet="x" * 9000)], saved={})
        assert len(findings[0].code_snippet) == MAX_SNIPPET_CHARS

    def test_evidence_does_not_change_the_fingerprint(self):
        """Snippets move as code is reformatted; the finding's identity must not."""
        _, one = classify([_raw(code_snippet="a = 1")], saved={})
        _, two = classify([_raw(code_snippet="a = 1  # reformatted")], saved={})
        assert one[0].fingerprint == two[0].fingerprint

    def test_state_from_before_this_field_still_loads(self):
        """Findings saved by an older version have no verification fields."""
        old = Finding(fingerprint="f" * 16, id="f" * 8, file="app.py",
                      anchor="login", severity="high", category="injection",
                      title="SQL Injection", description="…")
        assert old.verification_status == "unverified"
        assert old.code_snippet == ""


class TestPromptLanguage:
    def test_english_is_the_default(self):
        assert "Spanish" not in build_diff_prompt(None, "all", None)

    def test_spanish_is_requested_explicitly(self):
        prompt = build_diff_prompt(None, "all", None, "es")
        assert "Spanish (castellano)" in prompt
        assert '"title", "description"' in prompt

    def test_code_is_never_translated(self):
        prompt = build_diff_prompt(None, "all", None, "es")
        assert "never translated" in prompt

    def test_an_unknown_language_falls_back_to_english(self):
        assert "Spanish" not in build_diff_prompt(None, "all", None, "fr")


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
