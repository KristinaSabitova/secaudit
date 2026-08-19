"""Tests for the FastAPI web layer (web/)."""
import json
import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

ROOT = Path(__file__).resolve().parent.parent

from web import auth as web_auth
from web import db as web_db
from web import engine as web_engine
from web import main as web_main
from web import models as web_models
from web import runnerqueue as web_runnerqueue
from web import settings as web_settings
from web.gitclone import CloneError, clone_repo, validate_branch, validate_repo_url
from web.main import app
from web.webhook import (
    EVENT_HEADER,
    FORM_CONTENT_TYPE,
    SIGNATURE_HEADER,
    WebhookError,
    decode_payload,
    parse_push_event,
    sign,
    verify_signature,
)

SECRET = "s3cr3t-webhook-token"


@pytest.fixture(autouse=True)
def clean_backend_env(monkeypatch):
    """Keep the developer's own backend config out of the tests."""
    for name in ("SECAUDIT_BACKEND", "SECAUDIT_MODEL", "SECAUDIT_OLLAMA_URL",
                 "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CLAUDE_BIN",
                 web_auth.ADMIN_LOGIN_ENV, web_auth.ALLOWED_LOGINS_ENV,
                 web_auth.CLIENT_ID_ENV, web_auth.CLIENT_SECRET_ENV,
                 web_auth.SINGLE_USER_ENV, web_settings.SECRET_ENV):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(web_engine.engine, "load_config", dict)


FAKE_FINDINGS = [
    {"category": "injection", "file": "app.py", "anchor": "get_user",
     "severity": "critical", "title": "SQL injection in get_user",
     "description": "Query is built by string concatenation; use bound parameters.",
     "code_snippet": 'return cur.execute("SELECT * FROM users WHERE name = \'" + name)',
     "line": 4, "verification_status": "verified", "verification_note": ""},
    {"category": "secrets", "file": "app.py", "anchor": "API_KEY",
     "severity": "high", "title": "Hardcoded API key",
     "description": "Credential committed in app.py; move it to an env var.",
     "code_snippet": 'API_KEY = "sk-test-000000000000"',
     "verification_status": "verified", "verification_note": ""},
]

# A finding the engine could not anchor to any code: reported, but never as if
# it were confirmed.
UNVERIFIED_FINDING = {
    "category": "csrf", "file": "", "anchor": "",
    "severity": "medium", "title": "No CSRF protection found",
    "description": "State-changing endpoints should carry a CSRF token.",
    "code_snippet": "", "verification_status": "unverified",
    "verification_note": "no state-changing handler found in this codebase",
}


class FakeBackend(web_engine.engine.AuditBackend):
    """Stands in for the LLM backend: returns canned JSON findings.

    It inherits AuditBackend so it is handed the repository the way a real
    single-request backend is, rather than quietly skipping that step.
    """
    def __init__(self, output=None):
        self.output = output if output is not None else json.dumps(FAKE_FINDINGS)
        self.prompts = []

    def run(self, project, prompt, timeout=3600):
        self.prompts.append(prompt)
        return self.output


@pytest.fixture
def backend_prompts(monkeypatch):
    """Capture the prompts the engine builds, as the backend receives them."""
    prompts = []

    def select(flag, config=None):
        backend = FakeBackend()
        backend.prompts = prompts
        return backend

    monkeypatch.setattr(web_engine.engine, "select_backend", select)
    return prompts


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'test.db'}")
    web_db.reset_engine()
    web_db.Base.metadata.create_all(web_db.get_engine())
    monkeypatch.setattr(
        web_engine.engine, "select_backend",
        lambda flag, config=None: FakeBackend(),
    )
    yield TestClient(app)
    web_db.reset_engine()


@pytest.fixture
def sample_repo(tmp_path):
    """Small local git repo used as the clone source in API tests."""
    repo = tmp_path / "sample"
    repo.mkdir()
    (repo / "app.py").write_text(
        'API_KEY = "sk-test-000000000000"\n\n'
        'def get_user(cur, name):\n'
        '    return cur.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
    )
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=test", "-c", "user.email=test@test",
         "commit", "-qm", "init"],
        cwd=repo, check=True,
    )
    return repo


@pytest.fixture
def clone_from_sample(monkeypatch, sample_repo, stub_audit):
    """Route the app's clone through a real shallow clone of the local sample repo.

    Yields the list of clone calls the app made, so tests can assert on the
    arguments without depending on the local repo's default branch name.
    """
    calls = []

    def fake_clone(url, dest, timeout=120, branch=None):
        calls.append({"url": url, "branch": branch})
        return clone_repo(f"file://{sample_repo}", dest)

    monkeypatch.setattr(web_main, "clone_repo", fake_clone)
    return calls


def sign_in(client, github_id=4242, login="kris", name="Kris"):
    """Create a GitHub account and give the client its session cookie."""
    session = web_db.get_session()
    user = web_auth.upsert_user(session, {"id": github_id, "login": login,
                                          "name": name})
    record = web_auth.start_session(session, user)
    user_id, is_admin = user.id, user.is_admin
    session.close()
    client.cookies.set(web_auth.COOKIE_NAME, record.token)
    user.id, user.is_admin = user_id, is_admin
    return user


@pytest.fixture
def signed_in(client):
    """The first account to sign in, which administers the instance."""
    return sign_in(client)


@pytest.fixture
def stub_audit(monkeypatch):
    """Return canned findings instead of spawning a real audit process."""
    calls = []

    def fake(project, config=None, credentials=None):
        calls.append({"config": config, "credentials": credentials})
        return web_engine.run_audit_in_process(project, config or {}, 10)

    monkeypatch.setattr(web_main, "run_audit", fake)
    return calls


@pytest.fixture
def master_key(monkeypatch):
    monkeypatch.setenv(web_settings.SECRET_ENV, "test-master-key")
    return "test-master-key"


@pytest.fixture
def webhook_secret(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    return SECRET


def stored_audits():
    """Audits straight from the database, for assertions without signing in."""
    session = web_db.get_session()
    try:
        return session.scalars(select(web_models.Audit)).all()
    finally:
        session.close()


def push_payload(ref="refs/heads/main", after="a" * 40,
                 clone_url="https://github.com/acme/sample.git", **extra):
    return {
        "ref": ref,
        "after": after,
        "repository": {"clone_url": clone_url, "full_name": "acme/sample"},
        **extra,
    }


def encode_delivery(payload, form=False):
    """Serialise a payload the way a hook's Content type setting would."""
    if form:
        return (urlencode({"payload": json.dumps(payload)}).encode(),
                FORM_CONTENT_TYPE)
    return json.dumps(payload).encode(), "application/json"


def deliver(client, payload, *, secret=SECRET, event="push", signature=None,
            form=False):
    """POST a webhook delivery, signed with secret unless told otherwise.

    signature=None signs the body; a string is sent verbatim; "" omits the header.
    """
    body, content_type = encode_delivery(payload, form)
    headers = {EVENT_HEADER: event, "Content-Type": content_type}
    sig = sign(body, secret) if signature is None else signature
    if sig:
        headers[SIGNATURE_HEADER] = sig
    return client.post("/api/webhook/github", content=body, headers=headers)


# ---------------------------------------------------------------------------
# URL validation
# ---------------------------------------------------------------------------

class TestValidateRepoUrl:
    def test_plain_url_normalised(self):
        assert (validate_repo_url("https://github.com/torvalds/linux")
                == "https://github.com/torvalds/linux.git")

    def test_git_suffix_and_trailing_slash(self):
        assert (validate_repo_url("https://github.com/a/b.git")
                == "https://github.com/a/b.git")
        assert (validate_repo_url("https://github.com/a/b/")
                == "https://github.com/a/b.git")

    @pytest.mark.parametrize("url", [
        "git@github.com:a/b.git",
        "ssh://git@github.com/a/b",
        "http://github.com/a/b",
        "https://gitlab.com/a/b",
        "https://github.com/a",
        "https://github.com/a/b/c",
        "https://github.com/a/..",
        "https://evil.com/https://github.com/a/b",
        "file:///etc/passwd",
        "",
    ])
    def test_rejects_invalid(self, url):
        with pytest.raises(ValueError):
            validate_repo_url(url)


# ---------------------------------------------------------------------------
# Engine wrapper
# ---------------------------------------------------------------------------

class TestRunAudit:
    def test_returns_finding_dicts(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            web_engine.engine, "select_backend",
            lambda flag, config=None: FakeBackend(),
        )
        findings = web_engine.run_audit_in_process(tmp_path, {}, 10)
        assert len(findings) == 2
        sevs = {f["severity"] for f in findings}
        assert sevs == {"critical", "high"}
        assert all(f["fingerprint"] for f in findings)

    def test_unparseable_output_raises(self, monkeypatch, tmp_path):
        monkeypatch.setattr(
            web_engine.engine, "select_backend",
            lambda flag, config=None: FakeBackend(output="not json at all"),
        )
        with pytest.raises(web_engine.AuditError):
            web_engine.run_audit_in_process(tmp_path, {}, 10)

    def test_engine_sysexit_becomes_audit_error(self, monkeypatch, tmp_path):
        def exploding(flag, config=None):
            sys.exit("error: unknown backend 'nope'")
        monkeypatch.setattr(web_engine.engine, "select_backend", exploding)
        with pytest.raises(web_engine.AuditError):
            web_engine.run_audit_in_process(tmp_path, {}, 10)


# ---------------------------------------------------------------------------
# Backend selection: the deployment must work with any supported backend
# ---------------------------------------------------------------------------

class TestBackendConfig:
    def test_environment_overrides_the_config_file(self, monkeypatch):
        monkeypatch.setattr(web_engine.engine, "load_config",
                            lambda: {"backend": "claude-code", "model": "from-file"})
        monkeypatch.setenv("SECAUDIT_BACKEND", "ollama")
        monkeypatch.setenv("SECAUDIT_MODEL", "qwen2.5-coder")
        config = web_engine.backend_config()
        assert config["backend"] == "ollama"
        assert config["model"] == "qwen2.5-coder"

    def test_config_file_is_used_when_environment_is_empty(self, monkeypatch):
        monkeypatch.setattr(web_engine.engine, "load_config",
                            lambda: {"backend": "openai-api"})
        assert web_engine.backend_config()["backend"] == "openai-api"

    @pytest.mark.parametrize("backend,cls", [
        ("ollama", "OllamaBackend"),
        ("anthropic-api", "AnthropicAPIBackend"),
        ("openai-api", "OpenAIBackend"),
        ("claude-code", "ClaudeCodeBackend"),
    ])
    def test_every_backend_can_be_selected_from_the_environment(
            self, monkeypatch, backend, cls):
        monkeypatch.setenv("SECAUDIT_BACKEND", backend)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "x")   # ClaudeCode/API constructors
        monkeypatch.setenv("OPENAI_API_KEY", "x")
        selected = web_engine.engine.select_backend(None, web_engine.backend_config())
        assert type(selected).__name__ == cls

    def test_ollama_url_reaches_the_backend(self, monkeypatch):
        monkeypatch.setenv("SECAUDIT_BACKEND", "ollama")
        monkeypatch.setenv("SECAUDIT_OLLAMA_URL", "http://ollama:11434/")
        backend = web_engine.engine.select_backend(None, web_engine.backend_config())
        assert backend.base_url == "http://ollama:11434"


class TestSignIn:
    def test_anonymous_callers_are_refused(self, client):
        assert client.get("/api/audits").status_code == 401
        assert client.get("/api/settings").status_code == 401
        assert client.put("/api/settings", json={}).status_code == 401
        assert client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).status_code == 401

    def test_health_and_webhook_stay_public(self, client, webhook_secret):
        assert client.get("/api/health").status_code == 200
        assert deliver(client, {"zen": "hi"}, event="ping").status_code == 200

    def test_me_reports_who_is_signed_in(self, client):
        assert client.get("/api/me").json()["user"] is None
        user = sign_in(client)
        assert client.get("/api/me").json()["user"]["login"] == user.login

    def test_logout_ends_the_session(self, client, signed_in):
        assert client.get("/api/settings").status_code == 200
        assert client.post("/api/auth/logout").status_code == 204
        assert client.get("/api/settings").status_code == 401

    def test_an_expired_session_does_not_authenticate(self, client, signed_in):
        session = web_db.get_session()
        record = session.scalars(select(web_models.UserSession)).one()
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        session.commit()
        session.close()
        assert client.get("/api/settings").status_code == 401

    def test_login_is_503_without_an_oauth_app(self, client):
        r = client.get("/api/auth/login", follow_redirects=False)
        assert r.status_code == 503
        assert web_auth.CLIENT_ID_ENV in r.json()["detail"]

    def test_a_callback_with_a_mismatched_state_is_rejected(self, client, monkeypatch):
        """Otherwise a link could sign a victim into the attacker's account."""
        monkeypatch.setenv(web_auth.CLIENT_ID_ENV, "id")
        monkeypatch.setenv(web_auth.CLIENT_SECRET_ENV, "secret")
        client.cookies.set(web_main.OAUTH_STATE_COOKIE, "the-real-state")
        r = client.get("/api/auth/callback?code=abc&state=forged",
                       follow_redirects=False)
        assert r.status_code == 400

    def test_the_first_account_administers_the_instance(self, client):
        first = sign_in(client, github_id=1, login="first")
        second = sign_in(client, github_id=2, login="second")
        assert first.is_admin is True
        assert second.is_admin is False

    def test_the_named_account_administers_the_instance(self, client, monkeypatch):
        monkeypatch.setenv(web_auth.ADMIN_LOGIN_ENV, "kris")
        assert sign_in(client, github_id=1, login="someone").is_admin is False
        assert sign_in(client, github_id=2, login="kris").is_admin is True


class TestSingleUserMode:
    """A personal instance on loopback has one owner and no sign-in."""

    def test_without_it_sign_in_is_required(self, client):
        assert client.get("/api/audits").status_code == 401

    def test_the_owner_is_signed_in_by_default(self, client, monkeypatch):
        monkeypatch.setenv(web_auth.SINGLE_USER_ENV, "kris")
        body = client.get("/api/me").json()
        assert body["single_user"] is True
        assert body["user"]["login"] == "kris"
        assert body["user"]["is_admin"] is True
        assert client.get("/api/audits").status_code == 200

    def test_the_owner_is_created_once(self, client, monkeypatch):
        monkeypatch.setenv(web_auth.SINGLE_USER_ENV, "kris")
        client.get("/api/me")
        client.get("/api/me")
        session = web_db.get_session()
        assert len(session.scalars(select(web_models.User)).all()) == 1
        session.close()

    def test_the_owner_keeps_settings_and_audits(self, client, monkeypatch,
                                                 master_key, clone_from_sample):
        monkeypatch.setenv(web_auth.SINGLE_USER_ENV, "kris")
        client.put("/api/settings", json={"api_key": "sk-ant-local"})
        client.post("/api/audits", json={"repo_url": "https://github.com/acme/sample"})
        assert client.get("/api/settings").json()["api_key_set"] is True
        assert len(client.get("/api/audits").json()) == 1


class TestRunnerQueue:
    """claude-code audits are executed by the owner's machine, not the server."""

    def bearer(self, token):
        return {"Authorization": f"Bearer {token}"}

    def queue_claude_code_audit(self, client, master_key, clone_from_sample):
        client.put("/api/settings", json={"backend": "claude-code"})
        return client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]

    def test_the_server_leaves_them_queued(self, client, signed_in, master_key,
                                           clone_from_sample):
        audit_id = self.queue_claude_code_audit(client, master_key,
                                                clone_from_sample)
        assert client.get(f"/api/audits/{audit_id}").json()["status"] == "pending"
        assert clone_from_sample == []       # the server did not even clone

    def test_a_runner_claims_and_completes_one(self, client, signed_in,
                                               master_key, clone_from_sample):
        audit_id = self.queue_claude_code_audit(client, master_key,
                                                clone_from_sample)
        token = client.post("/api/runner/token").json()["token"]

        job = client.post("/api/runner/claim", headers=self.bearer(token)).json()
        assert job["id"] == audit_id
        assert client.get(f"/api/audits/{audit_id}").json()["status"] == "running"

        client.post("/api/runner/result", headers=self.bearer(token), json={
            "audit_id": audit_id, "commit_sha": "a" * 40,
            "findings": [{"severity": "high", "title": "Found on my laptop"}],
        })
        detail = client.get(f"/api/audits/{audit_id}").json()
        assert detail["status"] == "done"
        assert detail["summary"]["high"] == 1
        assert detail["findings"][0]["title"] == "Found on my laptop"

    def test_a_runner_reports_failures(self, client, signed_in, master_key,
                                       clone_from_sample):
        audit_id = self.queue_claude_code_audit(client, master_key,
                                                clone_from_sample)
        token = client.post("/api/runner/token").json()["token"]
        client.post("/api/runner/claim", headers=self.bearer(token))
        client.post("/api/runner/result", headers=self.bearer(token),
                    json={"audit_id": audit_id, "error": "claude exited with code 1"})
        detail = client.get(f"/api/audits/{audit_id}").json()
        assert detail["status"] == "error"
        assert "exited" in detail["error"]

    def test_a_claimed_audit_is_not_handed_out_twice(self, client, signed_in,
                                                     master_key,
                                                     clone_from_sample):
        self.queue_claude_code_audit(client, master_key, clone_from_sample)
        token = client.post("/api/runner/token").json()["token"]
        assert client.post("/api/runner/claim",
                           headers=self.bearer(token)).status_code == 200
        assert client.post("/api/runner/claim",
                           headers=self.bearer(token)).status_code == 204

    def test_an_abandoned_claim_is_handed_out_again(self, client, signed_in,
                                                    master_key,
                                                    clone_from_sample):
        """A runner that goes offline must not strand the audit forever."""
        audit_id = self.queue_claude_code_audit(client, master_key,
                                                clone_from_sample)
        token = client.post("/api/runner/token").json()["token"]
        client.post("/api/runner/claim", headers=self.bearer(token))

        session = web_db.get_session()
        audit = session.get(web_models.Audit, audit_id)
        audit.runner_claimed_at = (datetime.now(timezone.utc)
                                   - web_runnerqueue.CLAIM_TIMEOUT
                                   - timedelta(minutes=1))
        session.commit()
        session.close()

        assert client.post("/api/runner/claim",
                           headers=self.bearer(token)).json()["id"] == audit_id

    def test_a_runner_sees_only_its_owners_audits(self, client, master_key,
                                                  clone_from_sample):
        sign_in(client, github_id=1, login="admin")          # first: admin
        sign_in(client, github_id=2, login="other")
        self.queue_claude_code_audit(client, master_key, clone_from_sample)
        other_token = client.post("/api/runner/token").json()["token"]

        sign_in(client, github_id=1, login="admin")
        admin_token = client.post("/api/runner/token").json()["token"]
        # The admin's runner also takes what a webhook queued; the other's
        # runner sees only its own, and there is nothing left for it after.
        assert client.post("/api/runner/claim",
                           headers=self.bearer(other_token)).status_code == 200
        assert client.post("/api/runner/claim",
                           headers=self.bearer(admin_token)).status_code == 204

    def test_an_invalid_token_is_refused(self, client):
        assert client.post("/api/runner/claim",
                           headers=self.bearer("nope")).status_code == 401
        assert client.post("/api/runner/claim").status_code == 401

    def test_a_revoked_token_stops_working(self, client, signed_in):
        token = client.post("/api/runner/token").json()["token"]
        assert client.post("/api/runner/claim",
                           headers=self.bearer(token)).status_code in (200, 204)
        client.delete("/api/runner/token")
        assert client.post("/api/runner/claim",
                           headers=self.bearer(token)).status_code == 401

    def test_the_token_is_stored_hashed(self, client, signed_in):
        token = client.post("/api/runner/token").json()["token"]
        session = web_db.get_session()
        stored = session.scalars(select(web_models.User)).one().runner_token_hash
        session.close()
        assert stored != token
        assert stored == web_runnerqueue.hash_token(token)

    def test_a_result_for_an_unclaimed_audit_is_refused(self, client, signed_in,
                                                        master_key,
                                                        clone_from_sample):
        audit_id = self.queue_claude_code_audit(client, master_key,
                                                clone_from_sample)
        token = client.post("/api/runner/token").json()["token"]
        r = client.post("/api/runner/result", headers=self.bearer(token),
                        json={"audit_id": audit_id, "findings": []})
        assert r.status_code == 409


class TestDeleteAudit:
    def test_the_owner_can_delete_and_findings_go_too(self, client, signed_in,
                                                      clone_from_sample):
        audit_id = client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]
        assert len(client.get(f"/api/audits/{audit_id}").json()["findings"]) == 2

        assert client.delete(f"/api/audits/{audit_id}").status_code == 204
        assert client.get(f"/api/audits/{audit_id}").status_code == 404

        session = web_db.get_session()
        assert session.scalars(select(web_models.Finding)).all() == []
        session.close()

    def test_someone_elses_audit_cannot_be_deleted(self, client,
                                                   clone_from_sample):
        sign_in(client, github_id=1, login="first")
        audit_id = client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]

        sign_in(client, github_id=2, login="second")
        assert client.delete(f"/api/audits/{audit_id}").status_code == 404
        assert len(stored_audits()) == 1        # still there

    def test_an_admin_can_delete_any_audit(self, client, webhook_secret,
                                           clone_from_sample):
        sign_in(client, github_id=1, login="admin")          # first: admin
        audit_id = deliver(client, push_payload()).json()["id"]
        assert client.delete(f"/api/audits/{audit_id}").status_code == 204
        assert stored_audits() == []

    def test_deleting_an_unknown_audit_is_404(self, client, signed_in):
        assert client.delete("/api/audits/doesnotexist").status_code == 404

    def test_anonymous_callers_cannot_delete(self, client, clone_from_sample):
        sign_in(client, github_id=1, login="first")
        audit_id = client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]
        client.cookies.clear()
        assert client.delete(f"/api/audits/{audit_id}").status_code == 401


class TestGuestList:
    """Empty guest list means anyone with a GitHub account may sign in."""

    def test_anyone_may_sign_in_by_default(self, client):
        assert web_auth.allowed_logins() == set()
        assert sign_in(client, github_id=9, login="stranger").login == "stranger"

    def test_only_invited_logins_may_sign_in(self, client, monkeypatch):
        monkeypatch.setenv(web_auth.ALLOWED_LOGINS_ENV, "kris, Someone-Else")
        assert sign_in(client, github_id=1, login="KRIS").login == "KRIS"
        assert sign_in(client, github_id=2, login="someone-else")
        with pytest.raises(web_auth.NotInvited):
            sign_in(client, github_id=3, login="stranger")

    def test_an_uninvited_callback_is_403(self, client, monkeypatch):
        monkeypatch.setenv(web_auth.ALLOWED_LOGINS_ENV, "kris")
        monkeypatch.setenv(web_auth.CLIENT_ID_ENV, "id")
        monkeypatch.setenv(web_auth.CLIENT_SECRET_ENV, "secret")
        monkeypatch.setattr(web_auth, "exchange_code",
                            lambda code, uri: {"id": 7, "login": "stranger"})
        client.cookies.set(web_main.OAUTH_STATE_COOKIE, "s")
        r = client.get("/api/auth/callback?code=c&state=s", follow_redirects=False)
        assert r.status_code == 403
        assert "guest list" in r.json()["detail"]


class TestPerUserIsolation:
    def test_audits_are_not_visible_to_other_users(self, client, clone_from_sample):
        sign_in(client, github_id=1, login="first")
        mine = client.post("/api/audits",
                           json={"repo_url": "https://github.com/acme/sample"}).json()

        sign_in(client, github_id=2, login="second")
        assert client.get("/api/audits").json() == []
        # 404 rather than 403: the response must not confirm the id exists.
        assert client.get(f"/api/audits/{mine['id']}").status_code == 404

    def test_an_admin_sees_every_audit(self, client, webhook_secret,
                                       clone_from_sample):
        sign_in(client, github_id=1, login="admin")          # first, so admin
        sign_in(client, github_id=2, login="other")
        client.post("/api/audits", json={"repo_url": "https://github.com/acme/sample"})
        deliver(client, push_payload())                      # owned by nobody

        sign_in(client, github_id=1, login="admin")
        triggers = {a["trigger"] for a in client.get("/api/audits").json()}
        assert triggers == {"manual", "webhook"}

    def test_keys_are_stored_per_user(self, client, master_key):
        sign_in(client, github_id=1, login="first")
        client.put("/api/settings", json={"api_key": "sk-ant-first-key"})

        sign_in(client, github_id=2, login="second")
        assert client.get("/api/settings").json()["api_key_set"] is False
        client.put("/api/settings", json={"api_key": "sk-proj-second-key"})

        session = web_db.get_session()
        keys = {u.login: web_settings.credentials(session, u.id)
                for u in session.scalars(select(web_models.User)).all()}
        session.close()
        assert keys["first"] == {"ANTHROPIC_API_KEY": "sk-ant-first-key"}
        assert keys["second"] == {"OPENAI_API_KEY": "sk-proj-second-key"}

    def test_an_audit_runs_with_its_own_owners_key(self, client, master_key,
                                                   clone_from_sample, stub_audit):
        sign_in(client, github_id=1, login="first")
        client.put("/api/settings", json={"api_key": "sk-ant-first-key"})
        client.post("/api/audits", json={"repo_url": "https://github.com/acme/sample"})
        assert stub_audit[-1]["credentials"] == {"ANTHROPIC_API_KEY": "sk-ant-first-key"}


class TestCredentialIsolation:
    """The audit runs in its own process so keys cannot cross between users."""

    def test_the_parents_key_is_not_inherited(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-belongs-to-someone-else")
        with pytest.raises(web_engine.AuditError) as excinfo:
            web_engine.run_audit(tmp_path, {"backend": "anthropic-api"},
                                 credentials={})
        assert "ANTHROPIC_API_KEY is not set" in str(excinfo.value)

    def test_the_supplied_key_reaches_the_audit(self, tmp_path, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with pytest.raises(web_engine.AuditError) as excinfo:
            web_engine.run_audit(tmp_path, {"backend": "anthropic-api"},
                                 credentials={"ANTHROPIC_API_KEY": "sk-ant-supplied"})
        # It got past the missing-key check and failed at the API call instead.
        assert "ANTHROPIC_API_KEY is not set" not in str(excinfo.value)


class TestStoredSettings:
    """The dashboard stores the backend config; the key is encrypted at rest."""

    def test_a_pasted_key_picks_its_own_backend(self, client, signed_in, master_key):
        body = client.put("/api/settings", json={"api_key": "sk-ant-abc123"}).json()
        assert body["backend"] == "anthropic-api"
        assert body["api_key_set"] is True
        assert body["backend_status"]["ready"] is True

    def test_an_openai_key_picks_openai(self, client, signed_in, master_key):
        body = client.put("/api/settings", json={"api_key": "sk-proj-abc123"}).json()
        assert body["backend"] == "openai-api"

    def test_an_unrecognisable_key_is_400(self, client, signed_in, master_key):
        r = client.put("/api/settings", json={"api_key": "nonsense"})
        assert r.status_code == 400
        assert "explicitly" in r.json()["detail"]

    def test_the_key_is_never_returned(self, client, signed_in, master_key):
        client.put("/api/settings", json={"api_key": "sk-ant-secret-value"})
        for body in (client.get("/api/settings").text,
                     client.get("/api/health").text):
            assert "sk-ant-secret-value" not in body

    def test_the_key_is_encrypted_in_the_database(self, client, signed_in, master_key):
        client.put("/api/settings", json={"api_key": "sk-ant-secret-value"})
        session = web_db.get_session()
        stored = web_settings.load(session, signed_in.id).api_key_encrypted
        session.close()
        assert stored and "sk-ant-secret-value" not in stored
        assert web_settings.decrypt(stored) == "sk-ant-secret-value"

    def test_a_stored_key_reaches_the_audit_but_not_the_environment(
            self, client, signed_in, master_key):
        """It is handed to the audit process, never exported process-wide."""
        client.put("/api/settings", json={"api_key": "sk-ant-abc123"})
        session = web_db.get_session()
        assert web_settings.credentials(session, signed_in.id) == {
            "ANTHROPIC_API_KEY": "sk-ant-abc123"}
        session.close()
        assert "ANTHROPIC_API_KEY" not in os.environ

    def test_removing_the_key_forgets_it_everywhere(self, client, signed_in, master_key):
        client.put("/api/settings", json={"api_key": "sk-ant-abc123"})
        body = client.put("/api/settings", json={"clear_api_key": True}).json()
        assert body["api_key_set"] is False
        assert body["backend_status"]["ready"] is False
        session = web_db.get_session()
        assert web_settings.credentials(session, signed_in.id) == {}
        session.close()

    def test_health_describes_the_instance_not_the_signed_in_user(
            self, client, signed_in, master_key):
        """Health is public, so it must not leak whether a user has a key."""
        client.put("/api/settings", json={"api_key": "sk-ant-abc123"})
        assert client.get("/api/settings").json()["backend_status"]["name"] == \
            "anthropic-api"
        # The instance itself has no key configured, so health falls back to the
        # deployment default rather than describing the signed-in user.
        assert client.get("/api/health").json()["backend"]["name"] != "anthropic-api"

    def test_settings_override_the_environment(self, client, signed_in, master_key, monkeypatch):
        monkeypatch.setenv("SECAUDIT_BACKEND", "claude-code")
        client.put("/api/settings", json={"backend": "ollama",
                                          "ollama_url": "http://ollama:11434"})
        assert client.get("/api/settings").json()["backend_status"]["name"] == "ollama"

    def test_an_unknown_backend_is_rejected(self, client, signed_in, master_key):
        r = client.put("/api/settings", json={"backend": "chatgpt5"})
        assert r.status_code == 400

    def test_without_a_master_key_storing_is_refused(self, client, signed_in, monkeypatch):
        monkeypatch.delenv(web_settings.SECRET_ENV, raising=False)
        r = client.put("/api/settings", json={"api_key": "sk-ant-abc123"})
        assert r.status_code == 503
        assert web_settings.SECRET_ENV in r.json()["detail"]

    def test_a_rotated_master_key_is_reported_not_silently_wrong(
            self, client, signed_in, master_key, monkeypatch):
        client.put("/api/settings", json={"api_key": "sk-ant-abc123"})
        monkeypatch.setenv(web_settings.SECRET_ENV, "a-different-master-key")
        session = web_db.get_session()
        with pytest.raises(web_settings.SecretsUnavailable):
            web_settings.credentials(session, signed_in.id)
        session.close()

    def test_settings_survive_a_restart(self, client, signed_in, master_key):
        client.put("/api/settings", json={"api_key": "sk-ant-abc123"})
        web_main.fail_interrupted_audits()          # what startup does
        assert client.get("/api/settings").json()["api_key_set"] is True


class TestBackendStatus:
    def test_missing_credentials_name_the_variable(self, monkeypatch):
        monkeypatch.setenv("SECAUDIT_BACKEND", "anthropic-api")
        status = web_engine.backend_status()
        assert status["ready"] is False
        assert "ANTHROPIC_API_KEY" in status["detail"]

    def test_credentials_present_is_ready(self, monkeypatch):
        monkeypatch.setenv("SECAUDIT_BACKEND", "openai-api")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
        status = web_engine.backend_status()
        assert status["ready"] is True
        assert status["detail"] is None
        assert status["model"]

    def test_unknown_backend_is_reported_not_ready(self, monkeypatch):
        monkeypatch.setenv("SECAUDIT_BACKEND", "does-not-exist")
        status = web_engine.backend_status()
        assert status["ready"] is False
        assert "does-not-exist" in status["detail"]

    def _fake_tags(self, monkeypatch, models):
        class Resp:
            def read(self):
                return json.dumps({"models": [{"name": m} for m in models]}).encode()
            def __enter__(self): return self
            def __exit__(self, *a): return False
        monkeypatch.setattr(web_engine.urllib.request, "urlopen",
                            lambda url, timeout=None: Resp())

    def test_ollama_with_the_model_pulled_is_ready(self, monkeypatch):
        monkeypatch.setenv("SECAUDIT_BACKEND", "ollama")
        monkeypatch.setenv("SECAUDIT_MODEL", "llama3")
        self._fake_tags(monkeypatch, ["llama3:latest"])
        status = web_engine.backend_status()
        assert status["ready"] is True

    def test_ollama_without_a_generative_model_is_not_ready(self, monkeypatch):
        """An embeddings-only server cannot produce findings."""
        monkeypatch.setenv("SECAUDIT_BACKEND", "ollama")
        monkeypatch.setenv("SECAUDIT_MODEL", "llama3")
        self._fake_tags(monkeypatch, ["bge-m3:latest"])
        status = web_engine.backend_status()
        assert status["ready"] is False
        assert "bge-m3:latest" in status["detail"]

    def test_unreachable_ollama_reports_the_url(self, monkeypatch):
        monkeypatch.setenv("SECAUDIT_BACKEND", "ollama")
        monkeypatch.setenv("SECAUDIT_OLLAMA_URL", "http://nope:11434")
        def boom(url, timeout=None):
            raise OSError("connection refused")
        monkeypatch.setattr(web_engine.urllib.request, "urlopen", boom)
        status = web_engine.backend_status()
        assert status["ready"] is False
        assert "http://nope:11434" in status["detail"]


# ---------------------------------------------------------------------------
# Alembic migration
# ---------------------------------------------------------------------------

class TestMigration:
    def test_initial_migration_creates_schema(self, tmp_path):
        db_file = tmp_path / "mig.db"
        env = {**os.environ, "DATABASE_URL": f"sqlite:///{db_file}"}
        r = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=ROOT, env=env, capture_output=True, text=True,
        )
        assert r.returncode == 0, r.stderr
        con = sqlite3.connect(db_file)
        tables = {row[0] for row in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        columns = {row[1] for row in con.execute("PRAGMA table_info(audits)")}
        con.close()
        assert {"audits", "findings", "alembic_version"} <= tables
        assert "branch" in columns          # added by revision 0002


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

class TestCreateAudit:
    def test_invalid_url_is_400(self, client, signed_in):
        r = client.post("/api/audits", json={"repo_url": "git@github.com:a/b.git"})
        assert r.status_code == 400

    def test_response_is_immediate_pending(self, client, signed_in, clone_from_sample):
        r = client.post("/api/audits",
                        json={"repo_url": "https://github.com/acme/sample"})
        assert r.status_code == 202
        body = r.json()
        assert body["status"] == "pending"
        assert body["repo_url"] == "https://github.com/acme/sample.git"
        assert body["trigger"] == "manual"
        assert body["commit_sha"] is None

    def test_background_task_completes_audit(self, client, signed_in, clone_from_sample):
        audit_id = client.post(
            "/api/audits", json={"repo_url": "https://github.com/acme/sample"}
        ).json()["id"]
        # TestClient runs background tasks before returning control.
        detail = client.get(f"/api/audits/{audit_id}").json()
        assert detail["status"] == "done"
        assert len(detail["commit_sha"]) == 40
        assert len(detail["findings"]) == 2
        assert detail["summary"]["critical"] == 1
        assert detail["summary"]["high"] == 1
        assert detail["summary"]["low"] == 0
        titles = {f["title"] for f in detail["findings"]}
        assert "Hardcoded API key" in titles

    def test_clone_failure_recorded_as_error(self, client, signed_in, monkeypatch):
        def failing(url, dest, timeout=120, branch=None):
            raise CloneError("git clone failed: repository not found")
        monkeypatch.setattr(web_main, "clone_repo", failing)
        audit_id = client.post(
            "/api/audits", json={"repo_url": "https://github.com/acme/missing"}
        ).json()["id"]
        detail = client.get(f"/api/audits/{audit_id}").json()
        assert detail["status"] == "error"
        assert "clone failed" in detail["error"]

    def test_engine_failure_recorded_as_error(self, client, signed_in, clone_from_sample,
                                              monkeypatch):
        monkeypatch.setattr(
            web_engine.engine, "select_backend",
            lambda flag, config=None: FakeBackend(output="garbage"),
        )
        audit_id = client.post(
            "/api/audits", json={"repo_url": "https://github.com/acme/sample"}
        ).json()["id"]
        assert client.get(f"/api/audits/{audit_id}").json()["status"] == "error"


class TestTimestamps:
    def test_created_at_carries_an_explicit_utc_offset(self, client, signed_in, clone_from_sample):
        """Without an offset browsers read the timestamp as local time."""
        created = client.post(
            "/api/audits", json={"repo_url": "https://github.com/acme/sample"}
        ).json()["created_at"]
        assert created.endswith("+00:00")
        parsed = datetime.fromisoformat(created)
        assert abs((datetime.now(timezone.utc) - parsed).total_seconds()) < 60

    def test_naive_timestamps_are_treated_as_utc(self):
        naive = datetime(2026, 8, 6, 2, 41, 17)
        assert web_models.isoformat_utc(naive) == "2026-08-06T02:41:17+00:00"

    def test_aware_timestamps_are_converted_to_utc(self):
        madrid = timezone(timedelta(hours=2))
        aware = datetime(2026, 8, 6, 4, 41, 17, tzinfo=madrid)
        assert web_models.isoformat_utc(aware) == "2026-08-06T02:41:17+00:00"

    def test_missing_timestamp_stays_none(self):
        assert web_models.isoformat_utc(None) is None


class TestReadAudits:
    def test_list_and_detail(self, client, signed_in, clone_from_sample):
        audit_id = client.post(
            "/api/audits", json={"repo_url": "https://github.com/acme/sample"}
        ).json()["id"]

        listing = client.get("/api/audits").json()
        assert len(listing) == 1
        assert listing[0]["id"] == audit_id
        assert "findings" not in listing[0]        # summary only
        assert listing[0]["summary"]["critical"] == 1

        detail = client.get(f"/api/audits/{audit_id}").json()
        assert detail["id"] == audit_id
        assert len(detail["findings"]) == 2

    def test_unknown_id_is_404(self, client, signed_in):
        assert client.get("/api/audits/doesnotexist").status_code == 404


class TestBranchCloning:
    @pytest.mark.parametrize("name", ["main", "feature/x", "v1.2-rc", "a_b.c"])
    def test_accepts_ordinary_names(self, name):
        assert validate_branch(name) == name

    @pytest.mark.parametrize("name", [
        "--upload-pack=touch /tmp/pwned",
        "-b",
        "a..b",
        "refs/heads/x.lock",
        "with space",
        "semi;colon",
        "$(whoami)",
        "",
    ])
    def test_rejects_dangerous_names(self, name):
        with pytest.raises(ValueError):
            validate_branch(name)

    def test_clones_the_requested_branch(self, tmp_path, sample_repo):
        subprocess.run(["git", "checkout", "-qb", "topic"], cwd=sample_repo, check=True)
        (sample_repo / "extra.py").write_text("PASSWORD = 'hunter2'\n")
        subprocess.run(["git", "add", "."], cwd=sample_repo, check=True)
        subprocess.run(
            ["git", "-c", "user.name=test", "-c", "user.email=test@test",
             "commit", "-qm", "on topic"],
            cwd=sample_repo, check=True,
        )
        # Leave the repo on its original branch so "topic" is not simply HEAD.
        subprocess.run(["git", "checkout", "-q", "-"], cwd=sample_repo, check=True)

        dest = tmp_path / "checkout"
        sha = clone_repo(f"file://{sample_repo}", dest, branch="topic")
        assert len(sha) == 40
        assert (dest / "extra.py").exists()

    def test_unknown_branch_raises_clone_error(self, tmp_path, sample_repo):
        with pytest.raises(CloneError):
            clone_repo(f"file://{sample_repo}", tmp_path / "x", branch="nope")


# ---------------------------------------------------------------------------
# Webhook: signature verification and payload parsing
# ---------------------------------------------------------------------------

class TestVerifySignature:
    def test_accepts_matching_signature(self):
        body = b'{"ref": "refs/heads/main"}'
        verify_signature(body, sign(body, SECRET), SECRET)      # does not raise

    def test_rejects_missing_header(self):
        with pytest.raises(WebhookError):
            verify_signature(b"{}", None, SECRET)

    def test_rejects_wrong_secret(self):
        body = b"{}"
        with pytest.raises(WebhookError):
            verify_signature(body, sign(body, "other-secret"), SECRET)

    def test_rejects_tampered_body(self):
        signature = sign(b'{"ref": "refs/heads/main"}', SECRET)
        with pytest.raises(WebhookError):
            verify_signature(b'{"ref": "refs/heads/evil"}', signature, SECRET)

    @pytest.mark.parametrize("signature", [
        "", "sha256=", "deadbeef", "sha1=deadbeef", "sha256=not-hex",
    ])
    def test_rejects_malformed_signatures(self, signature):
        with pytest.raises(WebhookError):
            verify_signature(b"{}", signature, SECRET)


class TestDecodePayload:
    def test_reads_json_body(self):
        body, content_type = encode_delivery(push_payload())
        assert decode_payload(body, content_type)["ref"] == "refs/heads/main"

    def test_reads_form_encoded_body(self):
        """GitHub's default Content type wraps the JSON in a payload field."""
        body, content_type = encode_delivery(push_payload(), form=True)
        assert decode_payload(body, content_type)["ref"] == "refs/heads/main"

    def test_form_content_type_is_matched_with_charset(self):
        body, _ = encode_delivery(push_payload(), form=True)
        decoded = decode_payload(body, f"{FORM_CONTENT_TYPE}; charset=utf-8")
        assert decoded["ref"] == "refs/heads/main"

    def test_missing_content_type_falls_back_to_json(self):
        body, _ = encode_delivery(push_payload())
        assert decode_payload(body)["ref"] == "refs/heads/main"

    def test_form_body_without_payload_field(self):
        with pytest.raises(ValueError):
            decode_payload(b"other=1", FORM_CONTENT_TYPE)

    @pytest.mark.parametrize("body", [b"not json", b"[1, 2]", b'"a string"', b""])
    def test_rejects_non_object_payloads(self, body):
        with pytest.raises(ValueError):
            decode_payload(body, "application/json")


class TestParsePushEvent:
    def test_extracts_url_branch_and_sha(self):
        push = parse_push_event(push_payload(ref="refs/heads/feature/login"))
        assert push == {
            "repo_url": "https://github.com/acme/sample.git",
            "branch": "feature/login",
            "sha": "a" * 40,
        }

    @pytest.mark.parametrize("payload", [
        push_payload(ref="refs/tags/v1.0"),
        push_payload(ref=""),
        push_payload(deleted=True),
        push_payload(after="0" * 40),
    ], ids=["tag", "no-ref", "deleted", "null-sha"])
    def test_ignores_pushes_without_a_branch_to_audit(self, payload):
        assert parse_push_event(payload) is None

    @pytest.mark.parametrize("clone_url", [
        "https://gitlab.com/acme/sample.git",
        "git@github.com:acme/sample.git",
        "",
    ])
    def test_rejects_repositories_we_will_not_clone(self, clone_url):
        with pytest.raises(ValueError):
            parse_push_event(push_payload(clone_url=clone_url))


class TestWebhookEndpoint:
    def test_without_secret_configured_is_503(self, client, signed_in, monkeypatch):
        monkeypatch.delenv("GITHUB_WEBHOOK_SECRET", raising=False)
        assert deliver(client, push_payload()).status_code == 503

    def test_ping_is_acknowledged(self, client, webhook_secret):
        r = deliver(client, {"zen": "Non-blocking is better than blocking."},
                    event="ping")
        assert r.status_code == 200
        assert r.json()["status"] == "pong"

    @pytest.mark.parametrize("signature", ["", "sha256=" + "0" * 64],
                             ids=["missing", "wrong"])
    def test_bad_signature_is_401(self, client, webhook_secret, signature):
        assert deliver(client, push_payload(),
                       signature=signature).status_code == 401

    def test_signature_from_another_secret_is_401(self, client, webhook_secret):
        assert deliver(client, push_payload(),
                       secret="not-the-secret").status_code == 401

    def test_unsigned_delivery_creates_no_audit(self, client, webhook_secret):
        deliver(client, push_payload(), signature="")
        assert stored_audits() == []

    def test_push_queues_a_webhook_audit(self, client, webhook_secret,
                                         clone_from_sample):
        r = deliver(client, push_payload(ref="refs/heads/release"))
        assert r.status_code == 202
        body = r.json()
        assert body["trigger"] == "webhook"
        assert body["repo_url"] == "https://github.com/acme/sample.git"
        assert body["branch"] == "release"
        assert body["commit_sha"] == "a" * 40      # the sha the push announced
        assert clone_from_sample == [
            {"url": "https://github.com/acme/sample.git", "branch": "release"}
        ]

    def test_form_encoded_push_queues_an_audit(self, client, webhook_secret,
                                               clone_from_sample):
        """A hook left on GitHub's default Content type must still work."""
        r = deliver(client, push_payload(ref="refs/heads/release"), form=True)
        assert r.status_code == 202
        assert r.json()["branch"] == "release"

    def test_tampered_form_payload_is_401(self, client, webhook_secret):
        signed_body, _ = encode_delivery(push_payload(), form=True)
        tampered, content_type = encode_delivery(
            push_payload(clone_url="https://github.com/evil/repo.git"), form=True)
        r = client.post(
            "/api/webhook/github", content=tampered,
            headers={EVENT_HEADER: "push", "Content-Type": content_type,
                     SIGNATURE_HEADER: sign(signed_body, SECRET)},
        )
        assert r.status_code == 401

    def test_form_body_without_payload_field_is_400(self, client, webhook_secret):
        body = b"other=1"
        r = client.post(
            "/api/webhook/github", content=body,
            headers={EVENT_HEADER: "push", "Content-Type": FORM_CONTENT_TYPE,
                     SIGNATURE_HEADER: sign(body, SECRET)},
        )
        assert r.status_code == 400

    def test_queued_audit_runs_to_completion(self, client, signed_in,
                                             webhook_secret, clone_from_sample):
        audit_id = deliver(client, push_payload()).json()["id"]
        detail = client.get(f"/api/audits/{audit_id}").json()
        assert detail["status"] == "done"
        assert len(detail["commit_sha"]) == 40
        assert detail["summary"]["critical"] == 1

    @pytest.mark.parametrize("payload", [
        push_payload(ref="refs/tags/v1.0"),
        push_payload(deleted=True, after="0" * 40),
    ], ids=["tag", "branch-deleted"])
    def test_uninteresting_pushes_are_ignored(self, client, webhook_secret, payload):
        r = deliver(client, payload)
        assert r.status_code == 200
        assert r.json()["status"] == "ignored"
        assert stored_audits() == []

    def test_unsupported_event_is_ignored(self, client, webhook_secret):
        r = deliver(client, {"action": "opened"}, event="issues")
        assert r.status_code == 200
        assert r.json()["status"] == "ignored"
        assert stored_audits() == []

    def test_foreign_repository_is_400(self, client, webhook_secret):
        r = deliver(client, push_payload(clone_url="https://evil.com/acme/sample.git"))
        assert r.status_code == 400

    def test_signed_non_json_body_is_400(self, client, webhook_secret):
        body = b"not json"
        r = client.post(
            "/api/webhook/github", content=body,
            headers={EVENT_HEADER: "push", SIGNATURE_HEADER: sign(body, SECRET)},
        )
        assert r.status_code == 400


class TestRestartRecovery:
    def test_interrupted_audits_are_failed_on_startup(self, client, signed_in):
        session = web_db.get_session()
        for status in ("pending", "running", "done"):
            session.add(web_models.Audit(
                repo_url=f"https://github.com/acme/{status}.git", status=status))
        session.commit()
        session.close()

        assert web_main.fail_interrupted_audits() == 2

        by_repo = {a["repo_url"]: a for a in client.get("/api/audits").json()}
        assert by_repo["https://github.com/acme/done.git"]["status"] == "done"
        for status in ("pending", "running"):
            audit = by_repo[f"https://github.com/acme/{status}.git"]
            assert audit["status"] == "error"
            assert "restarted" in audit["error"]

    def test_startup_is_a_no_op_without_stale_audits(self, client, signed_in):
        assert web_main.fail_interrupted_audits() == 0


class TestStaticFrontend:
    def test_root_serves_the_ui(self, client, signed_in):
        r = client.get("/")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "secaudit" in r.text

    @pytest.mark.parametrize("path", ["/app.js", "/style.css"])
    def test_assets_are_served(self, client, path):
        assert client.get(path).status_code == 200

    @pytest.mark.parametrize("path,content_type", [
        ("/favicon.svg", "image/svg+xml"),
        ("/favicon.ico", "image/"),
        ("/favicon-32x32.png", "image/png"),
        ("/favicon-16x16.png", "image/png"),
        ("/apple-touch-icon.png", "image/png"),
    ])
    def test_favicons_are_served(self, client, path, content_type):
        """The static mount serves these; no route is registered for them."""
        r = client.get(path)
        assert r.status_code == 200
        assert r.headers["content-type"].startswith(content_type)
        assert len(r.content) > 200

    def test_the_page_declares_every_favicon_it_ships(self):
        html = (ROOT / "web" / "static" / "index.html").read_text()
        for name in ("favicon.svg", "favicon.ico", "favicon-32x32.png",
                     "favicon-16x16.png", "apple-touch-icon.png"):
            assert f'href="/{name}"' in html, f"{name} is shipped but not linked"
            assert (ROOT / "web" / "static" / name).exists()

    def test_ui_loads_no_external_resources(self):
        """The UI must work offline behind TLS: no CDNs, no remote fonts.

        Matches resource loads specifically — a URL in placeholder text is fine.
        """
        loads_remotely = re.compile(
            r"""(?:src|href)\s*=\s*["']\s*(?:https?:)?//|@import|url\(\s*["']?\s*(?:https?:)?//""",
            re.IGNORECASE,
        )
        for name in ("index.html", "app.js", "style.css"):
            text = (ROOT / "web" / "static" / name).read_text()
            assert not loads_remotely.search(text), f"{name} loads a remote resource"

    def test_hidden_attribute_is_not_beaten_by_a_display_rule(self):
        """Several panels use [hidden]; a class setting display would win."""
        css = (ROOT / "web" / "static" / "style.css").read_text()
        assert re.search(r"\[hidden\][^{]*\{[^}]*display:\s*none\s*!important",
                         css), "style.css must force [hidden] to display:none"

    def test_api_routes_are_not_shadowed(self, client, signed_in):
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/audits").json() == []

    def test_unknown_path_is_404(self, client, signed_in):
        assert client.get("/nope.html").status_code == 404


class TestFindingVerification:
    """A finding is only presented as confirmed when it carries evidence."""

    def run_audit_returning(self, client, monkeypatch, findings):
        monkeypatch.setattr(
            web_engine.engine, "select_backend",
            lambda flag, config=None: FakeBackend(json.dumps(findings)),
        )
        return client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]

    def test_a_finding_with_evidence_is_verified(self, client, signed_in,
                                                 clone_from_sample):
        audit_id = client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]
        finding = client.get(f"/api/audits/{audit_id}").json()["findings"][0]
        assert finding["verification_status"] == "verified"
        assert finding["file"] == "app.py"
        assert finding["anchor"] == "get_user"
        assert "SELECT * FROM users" in finding["code_snippet"]

    def test_a_reported_line_reaches_the_api(self, client, signed_in,
                                             clone_from_sample):
        audit_id = client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]
        finding = client.get(f"/api/audits/{audit_id}").json()["findings"][0]
        assert finding["line"] == 4

    def test_a_finding_without_a_line_keeps_null(self, client, signed_in,
                                                 clone_from_sample, monkeypatch):
        audit_id = self.run_audit_returning(client, monkeypatch,
                                            [UNVERIFIED_FINDING])
        assert client.get(
            f"/api/audits/{audit_id}").json()["findings"][0]["line"] is None

    def test_the_backend_is_handed_the_repository(self, client, signed_in,
                                                  clone_from_sample,
                                                  backend_prompts):
        """The API backends cannot open files, so the code goes in the prompt."""
        client.post("/api/audits",
                    json={"repo_url": "https://github.com/acme/sample"})
        prompt = backend_prompts[0]
        assert "REPOSITORY CONTENTS" in prompt
        assert "app.py" in prompt
        assert "def get_user(cur, name):" in prompt

    def test_a_finding_without_evidence_is_unverified(self, client, signed_in,
                                                      clone_from_sample,
                                                      monkeypatch):
        audit_id = self.run_audit_returning(client, monkeypatch,
                                            [UNVERIFIED_FINDING])
        finding = client.get(f"/api/audits/{audit_id}").json()["findings"][0]
        assert finding["verification_status"] == "unverified"
        assert "no state-changing handler" in finding["verification_note"]
        assert "code_snippet" not in finding

    def test_a_generic_finding_claiming_to_be_verified_is_degraded(
            self, client, signed_in, clone_from_sample, monkeypatch):
        """The category description dressed up as a confirmed finding."""
        generic = dict(UNVERIFIED_FINDING, verification_status="verified",
                       verification_note="", file="app.py")
        audit_id = self.run_audit_returning(client, monkeypatch, [generic])
        finding = client.get(f"/api/audits/{audit_id}").json()["findings"][0]
        assert finding["verification_status"] == "unverified"
        assert "code evidence" in finding["verification_note"]

    def test_a_verified_finding_without_a_file_is_degraded(self, client,
                                                           signed_in,
                                                           clone_from_sample,
                                                           monkeypatch):
        floating = dict(FAKE_FINDINGS[0], file="")
        audit_id = self.run_audit_returning(client, monkeypatch, [floating])
        finding = client.get(f"/api/audits/{audit_id}").json()["findings"][0]
        assert finding["verification_status"] == "unverified"

    def test_a_runner_cannot_report_a_verified_finding_without_evidence(self):
        """The rule is enforced at storage, not only inside the engine."""
        stored = web_models.finding_from_dict("abc", {
            "severity": "high", "title": "Trust me", "file": "app.py",
            "verification_status": "verified",
        })
        assert stored.verification_status == "unverified"
        assert stored.code_snippet is None

    def test_a_secret_in_a_snippet_is_redacted_before_storage(self, client,
                                                              signed_in,
                                                              clone_from_sample):
        audit_id = client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]
        findings = client.get(f"/api/audits/{audit_id}").json()["findings"]
        secret = next(f for f in findings if f["category"] == "secrets")
        assert "sk-test-000000000000" not in secret["code_snippet"]
        assert "REDACTED" in secret["code_snippet"]

    def test_verified_only_filters_the_findings(self, client, signed_in,
                                                clone_from_sample, monkeypatch):
        audit_id = self.run_audit_returning(
            client, monkeypatch, [FAKE_FINDINGS[0], UNVERIFIED_FINDING])
        detail = client.get(f"/api/audits/{audit_id}").json()
        assert len(detail["findings"]) == 2
        assert detail["verified_count"] == 1

        filtered = client.get(f"/api/audits/{audit_id}?verified_only=true").json()
        assert len(filtered["findings"]) == 1
        assert filtered["findings"][0]["verification_status"] == "verified"
        # The count still describes the whole audit, not the filtered list.
        assert filtered["verified_count"] == 1
        assert sum(filtered["summary"].values()) == 2

    def test_the_prompt_demands_evidence_and_forbids_generic_findings(self):
        prompt = web_engine.engine.build_diff_prompt(None, "all", None)
        assert "code_snippet" in prompt
        assert "verification_status" in prompt
        assert "VERBATIM" in prompt
        assert "FORBIDDEN" in prompt


class TestAuditLanguage:
    def test_english_by_default(self, client, signed_in, clone_from_sample):
        audit = client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()
        assert audit["language"] == "en"

    def test_spanish_is_recorded_and_returned(self, client, signed_in,
                                              clone_from_sample):
        audit = client.post("/api/audits", json={
            "repo_url": "https://github.com/acme/sample", "language": "es",
        }).json()
        assert audit["language"] == "es"
        assert client.get(f"/api/audits/{audit['id']}").json()["language"] == "es"

        session = web_db.get_session()
        stored = session.get(web_models.Audit, audit["id"])
        assert stored.language == "es"
        session.close()

    def test_a_spanish_audit_asks_the_backend_for_spanish(self, client, signed_in,
                                                          clone_from_sample,
                                                          backend_prompts):
        client.post("/api/audits", json={
            "repo_url": "https://github.com/acme/sample", "language": "es",
        })
        assert len(backend_prompts) == 1
        prompt = backend_prompts[0]
        assert "Spanish (castellano)" in prompt
        # Only the prose is translated; the evidence is quoted as it is.
        assert "code_snippet" in prompt
        assert "never translated" in prompt

    def test_an_english_audit_carries_no_language_instruction(self, client,
                                                              signed_in,
                                                              clone_from_sample,
                                                              backend_prompts):
        client.post("/api/audits",
                    json={"repo_url": "https://github.com/acme/sample"})
        assert "Spanish" not in backend_prompts[0]

    def test_an_unsupported_language_is_refused(self, client, signed_in):
        r = client.post("/api/audits", json={
            "repo_url": "https://github.com/acme/sample", "language": "fr",
        })
        assert r.status_code == 400
        assert "fr" in r.json()["detail"]
        assert stored_audits() == []

    def test_a_runner_is_told_which_language_to_audit_in(self, client, signed_in,
                                                         master_key,
                                                         clone_from_sample):
        client.put("/api/settings", json={"backend": "claude-code"})
        client.post("/api/audits", json={
            "repo_url": "https://github.com/acme/sample", "language": "es",
        })
        token = client.post("/api/runner/token").json()["token"]
        job = client.post("/api/runner/claim",
                          headers={"Authorization": f"Bearer {token}"}).json()
        assert job["language"] == "es"

    def test_a_webhook_audit_uses_the_instance_default(self, client, monkeypatch,
                                                       webhook_secret,
                                                       clone_from_sample):
        monkeypatch.setenv("SECAUDIT_DEFAULT_LANGUAGE", "es")
        audit = deliver(client, push_payload()).json()
        assert audit["language"] == "es"


class TestErrorSanitisation:
    """An audit failure is stored and served; a key must not ride along."""

    KEY = "sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH"

    def test_a_key_in_an_engine_error_is_masked(self, client, signed_in,
                                                clone_from_sample, monkeypatch):
        def explode(project, config=None, credentials=None):
            raise web_engine.AuditError(
                f"anthropic error: invalid x-api-key: {self.KEY}")

        monkeypatch.setattr(web_main, "run_audit", explode)
        audit_id = client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]

        detail = client.get(f"/api/audits/{audit_id}").json()
        assert detail["status"] == "error"
        assert self.KEY not in detail["error"]
        assert self.KEY not in json.dumps(detail)
        assert "invalid x-api-key" in detail["error"]

        session = web_db.get_session()
        stored = session.get(web_models.Audit, audit_id).error
        session.close()
        assert self.KEY not in stored          # masked before it reached the db

    def test_a_key_in_a_crashing_subprocess_is_masked(self, client, signed_in,
                                                      clone_from_sample,
                                                      monkeypatch):
        """The engine subprocess dies with the key in its traceback."""
        class Result:
            stdout = "not json"
            stderr = f"Traceback...\nAuthenticationError: key={self.KEY}"
            returncode = 1

        monkeypatch.setattr(web_engine.subprocess, "run",
                            lambda *a, **k: Result())
        monkeypatch.setattr(web_main, "run_audit", web_engine.run_audit)
        audit_id = client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]

        error = client.get(f"/api/audits/{audit_id}").json()["error"]
        assert self.KEY not in error
        assert "REDACTED" in error

    def test_a_key_in_a_runner_result_is_masked(self, client, signed_in,
                                                master_key, clone_from_sample):
        client.put("/api/settings", json={"backend": "claude-code"})
        audit_id = client.post(
            "/api/audits",
            json={"repo_url": "https://github.com/acme/sample"}).json()["id"]
        token = client.post("/api/runner/token").json()["token"]
        headers = {"Authorization": f"Bearer {token}"}
        client.post("/api/runner/claim", headers=headers)
        client.post("/api/runner/result", headers=headers, json={
            "audit_id": audit_id, "error": f"claude failed with {self.KEY}",
        })
        assert self.KEY not in client.get(f"/api/audits/{audit_id}").json()["error"]

    @pytest.mark.parametrize("message,secret", [
        ("x-api-key: sk-ant-api03-ZZZZYYYYXXXXWWWWVVVVUUUU", "sk-ant-api03-ZZZZ"),
        ("OPENAI_API_KEY=sk-proj-1234567890abcdefghij", "sk-proj-1234567890"),
        ("Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz0123", "ghp_abcdef"),
        ("ANTHROPIC_API_KEY = supersecretvalue123", "supersecretvalue123"),
    ])
    def test_credential_shapes_are_masked(self, message, secret):
        assert secret not in web_engine.sanitize_error(message)

    def test_an_ordinary_error_is_left_readable(self):
        message = "audit timed out after 1800s"
        assert web_engine.sanitize_error(message) == message


class TestHealth:
    def test_health_shape(self, client, signed_in):
        r = client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] in ("ok", "degraded")
        assert body["git_available"] is True
        assert body["database"] is True
        assert body["audits_stored"] == 0
        assert "backend" in body
