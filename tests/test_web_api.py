"""Tests for the FastAPI web layer (web/)."""
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

ROOT = Path(__file__).resolve().parent.parent

from web import db as web_db
from web import engine as web_engine
from web import main as web_main
from web import models as web_models
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
                 "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "CLAUDE_BIN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(web_engine.engine, "load_config", dict)


FAKE_FINDINGS = [
    {"category": "injection", "file": "app.py", "anchor": "get_user",
     "severity": "critical", "title": "SQL injection in get_user",
     "description": "Query is built by string concatenation; use bound parameters."},
    {"category": "secrets", "file": "app.py", "anchor": "API_KEY",
     "severity": "high", "title": "Hardcoded API key",
     "description": "Credential committed in app.py; move it to an env var."},
]


class FakeBackend:
    """Stands in for the LLM backend: returns canned JSON findings."""
    def __init__(self, output=None):
        self.output = output if output is not None else json.dumps(FAKE_FINDINGS)

    def run(self, project, prompt, timeout=3600):
        return self.output


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
def clone_from_sample(monkeypatch, sample_repo):
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


@pytest.fixture
def webhook_secret(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    return SECRET


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
        findings = web_engine.run_audit(tmp_path)
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
            web_engine.run_audit(tmp_path)

    def test_engine_sysexit_becomes_audit_error(self, monkeypatch, tmp_path):
        def exploding(flag, config=None):
            sys.exit("error: unknown backend 'nope'")
        monkeypatch.setattr(web_engine.engine, "select_backend", exploding)
        with pytest.raises(web_engine.AuditError):
            web_engine.run_audit(tmp_path)


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
    def test_invalid_url_is_400(self, client):
        r = client.post("/api/audits", json={"repo_url": "git@github.com:a/b.git"})
        assert r.status_code == 400

    def test_response_is_immediate_pending(self, client, clone_from_sample):
        r = client.post("/api/audits",
                        json={"repo_url": "https://github.com/acme/sample"})
        assert r.status_code == 202
        body = r.json()
        assert body["status"] == "pending"
        assert body["repo_url"] == "https://github.com/acme/sample.git"
        assert body["trigger"] == "manual"
        assert body["commit_sha"] is None

    def test_background_task_completes_audit(self, client, clone_from_sample):
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

    def test_clone_failure_recorded_as_error(self, client, monkeypatch):
        def failing(url, dest, timeout=120, branch=None):
            raise CloneError("git clone failed: repository not found")
        monkeypatch.setattr(web_main, "clone_repo", failing)
        audit_id = client.post(
            "/api/audits", json={"repo_url": "https://github.com/acme/missing"}
        ).json()["id"]
        detail = client.get(f"/api/audits/{audit_id}").json()
        assert detail["status"] == "error"
        assert "clone failed" in detail["error"]

    def test_engine_failure_recorded_as_error(self, client, clone_from_sample,
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
    def test_created_at_carries_an_explicit_utc_offset(self, client, clone_from_sample):
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
    def test_list_and_detail(self, client, clone_from_sample):
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

    def test_unknown_id_is_404(self, client):
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
    def test_without_secret_configured_is_503(self, client, monkeypatch):
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
        assert client.get("/api/audits").json() == []

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

    def test_queued_audit_runs_to_completion(self, client, webhook_secret,
                                             clone_from_sample):
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
        assert client.get("/api/audits").json() == []

    def test_unsupported_event_is_ignored(self, client, webhook_secret):
        r = deliver(client, {"action": "opened"}, event="issues")
        assert r.status_code == 200
        assert r.json()["status"] == "ignored"
        assert client.get("/api/audits").json() == []

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
    def test_interrupted_audits_are_failed_on_startup(self, client):
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

    def test_startup_is_a_no_op_without_stale_audits(self, client):
        assert web_main.fail_interrupted_audits() == 0


class TestStaticFrontend:
    def test_root_serves_the_ui(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/html")
        assert "secaudit" in r.text

    @pytest.mark.parametrize("path", ["/app.js", "/style.css"])
    def test_assets_are_served(self, client, path):
        assert client.get(path).status_code == 200

    def test_ui_has_no_external_references(self):
        """The UI must work offline behind TLS: no CDNs, no remote fonts."""
        for name in ("index.html", "app.js", "style.css"):
            text = (ROOT / "web" / "static" / name).read_text()
            assert "//fonts." not in text
            assert "http://" not in text
            assert "https://" not in text.replace("https://github.com/", "")

    def test_api_routes_are_not_shadowed(self, client):
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/audits").json() == []

    def test_unknown_path_is_404(self, client):
        assert client.get("/nope.html").status_code == 404


class TestHealth:
    def test_health_shape(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] in ("ok", "degraded")
        assert body["git_available"] is True
        assert body["database"] is True
        assert body["audits_stored"] == 0
        assert "backend" in body
