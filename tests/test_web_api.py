"""Tests for the FastAPI web layer (web/)."""
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

ROOT = Path(__file__).resolve().parent.parent

from web import db as web_db
from web import engine as web_engine
from web import main as web_main
from web.gitclone import CloneError, clone_repo, validate_repo_url
from web.main import app


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
    """Route the app's clone through a real shallow clone of the local sample repo."""
    monkeypatch.setattr(
        web_main, "clone_repo",
        lambda url, dest, timeout=120: clone_repo(f"file://{sample_repo}", dest),
    )
    return sample_repo


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
        con.close()
        assert {"audits", "findings", "alembic_version"} <= tables


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
        def failing(url, dest, timeout=120):
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
