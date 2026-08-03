"""Tests for the FastAPI web layer (web/)."""
import json
import os
import subprocess
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

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
def client(monkeypatch):
    web_main.store.clear()
    monkeypatch.setattr(
        web_engine.engine, "select_backend",
        lambda flag, config=None: FakeBackend(),
    )
    return TestClient(app)


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
# API endpoints
# ---------------------------------------------------------------------------

class TestCreateAudit:
    def test_invalid_url_is_400(self, client):
        r = client.post("/api/audits", json={"repo_url": "git@github.com:a/b.git"})
        assert r.status_code == 400

    def test_full_flow(self, client, clone_from_sample):
        r = client.post("/api/audits",
                        json={"repo_url": "https://github.com/acme/sample"})
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "done"
        assert body["repo_url"] == "https://github.com/acme/sample.git"
        assert len(body["commit_sha"]) == 40
        assert len(body["findings"]) == 2
        assert body["summary"]["critical"] == 1
        assert body["summary"]["high"] == 1
        assert body["summary"]["low"] == 0

    def test_clone_failure_recorded_as_error(self, client, monkeypatch):
        def failing(url, dest, timeout=120):
            raise CloneError("git clone failed: repository not found")
        monkeypatch.setattr(web_main, "clone_repo", failing)
        r = client.post("/api/audits",
                        json={"repo_url": "https://github.com/acme/missing"})
        assert r.status_code == 201
        body = r.json()
        assert body["status"] == "error"
        assert "clone failed" in body["error"]

    def test_engine_failure_recorded_as_error(self, client, clone_from_sample,
                                              monkeypatch):
        monkeypatch.setattr(
            web_engine.engine, "select_backend",
            lambda flag, config=None: FakeBackend(output="garbage"),
        )
        r = client.post("/api/audits",
                        json={"repo_url": "https://github.com/acme/sample"})
        assert r.json()["status"] == "error"


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
        assert "backend" in body
