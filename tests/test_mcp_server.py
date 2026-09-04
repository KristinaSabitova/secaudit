"""Tests for the MCP server (mcp_server/).

The HTTP layer is mocked, never the tools themselves: every test drives a real
httpx client over a MockTransport, so the method, path, query, headers and body
each tool actually puts on the wire are what gets asserted. The tools are
invoked through server.call_tool(), which also proves they are registered under
the names an MCP client will call them by.
"""
import asyncio
import json
import os
import sys
from typing import Any

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from mcp_server import server as mcp_module

SERVER = mcp_module.server
API = "https://secaudit.test"
TOKEN = "svc-token-abc123"

TOOL_NAMES = {"launch_audit", "get_audit", "list_audits", "check_health",
              "get_backend_status"}


def run(coro):
    return asyncio.run(coro)


def call(name: str, **arguments) -> str:
    """Invoke a tool the way an MCP client would and read its text back."""
    result = run(SERVER.call_tool(name, arguments))
    assert result.content, f"{name} returned no content"
    return result.content[0].text


class FakeApi:
    """Stands in for the deployed REST API and records what it was sent."""

    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.status = 200
        self.body: Any = {}
        self.raises: Exception | None = None

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raises is not None:
            raise self.raises
        if isinstance(self.body, str):
            return httpx.Response(self.status, text=self.body)
        return httpx.Response(self.status, json=self.body)

    @property
    def last(self) -> httpx.Request:
        assert self.requests, "no request was made"
        return self.requests[-1]

    def sent_json(self) -> Any:
        return json.loads(self.last.content)


@pytest.fixture
def api(monkeypatch):
    """A mocked API, with a service token configured."""
    fake = FakeApi()
    monkeypatch.setenv(mcp_module.API_URL_ENV, API)
    monkeypatch.setenv(mcp_module.TOKEN_ENV, TOKEN)

    def client():
        return httpx.AsyncClient(base_url=mcp_module.api_url(),
                                 transport=httpx.MockTransport(fake._handle),
                                 timeout=mcp_module.TIMEOUT)

    monkeypatch.setattr(mcp_module, "_client", client)
    return fake


def an_audit(**overrides) -> dict:
    audit = {
        "id": "aud123",
        "repo_url": "https://github.com/owner/repo",
        "branch": None,
        "commit_sha": "abcdef1234567890",
        "trigger": "manual",
        "status": "done",
        "language": "en",
        "created_at": "2026-09-04T10:00:00Z",
        "error": None,
        "summary": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
    }
    audit.update(overrides)
    return audit


class TestRegistration:
    def test_every_tool_is_registered(self):
        tools = run(SERVER.list_tools())
        assert {t.name for t in tools} == TOOL_NAMES

    def test_every_tool_documents_itself(self):
        # The description is what an MCP client shows the model to choose with.
        for tool in run(SERVER.list_tools()):
            assert tool.description and len(tool.description) > 40

    def test_schemas_expose_the_documented_arguments(self):
        schemas = {t.name: t.input_schema for t in run(SERVER.list_tools())}
        assert set(schemas["launch_audit"]["properties"]) == {"repo_url",
                                                              "language"}
        assert set(schemas["get_audit"]["properties"]) == {"audit_id",
                                                           "verified_only"}
        assert set(schemas["list_audits"]["properties"]) == {"limit"}
        assert schemas["check_health"]["properties"] == {}
        # repo_url has no default, so a client must supply it.
        assert schemas["launch_audit"]["required"] == ["repo_url"]


class TestLaunchAudit:
    def test_posts_to_the_audits_endpoint(self, api):
        api.status = 202
        api.body = an_audit(status="pending", summary=None)
        call("launch_audit", repo_url="https://github.com/owner/repo")

        assert api.last.method == "POST"
        assert api.last.url.path == "/api/audits"
        assert api.sent_json() == {"repo_url": "https://github.com/owner/repo",
                                   "language": "en"}

    def test_language_is_passed_through(self, api):
        api.status = 202
        api.body = an_audit(status="pending", language="es")
        call("launch_audit", repo_url="https://github.com/owner/repo",
             language="es")
        assert api.sent_json()["language"] == "es"

    def test_reports_the_id_to_poll(self, api):
        api.status = 202
        api.body = an_audit(status="pending")
        text = call("launch_audit", repo_url="https://github.com/owner/repo")

        assert "aud123" in text
        assert "pending" in text
        assert 'get_audit("aud123")' in text

    def test_a_rejected_url_is_reported_not_raised(self, api):
        api.status = 400
        api.body = {"detail": "only github.com repositories are accepted"}
        text = call("launch_audit", repo_url="https://evil.example/x")

        assert "Could not launch the audit" in text
        assert "only github.com repositories are accepted" in text


class TestGetAudit:
    def test_gets_the_audit_by_id(self, api):
        api.body = an_audit(findings=[], verified_count=0)
        call("get_audit", audit_id="aud123")

        assert api.last.method == "GET"
        assert api.last.url.path == "/api/audits/aud123"
        # Absent rather than false: the API defaults it.
        assert "verified_only" not in api.last.url.params

    def test_verified_only_becomes_a_query_parameter(self, api):
        api.body = an_audit(findings=[], verified_count=0)
        call("get_audit", audit_id="aud123", verified_only=True)
        assert api.last.url.params["verified_only"] == "true"

    def test_renders_the_summary_and_the_findings(self, api):
        api.body = an_audit(verified_count=1, findings=[{
            "id": "f1",
            "severity": "critical",
            "category": "injection",
            "title": "SQL injection in the search handler",
            "description": "User input is concatenated into a query.",
            "file": "web/main.py",
            "line": 42,
            "anchor": "search_users",
            "fingerprint": "abcd1234",
            "verification_status": "verified",
        }])
        text = call("get_audit", audit_id="aud123")

        assert "audit aud123" in text
        assert "1 critical, 2 high" in text
        assert "[critical] SQL injection in the search handler" in text
        assert "web/main.py:42" in text
        assert "anchor: search_users" in text
        assert "User input is concatenated into a query." in text

    def test_an_unverified_finding_carries_its_reason(self, api):
        api.body = an_audit(verified_count=0, findings=[{
            "id": "f2",
            "severity": "medium",
            "category": "auth",
            "title": "Possible missing rate limit",
            "description": "No rate limiting was observed.",
            "file": None,
            "line": None,
            "anchor": None,
            "fingerprint": "beef",
            "verification_status": "unverified",
            "verification_note": "no file in the repository matched",
        }])
        text = call("get_audit", audit_id="aud123")

        assert "unverified" in text
        assert "note: no file in the repository matched" in text

    def test_a_running_audit_says_to_poll_again(self, api):
        api.body = an_audit(status="running", summary=None, findings=[],
                            verified_count=0)
        text = call("get_audit", audit_id="aud123")

        assert "running" in text
        assert "poll again" in text.lower()

    def test_an_unknown_id_is_reported_not_raised(self, api):
        api.status = 404
        api.body = {"detail": "audit not found"}
        text = call("get_audit", audit_id="nope")

        assert "Could not read audit nope" in text
        assert "not found" in text


class TestListAudits:
    def test_lists_from_the_audits_endpoint(self, api):
        api.body = [an_audit(), an_audit(id="aud456", status="running")]
        text = call("list_audits")

        assert api.last.method == "GET"
        assert api.last.url.path == "/api/audits"
        assert "aud123" in text and "aud456" in text
        assert "2 of 2 audit(s)" in text

    def test_limit_is_applied_client_side(self, api):
        api.body = [an_audit(id=f"aud{n}") for n in range(10)]
        text = call("list_audits", limit=3)

        assert "3 of 10 audit(s)" in text
        assert "aud3" not in text

    def test_limit_is_capped(self, api):
        api.body = [an_audit(id=f"aud{n}") for n in range(150)]
        text = call("list_audits", limit=5000)
        assert f"{mcp_module.MAX_LIMIT} of 150 audit(s)" in text

    def test_an_empty_instance_says_so(self, api):
        api.body = []
        assert "No audits yet" in call("list_audits")


class TestCheckHealth:
    def test_reads_the_health_endpoint(self, api):
        api.body = {"status": "ok", "git_available": True, "database": True,
                    "audits_stored": 7,
                    "backend": {"name": "anthropic-api", "ready": True,
                                "model": "claude-sonnet-4-6"}}
        text = call("check_health")

        assert api.last.method == "GET"
        assert api.last.url.path == "/api/health"
        assert "status: ok" in text
        assert "anthropic-api" in text

    def test_a_degraded_instance_is_explained(self, api):
        api.body = {"status": "degraded", "git_available": True,
                    "database": True, "audits_stored": 7,
                    "backend": {"name": "anthropic-api", "ready": False,
                                "detail": "ANTHROPIC_API_KEY is not set"}}
        text = call("check_health")

        assert "degraded" in text
        assert "ANTHROPIC_API_KEY is not set" in text
        assert "get_backend_status" in text

    def test_an_unreachable_instance_is_reported_not_raised(self, api):
        api.raises = httpx.ConnectError("nope")
        text = call("check_health")
        assert "is not answering" in text


class TestBackendStatus:
    def test_reads_the_settings_endpoint(self, api):
        api.body = {"backend": "anthropic-api", "model": "claude-sonnet-4-6",
                    "ollama_url": None, "api_key_set": True,
                    "updated_at": "2026-09-01T00:00:00Z",
                    "backend_status": {"name": "anthropic-api", "ready": True,
                                       "model": "claude-sonnet-4-6"}}
        text = call("get_backend_status")

        assert api.last.method == "GET"
        assert api.last.url.path == "/api/settings"
        assert "backend: anthropic-api" in text
        assert "ready: True" in text
        assert "API key stored: True" in text

    def test_never_reports_a_key_the_api_did_not_send(self, api):
        # /api/settings serialises api_key_set, never the key. Guard against a
        # future field leaking one through this formatter.
        api.body = {"backend": "openai-api", "model": None, "ollama_url": None,
                    "api_key_set": True, "updated_at": None,
                    "backend_status": {"name": "openai-api", "ready": True}}
        text = call("get_backend_status")
        assert "sk-" not in text


class TestServiceToken:
    def test_the_token_is_sent_as_a_bearer_header(self, api):
        api.body = []
        call("list_audits")
        assert api.last.headers["authorization"] == f"Bearer {TOKEN}"

    def test_no_token_means_no_header(self, api, monkeypatch):
        monkeypatch.delenv(mcp_module.TOKEN_ENV)
        api.body = {"status": "ok", "git_available": True, "database": True,
                    "audits_stored": 0, "backend": {}}
        call("check_health")
        assert "authorization" not in api.last.headers

    def test_a_rejected_token_says_how_to_fix_it(self, api):
        api.status = 401
        api.body = {"detail": "sign in to use secaudit"}
        text = call("list_audits")

        assert mcp_module.TOKEN_ENV in text
        assert "create runner token" in text

    def test_requests_go_to_the_configured_instance(self, api, monkeypatch):
        monkeypatch.setenv(mcp_module.API_URL_ENV, "https://other.example/")
        api.body = []
        call("list_audits")
        # The trailing slash is trimmed, not doubled into the path.
        assert str(api.last.url) == "https://other.example/api/audits"


class TestApiFailures:
    def test_a_server_error_reports_the_status(self, api):
        api.status = 500
        api.body = "upstream exploded"
        text = call("list_audits")

        assert "500" in text
        assert "upstream exploded" in text

    def test_a_non_json_answer_is_reported_not_raised(self, api):
        api.status = 200
        api.body = "<html>a proxy error page</html>"
        text = call("list_audits")
        assert "not JSON" in text
