"""MCP server exposing a deployed secaudit instance to an MCP client.

Every tool is a one-to-one wrapper over an endpoint the web app already serves.
No audit logic lives here: the engine, the queue and the database stay behind
the REST API, and this process only speaks HTTP to it. That is what keeps the
tool honest — anything it reports, the dashboard reports too.

Run it over stdio, which is what Claude Desktop and Claude Code start:

    SECAUDIT_MCP_TOKEN=... python3 -m mcp_server.server
"""

import os
from typing import Any

import httpx
from mcp.server.mcpserver import MCPServer

DEFAULT_API_URL = "https://secaudit.ksabitova.dev"
API_URL_ENV = "SECAUDIT_API_URL"
TOKEN_ENV = "SECAUDIT_MCP_TOKEN"

# Audits are queued, not run inline, so no request here waits on one.
TIMEOUT = 30.0
# An instance can hold thousands of audits and the list endpoint returns all of
# them; an unbounded listing would be answered straight into the model context.
DEFAULT_LIMIT = 20
MAX_LIMIT = 100

SEVERITIES = ("critical", "high", "medium", "low", "info")

server = MCPServer(
    name="secaudit",
    version="1.0.0",
    instructions=(
        "Audits GitHub repositories for security flaws through a hosted "
        "secaudit instance. Audits run in the background: launch_audit "
        "returns immediately with an id, and get_audit is how you read the "
        "findings once its status reaches 'done'."
    ),
)


class ApiError(Exception):
    """The API could not be reached, or refused the request."""


def api_url() -> str:
    return os.environ.get(API_URL_ENV, DEFAULT_API_URL).rstrip("/")


def _headers() -> dict[str, str]:
    """The service token, when one is configured.

    /api/health needs no credentials, so an unconfigured server is still
    useful for checking whether the instance is up.
    """
    token = os.environ.get(TOKEN_ENV, "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def _client() -> httpx.AsyncClient:
    """The HTTP client every tool goes through. Tests swap in a transport."""
    return httpx.AsyncClient(base_url=api_url(), timeout=TIMEOUT)


def _detail(response: httpx.Response) -> str:
    """The API's own error message, when it sent one."""
    try:
        body = response.json()
    except ValueError:
        return response.text[:200].strip()
    if isinstance(body, dict) and body.get("detail"):
        return str(body["detail"])
    return response.text[:200].strip()


async def _request(method: str, path: str, **kwargs: Any) -> Any:
    async with _client() as client:
        try:
            response = await client.request(method, path, headers=_headers(),
                                            **kwargs)
        except httpx.HTTPError as e:
            raise ApiError(f"could not reach {api_url()}: {e}") from e

    if response.status_code == 401:
        raise ApiError(
            f"{api_url()} rejected the service token. Set {TOKEN_ENV} to a "
            "token issued from the dashboard's backend panel "
            "('create runner token'); a revoked or mistyped one reads the same."
        )
    if response.status_code == 404:
        raise ApiError("not found — no audit with that id belongs to this "
                       "account, or it has been deleted")
    if response.status_code >= 400:
        raise ApiError(f"{api_url()} answered {response.status_code}: "
                       f"{_detail(response)}")

    if response.status_code == 204 or not response.content:
        return None
    try:
        return response.json()
    except ValueError:
        raise ApiError(f"{api_url()} answered {response.status_code} with "
                       "something that is not JSON") from None


def _counts(summary: dict | None) -> str:
    """Severity counts, leaving out the severities with nothing in them."""
    summary = summary or {}
    parts = [f"{summary[s]} {s}" for s in SEVERITIES if summary.get(s)]
    return ", ".join(parts) if parts else "no findings"


def _audit_line(audit: dict) -> str:
    line = (f"{audit.get('id')}  {audit.get('status')}  "
            f"{audit.get('repo_url')}")
    if audit.get("commit_sha"):
        line += f"@{str(audit['commit_sha'])[:8]}"
    line += f"  [{_counts(audit.get('summary'))}]"
    if audit.get("error"):
        line += f"  error: {audit['error']}"
    return line


def _finding_block(finding: dict) -> str:
    head = (f"[{finding.get('severity')}] {finding.get('title')} "
            f"({finding.get('category')}, {finding.get('verification_status')})")
    lines = [head]
    where = finding.get("file")
    if where:
        if finding.get("line"):
            where += f":{finding['line']}"
        if finding.get("anchor"):
            where += f"  anchor: {finding['anchor']}"
        lines.append(f"  {where}")
    if finding.get("description"):
        lines.append(f"  {finding['description']}")
    if finding.get("verification_note"):
        lines.append(f"  note: {finding['verification_note']}")
    return "\n".join(lines)


@server.tool()
async def launch_audit(repo_url: str, language: str = "en") -> str:
    """Queue a security audit of a public GitHub repository.

    The audit runs in the background: this returns as soon as it is queued,
    with the id to poll. Call get_audit with that id until its status is
    'done' (or 'error'); a real audit takes minutes, not seconds.

    repo_url: the repository to audit, e.g. https://github.com/owner/repo
    language: 'en' or 'es' — the language the findings are written in.
    """
    try:
        audit = await _request("POST", "/api/audits",
                               json={"repo_url": repo_url, "language": language})
    except ApiError as e:
        return f"Could not launch the audit: {e}"
    return (f"Audit queued.\n"
            f"id: {audit.get('id')}\n"
            f"repository: {audit.get('repo_url')}\n"
            f"status: {audit.get('status')}\n"
            f"language: {audit.get('language')}\n\n"
            f"Poll it with get_audit(\"{audit.get('id')}\").")


@server.tool()
async def get_audit(audit_id: str, verified_only: bool = False) -> str:
    """Read one audit and its findings.

    Every finding says whether it is anchored to code that was actually
    audited. A 'verified' finding carries a file and an anchor you can open;
    an 'unverified' one is reported with the reason it could not be tied to
    code, and must never be presented as confirmed.

    audit_id: the id returned by launch_audit or list_audits.
    verified_only: leave out the findings not backed by code.
    """
    params = {"verified_only": "true"} if verified_only else None
    try:
        audit = await _request("GET", f"/api/audits/{audit_id}", params=params)
    except ApiError as e:
        return f"Could not read audit {audit_id}: {e}"

    head = [
        f"audit {audit.get('id')}",
        f"repository: {audit.get('repo_url')}",
        f"status: {audit.get('status')}",
        f"created: {audit.get('created_at')}",
        f"summary: {_counts(audit.get('summary'))}",
    ]
    if audit.get("commit_sha"):
        head.insert(2, f"commit: {audit['commit_sha']}")
    if audit.get("error"):
        head.append(f"error: {audit['error']}")

    findings = audit.get("findings") or []
    verified = audit.get("verified_count")
    if verified is not None:
        head.append(f"{len(findings)} finding(s) listed, "
                    f"{verified} of them backed by evidence"
                    + (" (unverified ones filtered out)" if verified_only else ""))
    if not findings:
        if audit.get("status") in ("pending", "running"):
            head.append("Still running — poll again in a minute.")
        return "\n".join(head)

    blocks = "\n\n".join(_finding_block(f) for f in findings)
    return "\n".join(head) + "\n\n" + blocks


@server.tool()
async def list_audits(limit: int = DEFAULT_LIMIT) -> str:
    """List recent audits for this account, newest first.

    Use it to find the id of an audit launched earlier, or to see what is
    still running.

    limit: how many to return, newest first (1-100).
    """
    try:
        audits = await _request("GET", "/api/audits")
    except ApiError as e:
        return f"Could not list audits: {e}"
    if not audits:
        return "No audits yet. Launch one with launch_audit."

    capped = max(1, min(limit, MAX_LIMIT))
    shown = audits[:capped]
    lines = [_audit_line(a) for a in shown]
    header = f"{len(shown)} of {len(audits)} audit(s), newest first:"
    return header + "\n" + "\n".join(lines)


@server.tool()
async def check_health() -> str:
    """Check whether the secaudit instance is up and able to run audits.

    Reports git, the database and the instance-level backend. Needs no
    token, so it also tells you whether the address itself is right.
    """
    try:
        health = await _request("GET", "/api/health")
    except ApiError as e:
        return f"{api_url()} is not answering: {e}"

    backend = health.get("backend") or {}
    lines = [
        f"{api_url()} — status: {health.get('status')}",
        f"git available: {health.get('git_available')}",
        f"database: {health.get('database')}",
        f"audits stored: {health.get('audits_stored')}",
        f"instance backend: {backend.get('name')} "
        f"(ready: {backend.get('ready')})",
    ]
    if backend.get("detail"):
        lines.append(f"  {backend['detail']}")
    if health.get("status") != "ok":
        lines.append("'degraded' at instance level is expected here: audits "
                     "run with the key stored in your dashboard, not the "
                     "instance's. get_backend_status reports that one.")
    return "\n".join(lines)


@server.tool()
async def get_backend_status() -> str:
    """Report the LLM backend this account's audits will actually run with.

    Worth checking before launch_audit: an audit queued against a backend
    with no usable key ends in 'error'. The API key itself is never returned,
    only whether one is stored.
    """
    try:
        settings = await _request("GET", "/api/settings")
    except ApiError as e:
        return f"Could not read the backend settings: {e}"

    backend = settings.get("backend_status") or {}
    lines = [
        f"backend: {settings.get('backend') or backend.get('name')}",
        f"model: {settings.get('model') or backend.get('model') or 'default'}",
        f"ready: {backend.get('ready')}",
        f"API key stored: {settings.get('api_key_set')}",
    ]
    if settings.get("ollama_url"):
        lines.append(f"ollama url: {settings['ollama_url']}")
    if backend.get("detail"):
        lines.append(f"detail: {backend['detail']}")
    return "\n".join(lines)


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
