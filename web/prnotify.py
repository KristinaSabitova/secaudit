"""A pull request's audit, reported back on the pull request (B14).

Off by default. With SECAUDIT_PR_COMMENTS set and a token with write access
in SECAUDIT_GITHUB_WRITE_TOKEN, a webhook audit of a pull request:

- leaves one comment on the pull request, edited in place on every new push
  (found by a hidden marker), and
- sets a commit status, "secaudit", on the audited head commit.

What the comment says depends on SECAUDIT_PR_COMMENTS:

  summary  counts only (new, fixed, persisting, security drift) and a link
           to the audit. Nothing about where or what. The default when on.
  full     also the title, severity, assessment and file:line of each new
           finding. Never a code snippet. On a public repository this
           publishes where the weaknesses are: choose it knowingly.

The status fails when the pull request brings a new confirmed or potential
finding of high or critical severity, or weakens a control (drift), and
succeeds otherwise. Absence of findings is not a guarantee, and the status
description says "no new high findings", never "secure".

The token is separate from SECAUDIT_GITHUB_TOKEN (read-only, used by the
leverage map): the write token is used here and nowhere else, and only
against the repository the pull request belongs to. It needs "Pull
requests: write" (or "Issues: write") and "Commit statuses: write".
"""

import json
import os
import re
import urllib.error
import urllib.request

API = "https://api.github.com"
MODE_ENV = "SECAUDIT_PR_COMMENTS"
TOKEN_ENV = "SECAUDIT_GITHUB_WRITE_TOKEN"
MARKER = "<!-- secaudit:pr-report -->"
_REPO = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_.\-]{1,100}$")
_HIGH = {"critical", "high"}
_POSITIVE = {"confirmed", "potential"}
MAX_LISTED = 25


def mode() -> str | None:
    value = os.environ.get(MODE_ENV, "").strip().lower()
    if value in ("1", "true", "yes", "on"):
        value = "summary"
    return value if value in ("summary", "full") else None


def enabled() -> bool:
    return mode() is not None and bool(os.environ.get(TOKEN_ENV, "").strip())


def valid_repo(full_name: str | None) -> str | None:
    return full_name if full_name and _REPO.match(full_name) else None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None                     # a token never follows a redirect


class Writer:
    """The few GitHub calls this needs, on one repository."""

    def __init__(self, repo: str, token: str, opener=None):
        self.repo, self.token = repo, token
        self._opener = opener or urllib.request.build_opener(_NoRedirect())
        self.calls = 0

    def call(self, method: str, path: str, body: dict | None = None):
        if self.calls >= 20:
            raise RuntimeError("too many GitHub calls for one report")
        self.calls += 1
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{API}/repos/{self.repo}{path}", data=data,
                                     method=method, headers={
                                         "Accept": "application/vnd.github+json",
                                         "Authorization": f"Bearer {self.token}",
                                         "X-GitHub-Api-Version": "2022-11-28",
                                         "Content-Type": "application/json",
                                         "User-Agent": "secaudit"})
        try:
            with self._opener.open(req, timeout=15) as resp:
                raw = resp.read(2_000_000)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"GitHub answered {e.code} to {method} {path.split('?')[0]}")
        except (urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"GitHub could not be reached: {type(e).__name__}")
        return json.loads(raw) if raw else None

    def upsert_comment(self, number: int, body: str) -> str:
        for page in range(1, 4):
            comments = self.call("GET", f"/issues/{number}/comments?per_page=100&page={page}")
            for c in comments or []:
                if MARKER in (c.get("body") or ""):
                    self.call("PATCH", f"/issues/comments/{int(c['id'])}", {"body": body})
                    return "updated"
            if not comments or len(comments) < 100:
                break
        self.call("POST", f"/issues/{number}/comments", {"body": body})
        return "created"

    def status(self, sha: str, state: str, description: str, url: str | None):
        body = {"state": state, "context": "secaudit", "description": description[:140]}
        if url:
            body["target_url"] = url
        self.call("POST", f"/statuses/{sha}", body)


_T = {
    "en": {"title": "secaudit", "commit": "Audited commit", "base": "compared with",
           "new": "new", "fixed": "fixed", "persisting": "still there",
           "reintroduced": "reintroduced", "drift": "controls weakened",
           "open": "Open the audit", "listed": "New findings",
           "hidden": "Details are in the audit: this comment does not say where the "
                     "findings are, because pull request comments can be public.",
           "limit": "Static analysis; no finding is a vulnerability until checked, and "
                    "no finding is not a guarantee.",
           "fail": "new high findings or weakened controls",
           "ok": "no new high findings and no weakened controls",
           "more": "and {n} more"},
    "es": {"title": "secaudit", "commit": "Commit auditado", "base": "comparado con",
           "new": "nuevos", "fixed": "corregidos", "persisting": "siguen",
           "reintroduced": "reintroducidos", "drift": "controles debilitados",
           "open": "Abrir la auditoría", "listed": "Hallazgos nuevos",
           "hidden": "El detalle está en la auditoría: este comentario no dice dónde están "
                     "los hallazgos, porque los comentarios de un PR pueden ser públicos.",
           "limit": "Análisis estático: ningún hallazgo es una vulnerabilidad hasta "
                    "comprobarlo, y no tener hallazgos no es una garantía.",
           "fail": "hallazgos altos nuevos o controles debilitados",
           "ok": "sin hallazgos altos nuevos ni controles debilitados",
           "more": "y {n} más"},
}


def _md(text) -> str:
    """Repository text in markdown, defused: no links, mentions, HTML or code."""
    s = re.sub(r"[\r\n]+", " ", str(text or ""))[:200]
    s = re.sub(r"([\\`*_{}\[\]<>()#+!|~])", r"\\\1", s)
    return s.replace("@", "@​").replace("://", ":​//")


def report(diff: dict, drift_items: list, language: str, mode_: str, link: str | None,
           commit: str | None, base: str | None) -> tuple[str, str, str]:
    """(comment body, status state, status description)."""
    T = _T["es" if language == "es" else "en"]
    new = [f for f in diff.get("new") or [] if f.get("assessment") in _POSITIVE]
    blocking = [f for f in new if f.get("severity") in _HIGH] or drift_items
    counts = {k: len(diff.get(k) or []) for k in ("fixed", "persisting", "reintroduced")}
    lines = [MARKER, f"### {T['title']}", ""]
    lines.append(f"{T['commit']} `{(commit or '')[:12]}`"
                 + (f" · {T['base']} `{base[:12]}`" if base else ""))
    lines.append("")
    lines.append(" · ".join([f"**{len(new)}** {T['new']}",
                             f"**{counts['fixed']}** {T['fixed']}",
                             f"**{counts['persisting']}** {T['persisting']}",
                             f"**{counts['reintroduced']}** {T['reintroduced']}",
                             f"**{len(drift_items)}** {T['drift']}"]))
    lines.append("")
    if mode_ == "full" and new:
        lines.append(f"**{T['listed']}**")
        lines.append("")
        for f in new[:MAX_LISTED]:
            where = f"{_md(f.get('file'))}:{int(f['line'])}" if isinstance(f.get("line"), int) \
                else _md(f.get("file"))
            lines.append(f"- {_md((f.get('severity') or '').upper())} · "
                         f"{_md(f.get('assessment'))} · {_md(f.get('title'))} · {where}")
        if len(new) > MAX_LISTED:
            lines.append(f"- {T['more'].format(n=len(new) - MAX_LISTED)}")
        lines.append("")
    elif new:
        lines.append(f"_{T['hidden']}_")
        lines.append("")
    if link:
        lines.append(f"[{T['open']}]({link})")
        lines.append("")
    lines.append(f"<sub>{T['limit']}</sub>")
    state = "failure" if blocking else "success"
    return "\n".join(lines), state, T["fail"] if blocking else T["ok"]


def notify(repo: str, number: int, sha: str, diff: dict, drift_items: list, language: str,
           link: str | None, base: str | None, opener=None) -> dict:
    """Post the report. Returns what was done; raises RuntimeError on failure."""
    mode_ = mode()
    token = os.environ.get(TOKEN_ENV, "").strip()
    if not mode_ or not token:
        return {"posted": False, "reason": "disabled"}
    if not valid_repo(repo) or not re.fullmatch(r"[0-9a-f]{40}", sha or "") or not number:
        return {"posted": False, "reason": "no pull request to report on"}
    body, state, description = report(diff, drift_items, language, mode_, link, sha, base)
    w = Writer(repo, token, opener)
    comment = w.upsert_comment(int(number), body)
    w.status(sha, state, description, link)
    return {"posted": True, "comment": comment, "state": state, "mode": mode_,
            "repo": repo, "pr": number, "calls": w.calls}
