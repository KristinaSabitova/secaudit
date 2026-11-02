"""Credentials committed to the repository, and when they were (B17, C25).

A deterministic scan, beside the model: known token formats (AWS, GitHub,
GitLab, Slack, Stripe, Google, Anthropic, OpenAI, private keys) and quoted
values assigned to names that say they are secret. It runs on the server's
own checkout and never prints a secret: a value is only ever stored as the
mask engine.redact_secrets uses — [REDACTED:<first six hex digits of its
SHA-256>] — which is enough to recognise the same secret again, in the file
or in history, and not enough to recover it.

The timeline reads the history the clone fetched (SECAUDIT_HISTORY_DEPTH) with
`git log -p`, never running a diff driver or a text conversion: for each
secret, the commit that first added it, every commit that added or removed it,
and whether it is still there at the audited commit. A secret removed from
the code is still in the history, so the advice is always to revoke and
rotate it; deleting the line does not undo the leak.
"""

import hashlib
import math
import re
from pathlib import Path

from .parallax import _git_run

SCANNER_VERSION = "1"

# Same character class evidence.py accepts for a masked value, so a masked
# snippet can be found again in the file it came from.
_VALUE = r"[A-Za-z0-9+/=_\-.]"

# name, pattern (group "v" is the secret), severity, whether the format alone
# confirms it is a credential.
PATTERNS = [
    ("private_key", re.compile(
        r"(?P<v>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)"),
     "critical", True),
    ("aws_access_key_id", re.compile(r"\b(?P<v>(?:AKIA|ASIA)[0-9A-Z]{16})\b"), "high", True),
    ("github_token", re.compile(r"\b(?P<v>(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})\b"),
     "high", True),
    ("github_fine_grained_token", re.compile(r"\b(?P<v>github_pat_[A-Za-z0-9_]{60,})\b"),
     "high", True),
    ("gitlab_token", re.compile(r"\b(?P<v>glpat-[A-Za-z0-9_\-]{20,})"), "high", True),
    ("slack_token", re.compile(r"\b(?P<v>xox[baprs]-[A-Za-z0-9\-]{10,})"), "high", True),
    ("stripe_live_key", re.compile(r"\b(?P<v>(?:sk|rk)_live_[A-Za-z0-9]{20,})"),
     "critical", True),
    ("google_api_key", re.compile(r"\b(?P<v>AIza[0-9A-Za-z_\-]{35})"), "high", True),
    ("anthropic_api_key", re.compile(r"(?P<v>sk-ant-[A-Za-z0-9_\-]{20,})"), "high", True),
    ("openai_api_key", re.compile(r"(?<![\w-])(?P<v>sk-(?:proj-)?[A-Za-z0-9_\-]{32,})"),
     "high", True),
    ("credentials_in_url", re.compile(
        rf"\b[a-z][a-z0-9+.\-]*://[^/\s:@'\"]+:(?P<v>{_VALUE}{{6,}})@[\w.\-]+"),
     "high", False),
    ("assigned_secret", re.compile(
        r"(?i)\b[\w.\-]*(?:password|passwd|pwd|secret|api[_\-]?key|apikey|token|"
        r"auth[_\-]?key|client[_\-]?secret|private[_\-]?key|access[_\-]?key)[\w.\-]*"
        rf"[\"']?\s*[:=]>?\s*[\"'](?P<v>{_VALUE}{{8,}})[\"']"),
     "high", False),
]

# What a placeholder looks like: a secret nobody would commit by mistake.
_PLACEHOLDER = re.compile(
    r"(?i)(example|sample|dummy|placeholder|changeme|change_me|your[_\-]|<|>|\$\{|"
    r"xxxx|\*\*\*\*|0000000|1234567|abcdef|test|fake|redacted|replace|todo|"
    r"process\.env|os\.environ|getenv)")

# Files where a credential-shaped string is almost always a fixture.
_FIXTURE_PATH = re.compile(r"(?i)(^|/)(tests?|spec|specs|__tests__|fixtures?|examples?|"
                           r"docs?|testdata)(/|$)|\.(md|rst|txt)$|(^|/)\.env\.(example|sample|template)$")
_SKIP_FILES = re.compile(r"(?i)(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|"
                         r"poetry\.lock|cargo\.lock|go\.sum|composer\.lock|uv\.lock)$|"
                         r"\.min\.(js|css)$|\.(svg|map)$")

MAX_FINDINGS = 200
MAX_LINE_CHARS = 400


def mask(value: str) -> str:
    """The same mask engine.redact_secrets writes."""
    return f"[REDACTED:{hashlib.sha256(value.encode()).hexdigest()[:6]}]"


def value_id(value: str) -> str:
    """A stable id for a secret: a longer hash than the mask, still one-way."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def _accept(kind: str, value: str, specific: bool) -> bool:
    if _PLACEHOLDER.search(value):
        return False
    if specific:
        return True
    # A generic match is only a secret when it looks random.
    return entropy(value) >= 3.3 and len(set(value)) >= 6


def scan_line(line: str) -> list[tuple[str, str, str, bool, int]]:
    """(kind, value, severity, specific, start) for every secret on one line."""
    out, taken = [], []
    for kind, pattern, severity, specific in PATTERNS:
        for m in pattern.finditer(line):
            start, end = m.span("v")
            if any(s < end and start < e for s, e in taken):
                continue                # a more specific pattern already has it
            value = m.group("v")
            if not _accept(kind, value, specific):
                continue
            taken.append((start, end))
            out.append((kind, value, severity, specific, start))
    return out


def redact_line(line: str) -> str:
    """The line with every secret on it masked. Used for snippets and logs."""
    for kind, value, *_ in scan_line(line):
        if kind != "private_key":       # the header names the key; it is not the key
            line = line.replace(value, mask(value))
    return line[:MAX_LINE_CHARS]


_TITLES = {
    "en": "Hardcoded credential ({kind})",
    "es": "Credencial en el código ({kind})",
}


def _finding(rel: str, n: int, line: str, kind: str, value: str, severity: str,
             specific: bool, language: str) -> dict:
    es = language == "es"
    fixture = bool(_FIXTURE_PATH.search(rel))
    confirmed = specific and not fixture
    snippet = redact_line(line).strip()
    return {
        "category": "secrets",
        "file": rel,
        "anchor": f"{kind}:{value_id(value)}",
        "severity": "medium" if fixture else severity,
        "title": _TITLES["es" if es else "en"].format(kind=kind.replace("_", " ")),
        "description": (
            ("Hay una credencial escrita en el repositorio. Quien pueda leer el "
             "repositorio o cualquier copia suya la tiene. Revócala y rótala: borrar la "
             "línea no la saca del historial de git. Guárdala en un gestor de secretos o "
             "en variables de entorno.")
            if es else
            ("A credential is written into the repository. Anyone who can read the "
             "repository, or any copy of it, has it. Revoke and rotate it: deleting the "
             "line does not remove it from git history. Keep it in a secret manager or "
             "the environment.")),
        "code_snippet": snippet,
        "line": n,
        "verification_status": "verified",
        "verification_note": "",
        "rule_id": f"secret.{kind}",
        "detail": {
            "cwe": "CWE-798",
            "scanner": f"secrets/{SCANNER_VERSION}",
            "secret_kind": kind,
            "secret_id": value_id(value),
            "assessment": "confirmed" if confirmed else "potential",
            "confidence": "high" if confirmed else "medium" if specific else "low",
            "prerequisites": [("acceso de lectura al repositorio o a una copia" if es
                               else "read access to the repository or a copy of it")],
            "impact": ("quien tenga la credencial actúa con sus permisos" if es
                       else "whoever holds it acts with its permissions"),
            "mitigation": ("revocar y rotar; sacarla del código; si el repositorio es "
                           "público, darla por comprometida" if es else
                           "revoke and rotate; move it out of the code; if the "
                           "repository is public, treat it as compromised"),
            "limits": ("no se comprueba si la credencial sigue activa: eso exigiría "
                       "usarla" if es else
                       "whether it is still live is not checked: that would mean using it"),
            "fixture": fixture,
        },
    }


def scan(texts: dict[str, str], language: str = "en") -> tuple[list[dict], dict]:
    """Every secret in the checkout as a finding dict, and a summary."""
    findings, seen = [], set()
    by_kind: dict[str, int] = {}
    for rel in sorted(texts):
        if _SKIP_FILES.search(rel):
            continue
        for n, line in enumerate(texts[rel].splitlines(), 1):
            if len(line) > 4000:        # minified or data; not where keys are typed
                continue
            for kind, value, severity, specific, _ in scan_line(line):
                key = (rel, value_id(value))
                if key in seen:
                    continue
                seen.add(key)
                by_kind[kind] = by_kind.get(kind, 0) + 1
                if len(findings) < MAX_FINDINGS:
                    findings.append(_finding(rel, n, line, kind, value, severity,
                                             specific, language))
    return findings, {"found": len(seen), "by_kind": by_kind,
                      "listed": len(findings), "version": SCANNER_VERSION}


# ---------------------------------------------------------------------------
# Secret Exposure Timeline
# ---------------------------------------------------------------------------

MAX_LOG_CHARS = 40_000_000
_COMMIT_MARK = "@@secaudit-commit@@ "


def _shallow_edge(project: Path) -> set[str]:
    r = _git_run(project, "rev-parse", "--git-path", "shallow")
    if r.returncode != 0:
        return set()
    path = Path(r.stdout.strip())
    path = path if path.is_absolute() else project / path
    try:
        return set(path.read_text().split())
    except OSError:
        return set()


def timeline(project: Path, max_commits: int = 200, timeout: int = 120) -> dict:
    """Every secret in the fetched history: when it came, when it went.

    Returns {"secrets": [...], "commits_read", "truncated", "history_edge"}.
    Each secret: kind, secret_id, mask, files, first_commit, first_date,
    added_in, removed_in, present_at_head, before_history (its first commit
    is where the shallow history stops, so it may be older).
    """
    r = _git_run(project, "log", f"--max-count={int(max_commits)}", "--reverse",
                 "-p", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
                 "--no-renames", f"--format={_COMMIT_MARK}%H %aI", "HEAD",
                 timeout=timeout)
    if r.returncode != 0:
        return {"secrets": [], "commits_read": 0, "truncated": False,
                "error": (r.stderr or "").strip().splitlines()[-1:] or ["git log failed"]}
    text = r.stdout
    truncated = len(text) > MAX_LOG_CHARS
    text = text[:MAX_LOG_CHARS]
    edge = _shallow_edge(project)
    secrets: dict[str, dict] = {}
    commit = date = None
    file = None
    commits = 0
    for raw in text.split("\n"):
        if raw.startswith(_COMMIT_MARK):
            commit, _, date = raw[len(_COMMIT_MARK):].partition(" ")
            commits += 1
            continue
        if raw.startswith("+++ "):
            file = raw[6:] if raw.startswith("+++ b/") else file
            continue
        if raw.startswith("--- "):
            if raw.startswith("--- a/"):
                file = raw[6:]
            continue
        if not raw or raw[0] not in "+-" or commit is None or len(raw) > 4000:
            continue
        if file and _SKIP_FILES.search(file):
            continue
        added = raw[0] == "+"
        for kind, value, *_ in scan_line(raw[1:]):
            sid = value_id(value)
            s = secrets.setdefault(sid, {
                "kind": kind, "secret_id": sid, "mask": mask(value),
                "files": [], "first_commit": None, "first_date": None,
                "added_in": [], "removed_in": []})
            if file and file not in s["files"]:
                s["files"].append(file)
            entry = {"commit": commit, "date": date, "file": file}
            s["_net"] = s.get("_net", 0) + (1 if added else -1)
            if added:
                if s["first_commit"] is None:
                    s["first_commit"], s["first_date"] = commit, date
                if len(s["added_in"]) < 20:
                    s["added_in"].append(entry)
            elif len(s["removed_in"]) < 20:
                s["removed_in"].append(entry)
    head = _git_run(project, "rev-parse", "HEAD")
    head_sha = head.stdout.strip() if head.returncode == 0 else None
    out = []
    for s in secrets.values():
        # Lines added minus lines removed, in history order: still there if > 0.
        net = s.pop("_net", 0)
        present = net > 0
        s["present_at_head"] = present
        s["last_seen_commit"] = head_sha if present else (
            s["removed_in"][-1]["commit"] if s["removed_in"] else None)
        s["before_history"] = bool(s["first_commit"] and s["first_commit"] in edge) \
            or (not s["added_in"] and bool(s["removed_in"]))
        s["recommendation"] = "revoke_and_rotate"
        out.append(s)
    out.sort(key=lambda s: (not s["present_at_head"], s["first_date"] or ""))
    return {"secrets": out[:MAX_FINDINGS], "commits_read": commits,
            "truncated": truncated, "history_edge": bool(edge),
            "head": head_sha}
