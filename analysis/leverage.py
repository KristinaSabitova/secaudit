"""Module 4: the leverage map. Where is it fragile, and who is watching?

Every file gets two scores. Leverage is how much damage a malicious change to
it could do: a deploy workflow or an install script reaches further than a
test. Oversight is how much real human review that file gets: an owner in
CODEOWNERS, recent changes that came in through an approved pull request, a
protected default branch. The files that matter are the ones with much of the
first and little of the second, and each score comes with its reasons, so the
map says why, not just how much.

The agent surface is computed here too: what an AI agent opening the
repository would inherit — permissions, MCP servers, hooks, instructions —
and the combinations of those that make a complete path (read files, reach
the network, run without anyone asking), reported as a path, not as loose
patterns.

Nothing here runs the audited code. git reads its history; GitHub's API is
asked, read-only, only with SECAUDIT_GITHUB_TOKEN, and without it whatever
only GitHub knows is reported as unknown, never guessed.
"""

import json
import os
import re
import subprocess
import urllib.error
import urllib.request
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

from . import chunking
from .immune import _git, ai_declared, shallow_edge
from .parallax import (_CLAUDE_COMMAND_KEYS, _SUSPICIOUS_COMMAND, _load_json)

# ---------------------------------------------------------------------------
# Leverage
# ---------------------------------------------------------------------------

# The base leverage of each risk tier, before anything specific to the file.
TIER_LEVERAGE = {
    chunking.AUTO_EXECUTION: 0.85,
    chunking.AGENT_CONFIG: 0.85,
    chunking.ENTRY_POINT: 0.7,
    chunking.AUTH_SECRETS: 0.8,
    chunking.CODE: 0.4,
    chunking.TESTS_DOCS_DATA: 0.1,
}
_TIER_CODE = {
    chunking.AUTO_EXECUTION: "auto_execution",
    chunking.AGENT_CONFIG: "agent_config",
    chunking.ENTRY_POINT: "entry_point",
    chunking.AUTH_SECRETS: "auth",
    chunking.CODE: "code",
    chunking.TESTS_DOCS_DATA: "tests_docs",
}

_DEPLOY = re.compile(r"(?im)\b(deploy|release|publish|upload|push|docker/login|"
                     r"twine|npm\s+publish|gh\s+release|kubectl|helm|terraform\s+apply|"
                     r"aws\s|gcloud|azure/|ssh\s|rsync|scp\s)")
_SECRETS = re.compile(r"\$\{\{\s*secrets\.(?!GITHUB_TOKEN\b)[A-Za-z0-9_]+")
_PR_TARGET = re.compile(r"(?m)^\s*(on:\s*\[?[^\n]*\bpull_request_target\b|"
                        r"pull_request_target\s*:|-\s*pull_request_target\b)")
_WRITE_PERMS = re.compile(r"(?m)^\s*(permissions:\s*write-all|"
                          r"(contents|packages|id-token|actions|deployments)\s*:\s*write)")
_INSTALL_SCRIPTS = re.compile(r'"(pre|post)?install"\s*:|"prepare"\s*:')
_LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
              "cargo.lock", "gemfile.lock", "composer.lock", "pipfile.lock",
              "uv.lock", "go.sum", "requirements.txt"}
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")


def _reason(side: str, code: str, delta: float = 0.0, **args) -> dict:
    return {"side": side, "code": code, "delta": round(delta, 3), "args": args}


_SCRIPT_REF = re.compile(r"(?<![\w/.-])(?:\./)?((?:[\w.-]+/)*[\w.-]+\.(?:sh|bash|py|js|mjs|"
                         r"cjs|ts|rb|pl|ps1|php))\b")


def runners_of(texts: dict[str, str], files: set[str]) -> dict[str, str]:
    """Scripts of this repository that something running on its own runs:
    a CI workflow, an install script, a git or agent hook. Each, with what runs it."""
    out = {}
    for rel, text in sorted(texts.items()):
        tier, _ = chunking.classify_path(rel)
        if tier not in (chunking.AUTO_EXECUTION, chunking.AGENT_CONFIG) or \
                rel.lower().endswith((".md", ".mdc")):
            continue
        base = PurePosixPath(rel).parent
        name = PurePosixPath(rel).name.lower()
        for line in text.splitlines():
            if not _runs(name, line):
                continue
            for m in _SCRIPT_REF.finditer(line):
                ref = m.group(1)
                for candidate in (ref, (base / ref).as_posix()):
                    if candidate in files and candidate != rel:
                        out.setdefault(candidate, rel)
                        break
    return out


def _runs(name: str, line: str) -> bool:
    """Whether this line of a file that runs on its own runs what it names.
    A comment does not; in a Dockerfile, COPY does not; in a compose file,
    only the command and the entrypoint do."""
    stripped = line.strip()
    if not stripped or stripped.startswith(("#", "//")):
        return False
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return bool(re.match(r"(?i)(run|cmd|entrypoint)\b", stripped))
    if name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml",
                "compose.yaml"):
        return bool(re.match(r"(?i)-?\s*(command|entrypoint)\s*:", stripped))
    return True


def leverage_of(rel: str, text: str | None, findings: int = 0,
                divergences: list[str] | None = None,
                on_attack_path: bool = False,
                run_by: str | None = None) -> tuple[float, list[dict]]:
    """How much damage a malicious change to this file could do, and why."""
    tier, _ = chunking.classify_path(rel)
    p = PurePosixPath(rel.lower())
    name = p.name
    score = TIER_LEVERAGE[tier]
    reasons = []
    text = text or ""
    if rel in CODEOWNERS_PATHS:
        score = 0.85
        reasons.append(_reason("leverage", "codeowners_file", score))
    elif rel.lower().startswith(".github/workflows/") and name.endswith((".yml", ".yaml")):
        score = 0.85
        reasons.append(_reason("leverage", "ci_workflow", score))
        if _DEPLOY.search(text):
            score += 0.1
            reasons.append(_reason("leverage", "ci_deploy", 0.1))
        if _SECRETS.search(text):
            score += 0.05
            reasons.append(_reason("leverage", "ci_secrets", 0.05))
        if _PR_TARGET.search(text):
            score += 0.1
            reasons.append(_reason("leverage", "ci_pr_target", 0.1))
        if _WRITE_PERMS.search(text):
            score += 0.05
            reasons.append(_reason("leverage", "ci_write_perms", 0.05))
    elif name == "package.json" and _INSTALL_SCRIPTS.search(text):
        score = 0.9
        reasons.append(_reason("leverage", "install_script", score))
    elif name in ("setup.py", "conftest.py", ".pre-commit-config.yaml") or \
            any(part in (".husky", ".githooks", "githooks") for part in p.parts):
        score = 0.9
        reasons.append(_reason("leverage", "install_script", score))
    elif name.startswith("dockerfile") or name in ("docker-compose.yml",
                                                     "docker-compose.yaml",
                                                     "compose.yml", "compose.yaml"):
        score = 0.75
        reasons.append(_reason("leverage", "container", score))
    elif name in _LOCKFILES:
        score = 0.5
        reasons.append(_reason("leverage", "lockfile", score))
    elif name.startswith(".env"):
        score = 0.8
        reasons.append(_reason("leverage", "env_file", score))
    else:
        reasons.append(_reason("leverage", _TIER_CODE[tier], score))
    if run_by and score < 0.85:
        reasons.append(_reason("leverage", "run_by", 0.85 - score, by=run_by))
        score = 0.85
    if findings:
        score += 0.1
        reasons.append(_reason("leverage", "finding", 0.1, count=findings))
    for kind in sorted(set(divergences or [])):
        if kind in ("hidden_content", "unexpected_execution"):
            score += 0.1
            reasons.append(_reason("leverage", "divergence", 0.1, kind=kind))
    if on_attack_path:
        score += 0.1
        reasons.append(_reason("leverage", "attack_path", 0.1))
    return round(min(1.0, score), 3), reasons


# ---------------------------------------------------------------------------
# CODEOWNERS
# ---------------------------------------------------------------------------

def _codeowners_regex(pattern: str) -> re.Pattern | None:
    """A CODEOWNERS pattern as a regex over repository paths (gitignore rules)."""
    if not pattern or pattern.startswith("!") or "[" in pattern:
        return None                       # not supported by GitHub either
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    directory = pattern.endswith("/")
    body = pattern.strip("/")
    out, i = "", 0
    while i < len(body):
        if body.startswith("**/", i):
            out += "(?:.*/)?"
            i += 3
        elif body.startswith("/**", i) and i + 3 == len(body):
            out += "/.*"
            i += 3
        elif body.startswith("**", i):
            out += ".*"
            i += 2
        elif body[i] == "*":
            out += "[^/]*"
            i += 1
        elif body[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(body[i])
            i += 1
    prefix = "^" if anchored else "^(?:.*/)?"
    # A pattern that names a directory owns everything under it.
    suffix = "/.*$" if directory else "(?:/.*)?$"
    return re.compile(prefix + out + suffix)


def parse_codeowners(text: str) -> list[tuple[re.Pattern, list[str], str]]:
    rules = []
    for line in text.splitlines():
        line = line.split(" #")[0].strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        regex = _codeowners_regex(parts[0])
        if regex is not None:
            rules.append((regex, parts[1:], parts[0]))
    return rules


def owners_of(rules, rel: str) -> tuple[list[str], str] | None:
    """The owners of a path: the last rule that matches wins, as on GitHub.
    None when no rule matches; an empty list when the last match removes them."""
    found = None
    for regex, owners, pattern in rules:
        if regex.match(rel):
            found = (owners, pattern)
    return found


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

def tracked_files(project: Path) -> list[str]:
    r = _git(project, "ls-files", "-z")
    if r.returncode != 0:
        return []
    out = []
    for rel in r.stdout.split("\0"):
        parts = PurePosixPath(rel).parts
        if rel and not any(p in chunking.SKIP_DIRS for p in parts[:-1]):
            out.append(rel)
    return out


def history(project: Path, per_file: int = 3) -> dict:
    """The last commits that changed each file, newest first, from what was fetched.

    A commit that came in through a merged pull request is tagged with its
    number: from the merge commit's subject, for the commits it brought in,
    or from a squash commit's "(#123)".
    """
    r = _git(project, "log", "--no-renames", "--format=%x1e%H%x1f%P%x1f%s%x1f%B%x1f",
             "--name-only", timeout=300)
    commits, files = {}, {}
    if r.returncode != 0:
        return {"commits": commits, "files": files, "shallow": False}
    for record in r.stdout.split("\x1e")[1:]:
        fields = record.split("\x1f")
        if len(fields) < 5:
            continue
        sha, parents, subject, body, names = fields[:5]
        parents = parents.split()
        squash = re.search(r"\(#(\d+)\)\s*$", subject)
        commits[sha] = {"sha": sha, "parents": parents, "subject": subject[:200],
                        "ai_declared": ai_declared(body),
                        "pr": int(squash.group(1)) if squash else None}
        for name in names.strip().splitlines():
            name = name.strip()
            if name and len(files.setdefault(name, [])) < per_file:
                files[name].append(sha)
    # Merge commits name the pull request; the commits on their second
    # parent's side are the ones it brought in.
    for sha, c in commits.items():
        m = re.match(r"Merge pull request #(\d+)", c["subject"])
        if not m or len(c["parents"]) < 2:
            continue
        brought = _git(project, "rev-list", f"{c['parents'][0]}..{c['parents'][1]}")
        for inner in brought.stdout.split() if brought.returncode == 0 else []:
            if inner in commits and commits[inner]["pr"] is None:
                commits[inner]["pr"] = int(m.group(1))
    return {"commits": commits, "files": files,
            "shallow": bool(shallow_edge(project))}


# ---------------------------------------------------------------------------
# GitHub, read-only
# ---------------------------------------------------------------------------

API = "https://api.github.com"
MAX_API_CALLS = 120
_REPO_RE = re.compile(r"^https://github\.com/([A-Za-z0-9][A-Za-z0-9_.\-]*)/"
                      r"([A-Za-z0-9_.\-]+?)(?:\.git)?/?$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith(API + "/"):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class GitHub:
    """GitHub's REST API with a read-only token, within a budget of calls."""

    def __init__(self, repo_url: str, token: str | None, budget: int = MAX_API_CALLS,
                 opener=None):
        m = _REPO_RE.match(repo_url or "")
        self.repo = f"{m.group(1)}/{m.group(2)}" if m else None
        self.token = token
        self.budget = budget
        self.calls = 0
        self.error = None
        self._opener = opener or urllib.request.build_opener(_NoRedirect())
        self._cache = {}

    @property
    def usable(self) -> bool:
        return bool(self.repo and self.token) and self.error is None

    def get(self, path: str):
        if not self.usable:
            return None
        if path in self._cache:
            return self._cache[path]
        if self.calls >= self.budget:
            self.error = self.error or f"the budget of {self.budget} API calls ran out"
            return None
        self.calls += 1
        req = urllib.request.Request(f"{API}/repos/{self.repo}{path}", headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "secaudit"})
        try:
            with self._opener.open(req, timeout=15) as resp:
                data = json.loads(resp.read(2_000_000).decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                data = None              # absent is an answer
            else:
                self.error = f"GitHub answered {e.code}"
                return None
        except (urllib.error.URLError, OSError, ValueError) as e:
            self.error = f"GitHub could not be reached: {type(e).__name__}"
            return None
        self._cache[path] = data
        return data

    def protection(self) -> dict:
        """Whether the default branch requires a reviewed pull request."""
        info = self.get("")
        branch = info.get("default_branch") if isinstance(info, dict) else None
        if not branch:
            return {"known": False}
        out = {"known": True, "branch": branch, "protected": False,
               "required_reviews": 0}
        b = self.get(f"/branches/{urllib.request.quote(branch, safe='')}")
        if isinstance(b, dict):
            out["protected"] = bool(b.get("protected"))
            reviews = ((b.get("protection") or {}).get("required_pull_request_reviews")
                       or {})
            out["required_reviews"] = int(reviews.get("required_approving_review_count")
                                          or 0)
        rules = self.get(f"/rules/branches/{urllib.request.quote(branch, safe='')}")
        for rule in rules if isinstance(rules, list) else []:
            if isinstance(rule, dict) and rule.get("type") == "pull_request":
                out["protected"] = True
                count = (rule.get("parameters") or {}).get("required_approving_review_count")
                out["required_reviews"] = max(out["required_reviews"], int(count or 0))
        if self.error:
            return {"known": False}
        return out

    def review(self, sha: str) -> dict | None:
        """The pull request a commit came in through, and whether someone other
        than its author approved it. None when GitHub could not say."""
        pulls = self.get(f"/commits/{sha}/pulls")
        if pulls is None or not isinstance(pulls, list):
            return None
        merged = [p for p in pulls if isinstance(p, dict) and p.get("merged_at")]
        if not merged:
            return {"pr": None, "approved": False}
        pr = merged[0]
        author = (pr.get("user") or {}).get("login")
        reviews = self.get(f"/pulls/{int(pr['number'])}/reviews")
        if reviews is None:
            return None
        approved = any(isinstance(r, dict) and r.get("state") == "APPROVED"
                       and (r.get("user") or {}).get("login") != author
                       for r in reviews if isinstance(reviews, list))
        return {"pr": int(pr["number"]), "approved": approved}


def github_token() -> str | None:
    return (os.environ.get("SECAUDIT_GITHUB_TOKEN") or "").strip() or None


# ---------------------------------------------------------------------------
# Oversight
# ---------------------------------------------------------------------------

OWNER_WEIGHT = 0.35
REVIEW_WEIGHT = 0.35
PR_WEIGHT = 0.15            # a pull request whose approval is not known
PROTECTION_WEIGHT = 0.3
AI_UNREVIEWED_PENALTY = 0.15


def oversight_of(rel: str, codeowners, owners_file: str | None, hist: dict,
                 reviews: dict, protection: dict) -> tuple[float, list[dict]]:
    """How much real human review this file gets, and why."""
    score, reasons = 0.0, []
    if owners_file is None:
        reasons.append(_reason("oversight", "no_codeowners"))
    else:
        found = owners_of(codeowners, rel)
        if found and found[0]:
            score += OWNER_WEIGHT
            reasons.append(_reason("oversight", "owner", OWNER_WEIGHT,
                                   owners=found[0][:5], pattern=found[1]))
        elif found:
            reasons.append(_reason("oversight", "owners_removed", pattern=found[1]))
        else:
            reasons.append(_reason("oversight", "no_owner", file=owners_file))

    recent = hist["files"].get(rel) or []
    if not recent:
        reasons.append(_reason("oversight", "old"))
    else:
        approved = through_pr = unknown = 0
        direct = []
        for sha in recent:
            c = hist["commits"].get(sha, {})
            r = reviews.get(sha)
            if r is not None and r.get("approved"):
                approved += 1
            elif (r or {}).get("pr") or (r is None and c.get("pr")):
                through_pr += 1
                unknown += r is None
            else:
                direct.append(sha)
        n = len(recent)
        if approved:
            delta = REVIEW_WEIGHT * approved / n
            score += delta
            reasons.append(_reason("oversight", "approved", delta, count=approved, of=n))
        if through_pr:
            delta = PR_WEIGHT * through_pr / n
            score += delta
            reasons.append(_reason("oversight",
                                   "pr_approval_unknown" if unknown else "pr_unapproved",
                                   delta, count=through_pr, of=n))
        if direct:
            reasons.append(_reason("oversight", "direct", count=len(direct), of=n,
                                   last=direct[0][:12]))
        last = hist["commits"].get(recent[0], {})
        last_review = reviews.get(recent[0])
        if last.get("ai_declared") and not (last_review and last_review.get("approved")):
            score -= AI_UNREVIEWED_PENALTY
            reasons.append(_reason("oversight", "ai_unreviewed", -AI_UNREVIEWED_PENALTY,
                                   commit=recent[0][:12]))

    if not protection.get("known"):
        reasons.append(_reason("oversight", "protection_unknown"))
    elif protection.get("required_reviews"):
        score += PROTECTION_WEIGHT
        reasons.append(_reason("oversight", "protected_reviews", PROTECTION_WEIGHT,
                               count=protection["required_reviews"],
                               branch=protection["branch"]))
    elif protection.get("protected"):
        score += 0.1
        reasons.append(_reason("oversight", "protected", 0.1,
                               branch=protection["branch"]))
    else:
        reasons.append(_reason("oversight", "unprotected", branch=protection["branch"]))
    return round(max(0.0, min(1.0, score)), 3), reasons


def priority(leverage: float, oversight: float) -> float:
    """Much leverage, little oversight: what to look at first."""
    return round(leverage * (1 - oversight), 3)


# ---------------------------------------------------------------------------
# The agent surface
# ---------------------------------------------------------------------------

READS_FILES, NETWORK, EXECUTES = "reads_files", "network", "executes"
RUNS_ON_START, MCP_SERVER, INSTRUCTIONS = "runs_on_start", "mcp_server", "instructions"

_NETWORK_COMMAND = re.compile(r"(?i)\b(curl|wget|nc|netcat|ssh|scp|rsync|ftp|"
                              r"telnet|socat|http|fetch|npx|uvx|pipx|docker\s+run)\b")
_INSTRUCTION_NAMES = {"claude.md", "claude.local.md", "agents.md", "agent.md",
                      "gemini.md", ".cursorrules", ".windsurfrules", ".clinerules",
                      "copilot-instructions.md", ".goosehints"}
_INSTRUCTION_DIRS = (".claude/commands/", ".claude/agents/", ".claude/skills/",
                     ".cursor/rules/", ".github/instructions/", ".github/prompts/",
                     ".clinerules/", ".windsurf/rules/", ".kiro/steering/")


def _cap(source: str, capability: str, detail: str) -> dict:
    return {"source_file": source, "capability": capability, "detail": detail[:1000]}


def _permission(rel: str, entry: str) -> list[dict]:
    m = re.match(r"^\s*([A-Za-z_]+)(?:\((.*)\))?\s*$", entry)
    if not m:
        return []
    tool, arg = m.group(1), (m.group(2) or "").strip()
    what = f'permission "{entry.strip()[:200]}" allowed without asking'
    if tool == "Bash":
        broad = arg in ("", "*", ":*", "*:*")
        out = [_cap(rel, EXECUTES, ("any shell command" if broad else "shell commands")
                    + f" — {what}")]
        if broad or _NETWORK_COMMAND.search(arg):
            out.append(_cap(rel, NETWORK, f"the shell can reach the network — {what}"))
        if broad or re.search(r"\b(cat|head|tail|less|grep|find|cp)\b", arg):
            out.append(_cap(rel, READS_FILES, f"the shell can read files — {what}"))
        return out
    if tool in ("Read", "Grep", "Glob"):
        outside = arg.startswith(("~", "/", "//")) or ".." in arg or arg in ("", "**", "*")
        return [_cap(rel, READS_FILES, ("files outside the repository"
                                        if outside and arg else "files") + f" — {what}")]
    if tool in ("WebFetch", "WebSearch"):
        return [_cap(rel, NETWORK, f"the web — {what}")]
    if tool.startswith("mcp__"):
        return [_cap(rel, MCP_SERVER, f"an MCP tool used without asking — {what}")]
    return []


def _hook_caps(rel: str, event: str, command: str) -> list[dict]:
    on_start = event in ("SessionStart", "Setup", "UserPromptSubmit")
    what = f'the {event} hook runs "{command.strip()[:200]}"'
    out = [_cap(rel, RUNS_ON_START if on_start else EXECUTES,
                ("without anyone asking, when a session starts — " if on_start
                 else "on every matching tool call — ") + what)]
    if on_start:
        out.append(_cap(rel, EXECUTES, what))
    if _NETWORK_COMMAND.search(command) or _SUSPICIOUS_COMMAND.search(command):
        out.append(_cap(rel, NETWORK, f"the hook reaches the network — {what}"))
    if re.search(r"(~/|\$HOME|/etc/|\.ssh|\.aws|\.env\b|\bcat\b)", command):
        out.append(_cap(rel, READS_FILES, f"the hook reads files — {what}"))
    return out


def _claude_settings(rel: str, data: dict) -> tuple[list[dict], set[str] | bool]:
    out = []
    permissions = data.get("permissions") if isinstance(data.get("permissions"), dict) else {}
    if permissions.get("defaultMode") == "bypassPermissions":
        what = 'defaultMode "bypassPermissions": every tool without asking'
        out += [_cap(rel, EXECUTES, what), _cap(rel, READS_FILES, what),
                _cap(rel, NETWORK, what)]
    for entry in permissions.get("allow") or []:
        if isinstance(entry, str):
            out += _permission(rel, entry)
    for d in permissions.get("additionalDirectories") or []:
        if isinstance(d, str):
            out.append(_cap(rel, READS_FILES, f'additional directory "{d[:200]}"'))
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    for event, matchers in hooks.items():
        for matcher in matchers if isinstance(matchers, list) else []:
            entries = matcher.get("hooks") if isinstance(matcher, dict) else None
            for hook in entries if isinstance(entries, list) else []:
                command = hook.get("command") if isinstance(hook, dict) else None
                if isinstance(command, str) and command.strip():
                    out += _hook_caps(rel, str(event), command)
    for key, what in _CLAUDE_COMMAND_KEYS.items():
        if isinstance(data.get(key), str) and data[key].strip():
            out.append(_cap(rel, RUNS_ON_START, f'{what}: "{data[key].strip()[:200]}"'))
    enabled: set[str] | bool = set()
    if data.get("enableAllProjectMcpServers") is True:
        enabled = True
    elif isinstance(data.get("enabledMcpjsonServers"), list):
        enabled = {str(s) for s in data["enabledMcpjsonServers"]}
    return out, enabled


def _mcp_servers(rel: str, data, enabled) -> list[dict]:
    servers = (data.get("mcpServers") or data.get("servers")) if isinstance(data, dict) else None
    out = []
    for name, server in (servers.items() if isinstance(servers, dict) else []):
        if not isinstance(server, dict):
            continue
        approved = enabled is True or (isinstance(enabled, set) and name in enabled)
        label = f'MCP server "{name}"'
        if isinstance(server.get("command"), str):
            args = server.get("args") if isinstance(server.get("args"), list) else []
            command = " ".join([server["command"], *map(str, args)])[:300]
            out.append(_cap(rel, MCP_SERVER, f'{label} runs "{command}"'))
            out.append(_cap(rel, EXECUTES, f'{label} starts a local process: "{command}"'))
            if approved:
                out.append(_cap(rel, RUNS_ON_START,
                                f"{label} is approved in advance: it starts when an "
                                f"agent opens the repository"))
            if _NETWORK_COMMAND.search(command) or server.get("env"):
                out.append(_cap(rel, NETWORK, f"{label} can reach the network"))
            out.append(_cap(rel, READS_FILES, f"{label} runs as the user, with "
                                              f"access to their files"))
        elif isinstance(server.get("url"), str):
            out.append(_cap(rel, MCP_SERVER, f'{label} at {server["url"][:200]}'))
            out.append(_cap(rel, NETWORK, f'{label} sends the agent\'s requests to '
                                          f'{server["url"][:200]}'))
    return out


def agent_surface(texts: dict[str, str], hidden: set[str] | None = None) -> dict:
    """What an agent opening this repository would inherit, and the paths it makes."""
    capabilities = []
    enabled: set[str] | bool = set()
    for rel, text in sorted(texts.items()):
        p = PurePosixPath(rel)
        if p.name in ("settings.json", "settings.local.json") and \
                ".claude" in p.parts:
            data = _load_json(text)
            if isinstance(data, dict):
                caps, on = _claude_settings(rel, data)
                capabilities += caps
                if on is True or enabled is True:
                    enabled = True
                else:
                    enabled |= on
    for rel, text in sorted(texts.items()):
        p = PurePosixPath(rel)
        lowered = rel.lower()
        if p.name.lower() in (".mcp.json", "mcp.json"):
            capabilities += _mcp_servers(rel, _load_json(text), enabled)
        elif p.name.lower() in _INSTRUCTION_NAMES or \
                any(lowered.startswith(d) for d in _INSTRUCTION_DIRS):
            note = " — and it hides content from a human reader (see parallax)" \
                if hidden and rel in hidden else ""
            capabilities.append(_cap(rel, INSTRUCTIONS,
                                     f"instructions every agent in the repository "
                                     f"reads ({len(text.splitlines())} lines){note}"))
    return {"capabilities": capabilities,
            "combinations": combinations(capabilities, hidden or set())}


def combinations(capabilities: list[dict], hidden: set[str]) -> list[dict]:
    """The capabilities that together make a complete path, as that path."""
    by = {}
    for i, c in enumerate(capabilities):
        by.setdefault(c["capability"], []).append(i)
    out = []
    start = by.get(RUNS_ON_START) or []
    run = start or by.get(EXECUTES) or []
    if by.get(READS_FILES) and by.get(NETWORK) and run:
        out.append({"kind": "exfiltration",
                    "severity": "critical" if start else "high",
                    "unattended": bool(start),
                    "steps": [run[0], by[READS_FILES][0], by[NETWORK][0]]})
    instructions = by.get(INSTRUCTIONS) or []
    if instructions and (by.get(EXECUTES) or by.get(NETWORK)):
        first = next((i for i in instructions
                      if capabilities[i]["source_file"] in hidden), instructions[0])
        tool = (by.get(EXECUTES) or by.get(NETWORK))[0]
        out.append({"kind": "steered_tools",
                    "severity": "high" if capabilities[first]["source_file"] in hidden
                    else "medium",
                    "unattended": False,
                    "steps": [first, tool] + ([by[NETWORK][0]]
                                              if by.get(NETWORK) and by[NETWORK][0] != tool
                                              else [])})
    return out


# ---------------------------------------------------------------------------
# All of it
# ---------------------------------------------------------------------------

MAX_FILES = 300
REVIEWED_FILES = 40         # the files GitHub is asked about, by leverage


def analyze(project: Path, texts: dict[str, str], findings_by_file: dict[str, int],
            divergences_by_file: dict[str, list[str]], repo_url: str | None = None,
            github: GitHub | None = None, attack_files: set[str] | None = None) -> dict:
    files = tracked_files(project) or sorted(texts)
    # Only what is in the repository: an untracked file is nobody's change.
    tracked = set(files)
    texts = {rel: text for rel, text in texts.items() if rel in tracked}
    owners_file = next((p for p in CODEOWNERS_PATHS if p in texts), None)
    codeowners = parse_codeowners(texts[owners_file]) if owners_file else []
    hist = history(project)

    run_by = runners_of(texts, set(files))
    scored = []
    for rel in files:
        lev, why = leverage_of(rel, texts.get(rel), findings_by_file.get(rel, 0),
                               divergences_by_file.get(rel),
                               rel in (attack_files or set()), run_by.get(rel))
        scored.append((rel, lev, why))

    github = github or GitHub(repo_url or "", github_token())
    protection = github.protection() if github.usable else {"known": False}
    reviews: dict[str, dict] = {}
    if github.usable:
        top = sorted(scored, key=lambda s: -s[1])[:REVIEWED_FILES]
        for rel, lev, _ in top:
            if lev < 0.5:
                break
            for sha in hist["files"].get(rel) or []:
                if sha not in reviews and github.usable:
                    r = github.review(sha)
                    if r is not None:
                        reviews[sha] = r

    rows = []
    for rel, lev, why in scored:
        ovs, owhy = oversight_of(rel, codeowners, owners_file, hist, reviews, protection)
        rows.append({"file": rel, "leverage_score": lev, "oversight_score": ovs,
                     "priority": priority(lev, ovs), "reasons": why + owhy,
                     "last_commit": (hist["files"].get(rel) or [None])[0]})
    rows.sort(key=lambda r: (-r["priority"], -r["leverage_score"], r["file"]))
    hidden = {f for f, kinds in divergences_by_file.items() if "hidden_content" in kinds}
    surface = agent_surface(texts, hidden)
    return {
        "files": rows[:MAX_FILES],
        "left_out": max(0, len(rows) - MAX_FILES),
        "agent": surface,
        "codeowners": owners_file,
        "history": {"commits": len(hist["commits"]), "shallow": hist["shallow"]},
        "github": {"used": bool(github.token and github.repo),
                   "token": bool(github.token), "calls": github.calls,
                   "error": github.error, "protection": protection},
    }
