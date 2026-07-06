#!/usr/bin/env python3
"""
secaudit — defensive security audit CLI.

One-shot mode (default / --full / --report-only):
    secaudit . [--stack "Django+Vue"] [--scope backend] [--report-only] [-o report.md]

Differential mode (compares with saved state):
    secaudit . --staged              # audit staged files only
    secaudit . --diff main           # audit files changed vs <ref>
    secaudit . --all                 # show all findings, not just NEW+REGRESSED
    secaudit . --json                # output classified findings as JSON

Backend selection:
    secaudit . --staged --backend anthropic-api
    secaudit . --staged --backend openai-api
    secaudit . --staged --backend ollama
    (default: claude-code, or read from ~/.secaudit/config.toml)

Project aliases:
    secaudit projects add myapp              # register cwd as alias
    secaudit projects add myapp ~/dev/myapp  # register explicit path
    secaudit projects list
    secaudit projects remove myapp
    secaudit myapp --staged          # resolves alias to its registered path

Shell integration:
    secaudit init                    # install `secaudit` alias in ~/.zshrc / ~/.bashrc

State commands:
    secaudit suppress <id> --reason "..."   # mark finding as ACCEPTED
    secaudit baseline [project]             # accept all current findings as baseline
    secaudit . --show-suppressed            # list suppressed findings
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Finding schema
# ---------------------------------------------------------------------------

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_LABEL = {
    "critical": "CRITICAL",
    "high":     "HIGH    ",
    "medium":   "MEDIUM  ",
    "low":      "LOW     ",
    "info":     "INFO    ",
}


@dataclass
class Finding:
    fingerprint: str       # stable 16-char hex hash
    id: str                # short 8-char CLI handle
    file: str              # repo-relative path
    anchor: str            # function/class/snippet, no line numbers
    severity: str          # critical/high/medium/low/info
    category: str
    title: str
    description: str
    status: str = "new"    # new/fixed/regressed/persisting/accepted
    suppression_reason: str = ""

# ---------------------------------------------------------------------------
# Fingerprinting
# ---------------------------------------------------------------------------

def _norm_anchor(anchor: str) -> str:
    anchor = re.sub(r'\blines?\s*\d+[\-–\d]*\b', '', anchor, flags=re.IGNORECASE)
    return re.sub(r'\s+', ' ', anchor).strip().lower()


def _norm_file(path: str) -> str:
    return path.strip().lstrip('./').lower()


def make_fingerprint(category: str, file_path: str, anchor: str) -> str:
    """Stable fingerprint: survives line-number changes and minor refactors."""
    raw = f"{category.lower().strip()}|{_norm_file(file_path)}|{_norm_anchor(anchor)}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _make_id(fingerprint: str) -> str:
    return fingerprint[:8]

# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------

def redact_secrets(text: str) -> str:
    """Redact secret values in text; keep type + short hash hint."""
    text = re.sub(
        r'(?i)((?:api[_\-]?key|token|password|secret|credential|auth)\s*[:=\'"` ]+)'
        r'([A-Za-z0-9+/=_\-]{8,})',
        lambda m: m.group(1) + f"[REDACTED:{hashlib.sha256(m.group(2).encode()).hexdigest()[:6]}]",
        text,
    )
    text = re.sub(
        r'((?:sk-|pk-|ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_\-]{10,})',
        lambda m: f"[REDACTED:{hashlib.sha256(m.group(1).encode()).hexdigest()[:6]}]",
        text,
    )
    return text


def _sanitize(finding: Finding) -> Finding:
    if finding.category == "secrets":
        finding.description = redact_secrets(finding.description)
        finding.anchor = redact_secrets(finding.anchor)
    return finding

# ---------------------------------------------------------------------------
# State management
# ---------------------------------------------------------------------------

_STATE_DIR = Path.home() / ".secaudit" / "state"


def get_project_id(project: Path) -> str:
    """Stable project ID: git remote URL or resolved path."""
    try:
        r = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            cwd=str(project), capture_output=True, text=True,
        )
        key = r.stdout.strip() if r.returncode == 0 and r.stdout.strip() else str(project.resolve())
    except Exception:
        key = str(project.resolve())
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def load_state(project_id: str) -> dict:
    """Returns dict[fingerprint -> Finding]."""
    state_file = _STATE_DIR / f"{project_id}.json"
    if not state_file.exists():
        return {}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
        return {f["fingerprint"]: Finding(**f) for f in data.get("findings", [])}
    except Exception:
        return {}


def save_state(project_id: str, findings: dict) -> None:
    _STATE_DIR.mkdir(parents=True, exist_ok=True)
    state_file = _STATE_DIR / f"{project_id}.json"
    tmp = state_file.with_suffix(".tmp")
    tmp.write_text(
        json.dumps({"findings": [asdict(f) for f in findings.values()]}, indent=2),
        encoding="utf-8",
    )
    tmp.replace(state_file)

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def classify(raw_findings: list, saved: dict) -> tuple:
    """
    raw_findings: list of dicts from LLM JSON output
    saved: dict[fingerprint -> Finding] from state

    Returns (updated_state, all_findings_list).
    """
    updated: dict = {}
    seen: set = set()

    for raw in raw_findings:
        cat = str(raw.get("category", "other")).lower().strip()
        fpath = str(raw.get("file", "")).strip()
        anchor = str(raw.get("anchor", "")).strip()
        fp = make_fingerprint(cat, fpath, anchor)
        seen.add(fp)

        finding = Finding(
            fingerprint=fp,
            id=_make_id(fp),
            file=fpath,
            anchor=anchor,
            severity=str(raw.get("severity", "medium")).lower(),
            category=cat,
            title=str(raw.get("title", "")).strip(),
            description=str(raw.get("description", "")).strip(),
        )
        finding = _sanitize(finding)

        if fp in saved:
            prev = saved[fp]
            if prev.status == "accepted":
                finding.status = "accepted"
                finding.suppression_reason = prev.suppression_reason
            elif prev.status == "fixed":
                finding.status = "regressed"
            else:
                finding.status = "persisting"
        else:
            finding.status = "new"

        updated[fp] = finding

    for fp, prev in saved.items():
        if fp not in seen:
            if prev.status == "accepted":
                updated[fp] = prev
            elif prev.status != "fixed":
                import copy
                fixed = copy.copy(prev)
                fixed.status = "fixed"
                updated[fp] = fixed
            else:
                updated[fp] = prev

    return updated, list(updated.values())

# ---------------------------------------------------------------------------
# Git helpers for diff modes
# ---------------------------------------------------------------------------

def _git(project: Path, *args) -> list:
    r = subprocess.run(
        ["git", *args], cwd=str(project), capture_output=True, text=True,
    )
    return [f for f in r.stdout.strip().splitlines() if f] if r.returncode == 0 else []


def staged_files(project: Path) -> list:
    return _git(project, "diff", "--cached", "--name-only")


def diff_files(project: Path, ref: str) -> list:
    files = _git(project, "diff", f"{ref}...HEAD", "--name-only")
    if not files:
        files = _git(project, "diff", ref, "--name-only")
    return files


def default_branch(project: Path) -> str:
    for b in ("main", "master", "develop"):
        if _git(project, "rev-parse", "--verify", b):
            return b
    return "HEAD~1"


def _is_git_repo(path: Path) -> bool:
    """True if path has a .git entry (covers normal repos, submodules, worktrees)."""
    return (path / ".git").exists()


def _confirm(prompt: str) -> bool:
    """Ask y/n interactively. Returns False when stdin is not a TTY."""
    if not sys.stdin.isatty():
        return False
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except (EOFError, KeyboardInterrupt):
        print()
        return False

# ---------------------------------------------------------------------------
# Project aliases
# ---------------------------------------------------------------------------

_PROJECTS_FILE = Path.home() / ".secaudit" / "projects.json"


def load_projects() -> dict:
    """Returns dict[alias -> absolute_path_str]."""
    if not _PROJECTS_FILE.exists():
        return {}
    try:
        return json.loads(_PROJECTS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_projects(projects: dict) -> None:
    _PROJECTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _PROJECTS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(projects, indent=2), encoding="utf-8")
    tmp.replace(_PROJECTS_FILE)


def resolve_project(arg: str) -> Path:
    """Resolve alias or literal path → absolute Path."""
    projects = load_projects()
    if arg in projects:
        return Path(projects[arg])
    return Path(arg).expanduser().resolve()


def cmd_projects(argv: list) -> None:
    p = argparse.ArgumentParser(prog="secaudit projects")
    sub = p.add_subparsers(dest="action", required=True)

    add_p = sub.add_parser("add", help="register an alias for a project path")
    add_p.add_argument("alias")
    add_p.add_argument("path", nargs="?", default=None,
                       help="project directory (default: current directory)")
    add_p.add_argument("--force", action="store_true",
                       help="register even if the directory is not a git repo")

    sub.add_parser("list", help="list all registered aliases")

    rm_p = sub.add_parser("remove", help="remove a registered alias")
    rm_p.add_argument("alias")

    args = p.parse_args(argv)
    projects = load_projects()

    if args.action == "add":
        raw = args.path if args.path is not None else os.getcwd()
        path = Path(raw).expanduser().resolve()
        if not path.is_dir():
            sys.exit(f"error: {path} is not a directory.")

        if not _is_git_repo(path):
            print(f"warning: {path} does not appear to be a git repository.",
                  file=sys.stderr)
            if not args.force:
                if not _confirm("Register anyway? [y/N] "):
                    sys.exit("Aborted. Pass --force to skip this check.")

        projects[args.alias] = str(path)
        save_projects(projects)
        print(f"[+] Alias '{args.alias}' → {path}")

    elif args.action == "list":
        if not projects:
            print("No aliases registered.")
            return
        width = max(len(k) for k in projects)
        for alias, path in sorted(projects.items()):
            print(f"  {alias:<{width}}  →  {path}")

    elif args.action == "remove":
        if args.alias not in projects:
            sys.exit(f"error: alias '{args.alias}' not found.")
        del projects[args.alias]
        save_projects(projects)
        print(f"[+] Alias '{args.alias}' removed.")

# ---------------------------------------------------------------------------
# Shell integration (init)
# ---------------------------------------------------------------------------

_INIT_MARKER = "# secaudit alias"


def detect_shell_rc() -> Path:
    """Return ~/.zshrc or ~/.bashrc based on $SHELL; default to ~/.zshrc."""
    shell = os.environ.get("SHELL", "")
    if "bash" in shell:
        return Path.home() / ".bashrc"
    return Path.home() / ".zshrc"


def cmd_init(rc_file: Path | None = None, script: Path | None = None) -> None:
    """Install `secaudit` alias in the user's shell RC file (idempotent)."""
    if script is None:
        script = Path(__file__).resolve()
    if rc_file is None:
        rc_file = detect_shell_rc()

    alias_line = f'alias secaudit="python3 {script}"'

    if rc_file.exists():
        content = rc_file.read_text(encoding="utf-8")
        if _INIT_MARKER in content:
            print(f"[=] Already installed in {rc_file} — nothing changed.")
            return

    block = f"\n{_INIT_MARKER}\n{alias_line}\n"
    with open(rc_file, "a", encoding="utf-8") as fh:
        fh.write(block)

    print(f"[+] Added to {rc_file}:")
    print(f"    {alias_line}")
    print()
    print("    To activate, run:")
    print(f"    source {rc_file}")
    print("    (or open a new terminal)")

# ---------------------------------------------------------------------------
# Audit backends
# ---------------------------------------------------------------------------

_CONFIG_FILE = Path.home() / ".secaudit" / "config.toml"

_CONFIG_EXAMPLE = """\
# secaudit backend configuration
# Uncomment and edit the section for the backend you want to use.
# See README for full documentation.

backend = "claude-code"
# model = "claude-sonnet-4-6"

# --- Anthropic API (direct HTTP, no Claude Code CLI needed) ---
# backend = "anthropic-api"
# model = "claude-sonnet-4-6"
# Set env var: export ANTHROPIC_API_KEY=sk-ant-...

# --- OpenAI API ---
# backend = "openai-api"
# model = "gpt-4o"
# Set env var: export OPENAI_API_KEY=sk-...

# --- Ollama (local, no account or cost) ---
# backend = "ollama"
# model = "llama3"
# ollama_url = "http://localhost:11434"
"""


def _parse_toml(text: str) -> dict:
    """Parse simple key = "value" TOML (no library dependency needed)."""
    result = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            result[k] = v
    return result


def load_config() -> dict:
    if not _CONFIG_FILE.exists():
        _CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CONFIG_FILE.write_text(_CONFIG_EXAMPLE, encoding="utf-8")
        return {}
    return _parse_toml(_CONFIG_FILE.read_text(encoding="utf-8"))


class AuditBackend:
    def run(self, project: Path, prompt: str, timeout: int = 3600) -> str:
        raise NotImplementedError


class ClaudeCodeBackend(AuditBackend):
    def run(self, project: Path, prompt: str, timeout: int = 3600) -> str:
        exe = os.environ.get("CLAUDE_BIN") or shutil.which("claude")
        if not exe:
            sys.exit(
                "error: 'claude' (Claude Code CLI) not found in PATH.\n"
                "Set CLAUDE_BIN or install from https://docs.claude.com."
            )
        print(f"[*] Running audit in {project} (claude-code) ...", file=sys.stderr)
        try:
            result = subprocess.run(
                [exe, "-p", prompt],
                cwd=str(project), capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            sys.exit("error: audit timed out.")
        if result.returncode != 0:
            sys.stderr.write(result.stderr)
            sys.exit(f"error: claude exited with code {result.returncode}")
        return result.stdout


class AnthropicAPIBackend(AuditBackend):
    DEFAULT_MODEL = "claude-sonnet-4-6"

    def __init__(self, model: str | None = None):
        self.model = model or self.DEFAULT_MODEL

    def run(self, project: Path, prompt: str, timeout: int = 3600) -> str:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            sys.exit(
                "error: ANTHROPIC_API_KEY is not set.\n"
                "Export it before running:\n"
                "  export ANTHROPIC_API_KEY=sk-ant-..."
            )
        payload = json.dumps({
            "model": self.model,
            "max_tokens": 8192,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=payload,
            headers={
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            method="POST",
        )
        print(f"[*] Running audit via Anthropic API ({self.model}) ...", file=sys.stderr)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
            return data["content"][0]["text"]
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            sys.exit(f"error: Anthropic API {e.code}: {body}")
        except urllib.error.URLError as e:
            sys.exit(f"error: Could not reach Anthropic API: {e.reason}")


class OpenAIBackend(AuditBackend):
    DEFAULT_MODEL = "gpt-4o"

    def __init__(self, model: str | None = None):
        self.model = model or self.DEFAULT_MODEL

    def run(self, project: Path, prompt: str, timeout: int = 3600) -> str:
        api_key = os.environ.get("OPENAI_API_KEY", "")
        if not api_key:
            sys.exit(
                "error: OPENAI_API_KEY is not set.\n"
                "Export it before running:\n"
                "  export OPENAI_API_KEY=sk-..."
            )
        payload = json.dumps({
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.openai.com/v1/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "content-type": "application/json",
            },
            method="POST",
        )
        print(f"[*] Running audit via OpenAI API ({self.model}) ...", file=sys.stderr)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
            return data["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="replace")
            sys.exit(f"error: OpenAI API {e.code}: {body}")
        except urllib.error.URLError as e:
            sys.exit(f"error: Could not reach OpenAI API: {e.reason}")


class OllamaBackend(AuditBackend):
    DEFAULT_MODEL = "llama3"
    DEFAULT_URL = "http://localhost:11434"

    def __init__(self, model: str | None = None, base_url: str | None = None):
        self.model = model or self.DEFAULT_MODEL
        self.base_url = (base_url or self.DEFAULT_URL).rstrip("/")

    def run(self, project: Path, prompt: str, timeout: int = 3600) -> str:
        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }).encode()
        req = urllib.request.Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"content-type": "application/json"},
            method="POST",
        )
        print(f"[*] Running audit via Ollama ({self.model}) ...", file=sys.stderr)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read())
            return data.get("response", "")
        except urllib.error.URLError as e:
            sys.exit(
                f"error: Could not reach Ollama at {self.base_url}.\n"
                f"Is Ollama running? Start it with: ollama serve\n"
                f"Detail: {e.reason}"
            )


_BACKENDS = {
    "claude-code":   ClaudeCodeBackend,
    "anthropic-api": AnthropicAPIBackend,
    "openai-api":    OpenAIBackend,
    "ollama":        OllamaBackend,
}


def select_backend(flag: str | None, config: dict | None = None) -> AuditBackend:
    """Priority: explicit flag > config.toml > default (claude-code)."""
    if config is None:
        config = load_config()
    name = flag or config.get("backend", "claude-code")
    if name not in _BACKENDS:
        valid = ", ".join(_BACKENDS)
        sys.exit(f"error: unknown backend '{name}'. Valid: {valid}")
    model = config.get("model") or None
    ollama_url = config.get("ollama_url") or None
    cls = _BACKENDS[name]
    if name == "ollama":
        return cls(model=model, base_url=ollama_url)
    if name == "claude-code":
        return cls()
    return cls(model=model)

# ---------------------------------------------------------------------------
# Prompt builders
# ---------------------------------------------------------------------------

BACKEND_CHECKS = """\
BACKEND:
- Injection (SQL/NoSQL/command/LDAP): every user input must be validated and
  sanitised. Enforce parameterisation / ORM bindings — never string concatenation.
- AuthN/AuthZ on every route: no IDOR or broken access control; roles enforced
  server-side; never trust client-supplied identity or role data.
- Sessions/tokens: short-lived JWTs + refresh, secrets in env vars (never in
  code), cookies flagged HttpOnly, Secure, SameSite.
- Rate limiting / brute-force protection on login and sensitive endpoints.
- Error handling: no stack traces, internal paths or verbose errors in prod;
  debug mode disabled.
- Vulnerable dependencies: run the ecosystem auditor (npm audit / pip-audit /
  cargo audit) and propose pinned upgrades.
- File handling: validate type/size, prevent path traversal.
- Secrets: grep for hardcoded keys, tokens, passwords, connection strings.
- CORS: no wildcard origin combined with credentials.
"""

FRONTEND_CHECKS = """\
FRONTEND:
- XSS: review every render of dynamic data; avoid dangerouslySetInnerHTML /
  innerHTML without sanitising; rely on framework default escaping.
- Strict Content-Security-Policy plus the full header set (HSTS,
  X-Content-Type-Options, X-Frame-Options/frame-ancestors, Referrer-Policy,
  Permissions-Policy). Target: A+ on securityheaders.com.
- CSRF protection (tokens or SameSite) on every state-changing operation.
- No security logic or secret that lives only on the client.
- CORS reviewed from the consumer side.
"""

DELIVERY_FREE = """\
DELIVERY:
For each finding give: severity (critical/high/medium/low), location
(file:line), risk explanation, and the concrete fix. {mode_instruction}
Group findings by severity. End with a short pentest-style executive summary.
Do not change functionality without flagging it first.
"""

DELIVERY_JSON = """\
DELIVERY — STRUCTURED OUTPUT:
Output ONLY a valid JSON array. No markdown, no explanation, no preamble.
Each element must have exactly these fields:
  "category": one of injection/authz/sessions/rate_limiting/error_handling/
               dependencies/file_handling/secrets/cors/xss/csp/csrf/
               client_security/other
  "file":      relative path from project root (empty string if not file-specific)
  "anchor":    function name, class name, or a brief code fragment — NO line numbers
  "severity":  critical | high | medium | low | info
  "title":     short title (one line)
  "description": risk explanation and concrete fix; for secrets findings do NOT
                 include the secret value itself, only its type and location
If no findings, output: []
"""

REPORT_ONLY = ("Do NOT modify any files. Only report findings and the fix you "
               "would apply.")
APPLY_FIXES = ("Apply critical and high fixes directly. List medium/low and any "
               "fix needing my decision before touching it.")


def build_oneshot_prompt(stack, scope, mode):
    parts = ["You are performing a defensive security audit of a web "
             "application I own. Work systematically.\n"]
    if stack:
        parts.append(f"Tech stack: {stack}.\n")
    if scope in ("all", "backend"):
        parts.append(BACKEND_CHECKS)
    if scope in ("all", "frontend"):
        parts.append(FRONTEND_CHECKS)
    instr = REPORT_ONLY if mode == "report" else APPLY_FIXES
    parts.append(DELIVERY_FREE.format(mode_instruction=instr))
    return "\n".join(parts)


def build_diff_prompt(stack, scope, files):
    parts = ["You are performing a defensive security audit of a web "
             "application I own.\n"]
    if stack:
        parts.append(f"Tech stack: {stack}.\n")
    if files:
        parts.append("Audit ONLY these files (changed in this diff):\n"
                     + "\n".join(f"  - {f}" for f in files) + "\n")
    if scope in ("all", "backend"):
        parts.append(BACKEND_CHECKS)
    if scope in ("all", "frontend"):
        parts.append(FRONTEND_CHECKS)
    parts.append(DELIVERY_JSON)
    return "\n".join(parts)

# ---------------------------------------------------------------------------
# JSON extraction
# ---------------------------------------------------------------------------

_PARSE_FAILED = object()  # sentinel: could not parse JSON at all


def extract_json_findings(text: str):
    """Return parsed list, empty list [], or _PARSE_FAILED sentinel."""
    cleaned = re.sub(r'```json\s*', '', text)
    cleaned = re.sub(r'```\s*', '', cleaned).strip()
    try:
        data = json.loads(cleaned)
        if isinstance(data, list):
            return data
    except json.JSONDecodeError:
        pass
    m = re.search(r'\[.*\]', cleaned, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    return _PARSE_FAILED

# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

STATUS_LABEL = {
    "new":        "[NEW]      ",
    "regressed":  "[REGRESSED]",
    "persisting": "[PERSISTING]",
    "fixed":      "[FIXED]    ",
    "accepted":   "[ACCEPTED] ",
}


def print_findings(findings: list, show_all: bool = False) -> None:
    if show_all:
        visible = [f for f in findings if f.status != "accepted"]
    else:
        visible = [f for f in findings if f.status in ("new", "regressed")]

    by_sev = {s: [] for s in SEVERITIES}
    for f in visible:
        by_sev.setdefault(f.severity, []).append(f)

    total = len(visible)
    if total == 0:
        print("[+] No new or regressed findings.")
        return

    for sev in SEVERITIES:
        for f in by_sev.get(sev, []):
            label = STATUS_LABEL.get(f.status, f.status.upper().ljust(11))
            print(f"\n{label} [{SEVERITY_LABEL.get(f.severity, f.severity.upper())}] "
                  f"[{f.id}] {f.title}")
            print(f"  File    : {f.file or '(project-wide)'}")
            print(f"  Anchor  : {f.anchor or '—'}")
            print(f"  Category: {f.category}")
            print(f"  {f.description}")

    counts = {s: sum(1 for f in visible if f.severity == s) for s in SEVERITIES}
    print(f"\n── Summary: {total} finding(s) ──")
    for s in SEVERITIES:
        if counts[s]:
            print(f"  {SEVERITY_LABEL.get(s, s).strip()}: {counts[s]}")

# ---------------------------------------------------------------------------
# Sub-commands: suppress, baseline, show-suppressed
# ---------------------------------------------------------------------------

def cmd_suppress(project: Path, finding_id: str, reason: str) -> None:
    pid = get_project_id(project)
    state = load_state(pid)
    for fp, f in state.items():
        if f.id == finding_id or f.fingerprint.startswith(finding_id):
            f.status = "accepted"
            f.suppression_reason = reason
            save_state(pid, state)
            print(f"[+] Finding {finding_id} ({f.title}) marked as ACCEPTED.")
            return
    sys.exit(f"error: finding '{finding_id}' not found in saved state.")


def cmd_baseline(project: Path) -> None:
    pid = get_project_id(project)
    state = load_state(pid)
    count = 0
    for f in state.values():
        if f.status not in ("accepted", "fixed"):
            f.status = "accepted"
            f.suppression_reason = "baseline"
            count += 1
    save_state(pid, state)
    print(f"[+] Baseline set: {count} finding(s) accepted.")


def cmd_show_suppressed(project: Path) -> None:
    pid = get_project_id(project)
    state = load_state(pid)
    suppressed = [f for f in state.values() if f.status == "accepted"]
    if not suppressed:
        print("No suppressed findings.")
        return
    print(f"{'ID':8}  {'SEV':8}  {'TITLE':40}  REASON")
    print("─" * 80)
    for f in sorted(suppressed, key=lambda x: SEVERITIES.index(x.severity)):
        print(f"{f.id:8}  {f.severity:8}  {f.title[:40]:40}  {f.suppression_reason}")

# ---------------------------------------------------------------------------
# Main flows
# ---------------------------------------------------------------------------

def run_oneshot(args, project: Path, backend: AuditBackend) -> None:
    mode = "report" if args.report_only else "fix"
    prompt = build_oneshot_prompt(args.stack, args.scope, mode)
    if args.print_prompt:
        print(prompt)
        return
    report = backend.run(project, prompt)
    if args.output:
        header = (f"# Security Audit Report\n\n"
                  f"- Project: `{project}`\n"
                  f"- Date: {datetime.now().isoformat(timespec='seconds')}\n\n"
                  f"---\n\n")
        args.output.write_text(header + report, encoding="utf-8")
        print(f"[+] Report written to {args.output}", file=sys.stderr)
    else:
        print(report)


def run_differential(args, project: Path, backend: AuditBackend, files=None) -> None:
    prompt = build_diff_prompt(args.stack, args.scope, files)
    if args.print_prompt:
        print(prompt)
        return

    raw_output = backend.run(project, prompt)
    raw_findings = extract_json_findings(raw_output)

    if raw_findings is _PARSE_FAILED:
        print("[!] Could not parse JSON from output:", file=sys.stderr)
        print(raw_output)
        return

    pid = get_project_id(project)
    saved = load_state(pid)
    updated_state, all_findings = classify(raw_findings, saved)
    save_state(pid, updated_state)

    if args.json:
        visible = [f for f in all_findings
                   if (args.all or f.status in ("new", "regressed"))
                   and f.status != "accepted"]
        print(json.dumps([asdict(f) for f in visible], indent=2))
        return

    print_findings(all_findings, show_all=args.all)

    if args.output:
        lines = [f"# Differential Audit\n\n- Project: `{project}`\n"
                 f"- Date: {datetime.now().isoformat(timespec='seconds')}\n\n---\n"]
        for f in all_findings:
            if not args.all and f.status not in ("new", "regressed"):
                continue
            lines.append(f"\n## [{f.status.upper()}] {f.title}\n")
            lines.append(f"- Severity: {f.severity}\n- File: {f.file}\n"
                         f"- Anchor: {f.anchor}\n\n{f.description}\n")
        args.output.write_text("\n".join(lines), encoding="utf-8")
        print(f"[+] Report written to {args.output}", file=sys.stderr)

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    # Early routing for subcommands that don't need the full parser
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        cmd_init()
        return

    if len(sys.argv) > 1 and sys.argv[1] == "projects":
        cmd_projects(sys.argv[2:])
        return

    if len(sys.argv) > 1 and sys.argv[1] == "suppress":
        sp = argparse.ArgumentParser(prog="secaudit suppress")
        sp.add_argument("finding_id")
        sp.add_argument("--reason", required=True)
        sp.add_argument("--project", type=str, default=".")
        sa = sp.parse_args(sys.argv[2:])
        cmd_suppress(resolve_project(sa.project), sa.finding_id, sa.reason)
        return

    if len(sys.argv) > 1 and sys.argv[1] == "baseline":
        bp = argparse.ArgumentParser(prog="secaudit baseline")
        bp.add_argument("project", type=str, nargs="?", default=".")
        ba = bp.parse_args(sys.argv[2:])
        cmd_baseline(resolve_project(ba.project))
        return

    p = argparse.ArgumentParser(
        prog="secaudit",
        description="Defensive web security audit via Claude Code.",
    )
    p.add_argument("project", type=str,
                   help="path to audit, or a registered alias (see 'projects add')")
    p.add_argument("--stack", help='tech stack hint, e.g. "Django + Vue"')
    p.add_argument("--scope", choices=["all", "backend", "frontend"], default="all")

    # One-shot flags (backward compatible)
    p.add_argument("--report-only", action="store_true",
                   help="report without applying fixes (one-shot mode)")
    p.add_argument("--full", action="store_true",
                   help="force full one-shot audit")
    p.add_argument("--output", "-o", type=Path, help="write report to file")
    p.add_argument("--print-prompt", action="store_true")

    # Differential flags
    p.add_argument("--staged", action="store_true",
                   help="audit only staged files (differential)")
    p.add_argument("--diff", metavar="REF",
                   help="audit files changed vs REF (differential)")
    p.add_argument("--all", action="store_true",
                   help="show all findings, not just NEW+REGRESSED")
    p.add_argument("--json", action="store_true",
                   help="output classified findings as JSON")
    p.add_argument("--show-suppressed", action="store_true",
                   help="list suppressed (ACCEPTED) findings")

    # Backend selection
    p.add_argument("--backend", choices=list(_BACKENDS),
                   help="audit backend (overrides config.toml)")

    args = p.parse_args()
    project = resolve_project(args.project)
    if not project.is_dir():
        sys.exit(f"error: {project} is not a directory.")

    if args.show_suppressed:
        cmd_show_suppressed(project)
        return

    backend = select_backend(args.backend)

    if args.staged or args.diff:
        if args.staged:
            files = staged_files(project)
            if not files:
                print("[*] No staged files found.", file=sys.stderr)
                return
            print(f"[*] Auditing {len(files)} staged file(s).", file=sys.stderr)
        else:
            ref = args.diff
            files = diff_files(project, ref)
            if not files:
                print(f"[*] No changed files vs {ref}.", file=sys.stderr)
                return
            print(f"[*] Auditing {len(files)} file(s) changed vs {ref}.", file=sys.stderr)
        run_differential(args, project, backend, files)
    else:
        run_oneshot(args, project, backend)


if __name__ == "__main__":
    main()
