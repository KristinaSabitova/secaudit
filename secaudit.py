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
from dataclasses import asdict, dataclass, field
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
    # key = value patterns
    text = re.sub(
        r'(?i)((?:api[_\-]?key|token|password|secret|credential|auth)\s*[:=\'"` ]+)'
        r'([A-Za-z0-9+/=_\-]{8,})',
        lambda m: m.group(1) + f"[REDACTED:{hashlib.sha256(m.group(2).encode()).hexdigest()[:6]}]",
        text,
    )
    # known token prefixes
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
    raw_findings: list of dicts from Claude JSON output
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

    # Findings no longer present → fixed (unless already accepted)
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
# Claude runner
# ---------------------------------------------------------------------------

def find_claude() -> str:
    exe = os.environ.get("CLAUDE_BIN") or shutil.which("claude")
    if not exe:
        sys.exit("error: 'claude' (Claude Code CLI) not found in PATH.\n"
                 "Set CLAUDE_BIN or install from https://docs.claude.com.")
    return exe


def run_claude(project: Path, prompt: str, timeout: int = 3600) -> str:
    claude = find_claude()
    print(f"[*] Running audit in {project} ...", file=sys.stderr)
    try:
        result = subprocess.run(
            [claude, "-p", prompt],
            cwd=str(project), capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        sys.exit("error: audit timed out after 1h.")
    if result.returncode != 0:
        sys.stderr.write(result.stderr)
        sys.exit(f"error: claude exited with code {result.returncode}")
    return result.stdout


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

def run_oneshot(args, project: Path) -> None:
    mode = "report" if args.report_only else "fix"
    prompt = build_oneshot_prompt(args.stack, args.scope, mode)
    if args.print_prompt:
        print(prompt)
        return
    report = run_claude(project, prompt)
    if args.output:
        header = (f"# Security Audit Report\n\n"
                  f"- Project: `{project}`\n"
                  f"- Date: {datetime.now().isoformat(timespec='seconds')}\n\n"
                  f"---\n\n")
        args.output.write_text(header + report, encoding="utf-8")
        print(f"[+] Report written to {args.output}", file=sys.stderr)
    else:
        print(report)


def run_differential(args, project: Path, files=None) -> None:
    prompt = build_diff_prompt(args.stack, args.scope, files)
    if args.print_prompt:
        print(prompt)
        return

    raw_output = run_claude(project, prompt)
    raw_findings = extract_json_findings(raw_output)

    if raw_findings is _PARSE_FAILED:
        print("[!] Could not parse JSON from Claude output:", file=sys.stderr)
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
    # Route sub-commands before full argparse
    if len(sys.argv) > 1 and sys.argv[1] == "suppress":
        sp = argparse.ArgumentParser(prog="secaudit suppress")
        sp.add_argument("finding_id")
        sp.add_argument("--reason", required=True)
        sp.add_argument("--project", type=Path, default=Path("."))
        sa = sp.parse_args(sys.argv[2:])
        cmd_suppress(sa.project.expanduser().resolve(), sa.finding_id, sa.reason)
        return

    if len(sys.argv) > 1 and sys.argv[1] == "baseline":
        bp = argparse.ArgumentParser(prog="secaudit baseline")
        bp.add_argument("project", type=Path, nargs="?", default=Path("."))
        ba = bp.parse_args(sys.argv[2:])
        cmd_baseline(ba.project.expanduser().resolve())
        return

    p = argparse.ArgumentParser(
        prog="secaudit",
        description="Defensive web security audit via Claude Code.",
    )
    p.add_argument("project", type=Path, help="path to the project to audit")
    p.add_argument("--stack", help='tech stack hint, e.g. "Django + Vue"')
    p.add_argument("--scope", choices=["all", "backend", "frontend"],
                   default="all")

    # One-shot flags (backward compatible)
    p.add_argument("--report-only", action="store_true",
                   help="report without applying fixes (one-shot mode)")
    p.add_argument("--full", action="store_true",
                   help="force full one-shot audit (same as --report-only without fix)")
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

    args = p.parse_args()
    project = args.project.expanduser().resolve()
    if not project.is_dir():
        sys.exit(f"error: {project} is not a directory.")

    if args.show_suppressed:
        cmd_show_suppressed(project)
        return

    # Decide mode
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
        run_differential(args, project, files)
    else:
        # One-shot mode (backward compatible)
        run_oneshot(args, project)


if __name__ == "__main__":
    main()
