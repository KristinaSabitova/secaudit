"""Module 3: immune memory. Every fix vaccinates the repository.

When a finding that had been shown to hold disappears because someone fixed
it, the fix says what the vulnerable pattern looked like. A model proposes a
Semgrep rule for it, and the rule is only kept if it passes a test built from
the project's own history: it must match the code just before the fix, and
must not match the code of the fix. Validated rules then run on every audit,
at no token cost, and anything they catch again is a regression — a zombie.

Provenance answers where a finding came from: the oldest commit that touched
its lines, by git blame (the V-SZZ criterion), and whether that commit
declares AI participation in its trailers. Declared, never established:
trailers are unreliable in both directions, and are reported as exactly that.

Nothing here runs the audited code. git reads its history; Semgrep parses
files without executing them.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path, PurePosixPath

from .evidence import locate

# Only findings shown to hold feed the other modules (principle 3).
EVIDENCED = ("reachable", "corroborated")

HIGH, MEDIUM, LOW = "high", "medium", "low"

DEFAULT_MAX_RULES = 3
MAX_DIFF_CHARS = 6000
MAX_FILE_CHARS = 12_000
SEMGREP_TIMEOUT = 300

# Trailers and footers by which a commit declares that an AI took part.
_AI_NAMES = (r"claude|anthropic|copilot|openai|chatgpt|gpt-?\d|codex|gemini|"
             r"cursor|devin|aider|windsurf|codeium|tabnine|amazon q|codewhisperer|"
             r"jules|sweep|bolt|lovable|replit agent|\bai\b|llm")
_AI_TRAILER = re.compile(
    rf"(?im)^\s*(co-authored-by|assisted-by|generated-by|ai-assisted-by|"
    rf"made-with|ai-tool|ai-agent)\s*:\s*(.*?(?:{_AI_NAMES}).*)$")
_AI_FOOTER = re.compile(
    r"(?i)(generated with \[?claude code|claude-session:|"
    r"generated (?:with|by) (?:github )?copilot|co-authored with|"
    r"🤖 generated with)")


def _git(project: Path, *args, timeout: int = 120, binary: bool = False,
         input=None) -> subprocess.CompletedProcess:
    """git on the untrusted checkout: its own config only, nothing that runs,
    and no network."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_TERMINAL_PROMPT="0")
    return subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}",
         "-c", "protocol.allow=never", "-C", str(project), *args],
        capture_output=True, text=not binary, env=env, timeout=timeout,
        input=input)


def has_commit(project: Path, sha: str | None) -> bool:
    if not sha or not re.fullmatch(r"[0-9a-f]{7,40}", sha):
        return False
    return _git(project, "cat-file", "-e", f"{sha}^{{commit}}").returncode == 0


def file_at(project: Path, sha: str, path: str) -> str | None:
    """A file as it was at a commit, or None if it did not exist there."""
    r = _git(project, "show", f"{sha}:{path}", binary=True)
    if r.returncode != 0 or b"\0" in r.stdout:
        return None
    return r.stdout.decode("utf-8", "replace")


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------

def shallow_edge(project: Path) -> set[str]:
    """The commits where a shallow clone's history stops."""
    r = _git(project, "rev-parse", "--git-path", "shallow")
    try:
        path = Path(r.stdout.strip())
        path = path if path.is_absolute() else project / path
        return set(path.read_text().split())
    except OSError:
        return set()


def ai_declared(message: str) -> bool:
    """Whether a commit message declares AI participation."""
    return bool(_AI_TRAILER.search(message) or _AI_FOOTER.search(message))


def _commit_info(project: Path, sha: str) -> dict | None:
    r = _git(project, "show", "-s", "--format=%H%x00%ct%x00%an%x00%s%x00%B", sha)
    if r.returncode != 0:
        return None
    full, when, author, subject, body = (r.stdout.split("\0") + [""] * 5)[:5]
    return {"sha": full.strip(), "time": int(when or 0), "author": author,
            "subject": subject[:200], "ai_declared": ai_declared(body)}


def provenance(project: Path, path: str, start: int, end: int,
               rev: str = "HEAD") -> dict | None:
    """The commit that most probably introduced lines start-end of path.

    Every line is blamed; the oldest commit among them is the origin. All
    lines from one commit is high confidence; several commits, medium; an
    origin at the edge of a shallow history, low — the real origin may be
    older than what was fetched.
    """
    if not path or not start or not end or end < start:
        return None
    r = _git(project, "blame", "--porcelain", "--root", "-w", "-L", f"{start},{end}",
             rev, "--", path)
    if r.returncode != 0:
        return None
    commits = set(re.findall(r"(?m)^([0-9a-f]{40}) \d+ \d+", r.stdout))
    if not commits:
        return None
    infos = [i for i in (_commit_info(project, sha) for sha in commits) if i]
    if not infos:
        return None
    origin = min(infos, key=lambda i: i["time"])
    for info in infos:          # ancestry first: commit times can tie or lie
        if info is not origin and _git(project, "merge-base", "--is-ancestor",
                                       info["sha"], origin["sha"]).returncode == 0:
            origin = info
    # A shallow clone cuts history at commits whose parents were not fetched:
    # blame credits them with lines that may be older.
    edge = shallow_edge(project)
    shallow = origin["sha"] in edge
    if shallow:
        confidence = LOW
    elif len(commits) == 1:
        confidence = HIGH
    else:
        confidence = MEDIUM
    return {"origin_commit": origin["sha"], "origin_confidence": confidence,
            "ai_declared": origin["ai_declared"], "author": origin["author"],
            "subject": origin["subject"], "commits": len(commits),
            "shallow": shallow}


# ---------------------------------------------------------------------------
# Fixes
# ---------------------------------------------------------------------------

def _norm_path(path) -> str:
    return re.sub(r"^(\./)+", "", str(path or "").replace("\\", "/")).strip()


def evidenced(finding: dict) -> bool:
    return (finding.get("verification_status") == "verified"
            and finding.get("epistemic_status") in EVIDENCED
            and bool(_norm_path(finding.get("file")))
            and bool(str(finding.get("code_snippet") or "").strip()))


def find_fixed(project: Path, previous: list[dict], previous_commit: str | None,
               head: str = "HEAD") -> list[dict]:
    """Which evidenced findings of the previous audit are gone, and by what commit.

    A finding is fixed only if its code is really gone from the file: one the
    model merely did not report again this time is not. The fix commit is the
    first commit after the previous audit in which the snippet no longer
    appears; the vulnerable commit is its parent.
    """
    out = []
    known = has_commit(project, previous_commit)
    for f in previous:
        if not isinstance(f, dict) or not evidenced(f):
            continue
        path, snippet = _norm_path(f["file"]), str(f["code_snippet"])
        now = file_at(project, head, path)
        if now is not None and locate(snippet, now):
            continue                # still there: not fixed, just not reported
        entry = {"fingerprint": f.get("fingerprint"), "finding_id": f.get("id"),
                 "file": path, "fix_commit": None, "vulnerable_commit": None}
        if not known:
            entry["reason"] = ("the commit of the previous audit is not in the "
                               "fetched history (SECAUDIT_HISTORY_DEPTH)")
            out.append(entry)
            continue
        r = _git(project, "rev-list", "--reverse", "--first-parent",
                 f"{previous_commit}..{head}", "--", path)
        for sha in r.stdout.split() if r.returncode == 0 else []:
            text = file_at(project, sha, path)
            if text is None or not locate(snippet, text):
                parent = _git(project, "rev-parse", f"{sha}^1")
                entry["fix_commit"] = sha
                entry["vulnerable_commit"] = parent.stdout.strip() \
                    if parent.returncode == 0 else None
                break
        if entry["fix_commit"] is None:
            entry["reason"] = "no commit since the previous audit removed the code"
        elif entry["vulnerable_commit"]:
            before = file_at(project, entry["vulnerable_commit"], path) or ""
            diff = _git(project, "diff", "--no-color", "-U5",
                        entry["vulnerable_commit"], entry["fix_commit"], "--", path)
            entry["before"] = before[:MAX_FILE_CHARS]
            entry["diff"] = (diff.stdout if diff.returncode == 0 else "")[:MAX_DIFF_CHARS]
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

LANGUAGES = {".py": "python", ".js": "javascript", ".mjs": "javascript",
             ".cjs": "javascript", ".jsx": "javascript", ".ts": "typescript",
             ".tsx": "typescript", ".go": "go", ".java": "java", ".rb": "ruby",
             ".php": "php", ".cs": "csharp", ".kt": "kotlin", ".rs": "rust",
             ".c": "c", ".h": "c", ".cpp": "cpp", ".scala": "scala",
             ".swift": "swift", ".sh": "bash", ".tf": "terraform",
             ".yml": "yaml", ".yaml": "yaml", ".json": "json"}
SEVERITIES = {"ERROR", "WARNING", "INFO"}
# The pattern operators a rule may use. Anything else — autofix, paths,
# options, taint mode — is not part of an immune rule and makes it invalid.
_OPERATORS = {"pattern", "patterns", "pattern-either", "pattern-not",
              "pattern-inside", "pattern-not-inside", "pattern-regex",
              "pattern-not-regex", "metavariable-regex", "metavariable-pattern",
              "metavariable-comparison", "focus-metavariable"}
_METAVARIABLE_KEYS = {"metavariable", "regex", "pattern", "patterns",
                      "pattern-either", "pattern-regex", "comparison", "language"}
_TOP_LEVEL = {"pattern", "patterns", "pattern-either", "pattern-regex"}


def language_of(path: str) -> str | None:
    return LANGUAGES.get(PurePosixPath(path).suffix.lower())


def _clean_operator(value, depth=0):
    """A pattern clause, if it only uses what an immune rule may use."""
    if depth > 8:
        return None
    if isinstance(value, str):
        return value if 0 < len(value) <= 2000 else None
    if isinstance(value, list):
        items = [_clean_operator(v, depth + 1) for v in value[:20]]
        return items if items and all(i is not None for i in items) else None
    if isinstance(value, dict):
        out = {}
        for key, v in value.items():
            if key in _OPERATORS:
                if key in ("metavariable-regex", "metavariable-pattern",
                           "metavariable-comparison"):
                    if not isinstance(v, dict) or set(v) - _METAVARIABLE_KEYS:
                        return None
                    inner = {k: _clean_operator(x, depth + 1) for k, x in v.items()}
                    if any(x is None for x in inner.values()):
                        return None
                    out[key] = inner
                    continue
                cleaned = _clean_operator(v, depth + 1)
                if cleaned is None:
                    return None
                out[key] = cleaned
            else:
                return None
        return out or None
    return None


def normalize_rule(raw, fingerprint: str, path: str) -> dict | None:
    """A model's proposed rule, made safe and uniform, or None if it is not one.

    The id is ours, the language is the file's, and only pattern operators
    survive: a rule that asks for anything else is not kept.
    """
    if not isinstance(raw, dict):
        return None
    language = language_of(path)
    if not language:
        return None
    clauses = {k: raw[k] for k in _TOP_LEVEL if k in raw}
    if len(clauses) != 1:
        return None
    key, value = next(iter(clauses.items()))
    cleaned = _clean_operator({key: value})
    if not cleaned:
        return None
    severity = str(raw.get("severity") or "WARNING").upper()
    slug = re.sub(r"[^a-z0-9]+", "-", str(raw.get("id") or "fix").lower()).strip("-")[:32]
    message = str(raw.get("message") or "a pattern this project fixed before")
    return {"id": f"secaudit-immune-{str(fingerprint or 'x')[:8]}-{slug or 'fix'}",
            "languages": [language],
            "severity": severity if severity in SEVERITIES else "WARNING",
            "message": message[:500].replace("\0", ""),
            **cleaned}


def _yaml_scalar(value) -> str:
    if isinstance(value, (list, dict)):
        return "[]" if isinstance(value, list) else "{}"
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return json.dumps(value)
    return json.dumps(str(value), ensure_ascii=False)   # a valid YAML string


def _yaml(value, indent: int = 0) -> list[str]:
    pad = " " * indent
    lines = []
    if isinstance(value, dict):
        for k, v in value.items():
            if isinstance(v, (dict, list)) and v:
                lines.append(f"{pad}{k}:")
                lines += _yaml(v, indent + 2)
            elif isinstance(v, str) and "\n" in v:
                lines.append(f"{pad}{k}: |")
                lines += [f"{pad}  {l}" if l else "" for l in v.rstrip("\n").split("\n")]
            else:
                lines.append(f"{pad}{k}: {_yaml_scalar(v)}")
    elif isinstance(value, list):
        for v in value:
            if isinstance(v, (dict, list)) and v:
                inner = _yaml(v, indent + 2)
                lines.append(f"{pad}- {inner[0].lstrip()}")
                lines += inner[1:]
            else:
                lines.append(f"{pad}- {_yaml_scalar(v)}")
    return lines


def to_yaml(rules: list[dict]) -> str:
    """Semgrep YAML for these rules, as a file to download and run."""
    return "\n".join(_yaml({"rules": rules})) + "\n"


class SemgrepError(Exception):
    pass


def semgrep_bin() -> str | None:
    return os.environ.get("SEMGREP_BIN") or shutil.which("semgrep")


def run_semgrep(rules: list[dict], target: Path, strict: bool = False) -> list[dict]:
    """Matches of these rules under target: rule id, path, lines.

    No metrics, no version check, no registry: only the rules given, read
    from a file written here. strict makes a file Semgrep could not parse an
    error: no match in code that was never read proves nothing.
    """
    exe = semgrep_bin()
    if not exe:
        raise SemgrepError("semgrep is not installed")
    with tempfile.TemporaryDirectory(prefix="secaudit-rules-") as tmp:
        config = Path(tmp) / "rules.json"
        config.write_text(json.dumps({"rules": rules}))
        env = {k: v for k, v in os.environ.items()
               if k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")}
        env.update(SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0",
                   XDG_CONFIG_HOME=tmp, HOME=env.get("HOME", tmp))
        try:
            r = subprocess.run(
                [exe, "scan", "--config", str(config), "--json", "--metrics=off",
                 "--disable-version-check", "--no-git-ignore", "--quiet",
                 "--timeout", "30", str(target)],
                capture_output=True, text=True, timeout=SEMGREP_TIMEOUT, env=env,
                cwd=tmp)
        except subprocess.TimeoutExpired as e:
            raise SemgrepError("semgrep timed out") from e
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        raise SemgrepError(f"semgrep failed: {(r.stderr or '').strip()[-200:]}") from e
    errors = [e for e in data.get("errors") or []
              if str(e.get("level", "")).lower() == "error"
              and "rule" in str(e.get("type", "")).lower()]
    if errors:
        raise SemgrepError(f"invalid rule: {str(errors[0].get('message', ''))[:200]}")
    unread = [e for e in data.get("errors") or []
              if re.search(r"(?i)syntax|pars|lexical", str(e.get("type", "")))]
    if strict and unread:
        raise SemgrepError("semgrep could not parse the file")
    out = []
    for m in data.get("results") or []:
        try:
            rel = Path(m["path"]).resolve().relative_to(target.resolve()).as_posix()
        except (ValueError, KeyError):
            rel = str(m.get("path"))
        out.append({"rule": m.get("check_id", "").rsplit(".", 1)[-1], "file": rel,
                    "line": m["start"]["line"], "line_end": m["end"]["line"]})
    return out


def validate(project: Path, rule: dict, path: str, vulnerable_commit: str,
             fix_commit: str) -> dict:
    """The rule must match the file before the fix and not after it.

    Each version is written alone into its own directory, under its own name
    so Semgrep reads it in the right language, and scanned there.
    """
    counts = {}
    for label, sha in (("before", vulnerable_commit), ("after", fix_commit)):
        text = file_at(project, sha, path) if sha else None
        with tempfile.TemporaryDirectory(prefix=f"secaudit-{label}-") as tmp:
            if text is not None:
                target = Path(tmp) / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(text, encoding="utf-8")
            try:
                counts[label] = len(run_semgrep([rule], Path(tmp), strict=True))
            except SemgrepError as e:
                return {"validated": False, "before": counts.get("before"),
                        "after": None, "error": str(e)}
    ok = counts["before"] > 0 and counts["after"] == 0
    reason = None if ok else ("it does not match the vulnerable code"
                              if counts["before"] == 0 else "it still matches the fix")
    return {"validated": ok, "before": counts["before"], "after": counts["after"],
            "vulnerable_commit": vulnerable_commit, "fix_commit": fix_commit,
            "reason": reason}


def max_rules_from(config: dict | None) -> int:
    value = (config or {}).get("max_rules")
    if value is None:
        value = os.environ.get("SECAUDIT_MAX_RULES")
    try:
        return max(0, int(value)) if value not in (None, "") else DEFAULT_MAX_RULES
    except (TypeError, ValueError):
        return DEFAULT_MAX_RULES


def snippet_at(project: Path, path: str, start: int, end: int) -> str:
    """The lines a rule matched, from the checkout, for a regression finding."""
    full = project / path
    try:
        if full.is_symlink() or project.resolve() not in full.resolve().parents:
            return ""
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    return "\n".join(lines[max(0, start - 1):min(len(lines), end, start + 14)])
