"""Module 1: the views of a repository, and where they disagree.

The same file can be several things at once: what a person reads on GitHub,
the bytes that are really there, what a package manager or an editor would
run because of it, what the auditor was actually sent, and what was published
to a registry under that version. Deception lives in the gap between two of
them, so each gap is measured:

  human  != bytes     hidden_content        invisible Unicode, comments a
                                            rendered page does not show
  bytes  != machine   unexpected_execution  something runs that does not
                                            look like it would
  bytes  != llm       audit_blind_spot      not sent to the auditor, cut
                                            short, or drowned in padding
  git    != published release_mismatch      the package on the registry is
                                            not the tagged source

Nothing here runs, imports or installs the audited code. Files are read as
text; Python is parsed with ast and never executed; the only network access
is to the official PyPI and npm registries, and only for the published view.
"""

import ast
import configparser
import difflib
import io
import json
import os
import re
import subprocess
import tarfile
import tomllib
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .chunking import (AGENT_CONFIG, AUTH_SECRETS, CODE, SKIP_DIRS, classify_path,
                       read_text)

HIDDEN_CONTENT = "hidden_content"
UNEXPECTED_EXECUTION = "unexpected_execution"
AUDIT_BLIND_SPOT = "audit_blind_spot"
RELEASE_MISMATCH = "release_mismatch"
KINDS = (HIDDEN_CONTENT, UNEXPECTED_EXECUTION, AUDIT_BLIND_SPOT, RELEASE_MISMATCH)

# The two views each kind compares.
VIEWS = {
    HIDDEN_CONTENT: ("human", "bytes"),
    UNEXPECTED_EXECUTION: ("bytes", "machine"),
    AUDIT_BLIND_SPOT: ("bytes", "llm"),
    RELEASE_MISMATCH: ("bytes", "published"),
}

SEVERITIES = ("critical", "high", "medium", "low", "info")

# How much of a file a divergence keeps to show the two views side by side.
CONTEXT_LINES = 3
MAX_EXCERPT_LINES = 40
MAX_LINE_CHARS = 400
# Occurrences listed per divergence; the rest are counted.
MAX_OCCURRENCES = 50
# Files named in one aggregated divergence.
MAX_LISTED = 200


@dataclass
class Divergence:
    file: str
    kind: str
    detail: str
    severity: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        view_a, view_b = VIEWS[self.kind]
        return {"file": self.file, "view_a": view_a, "view_b": view_b,
                "kind": self.kind, "detail": self.detail,
                "severity": self.severity, "evidence": self.evidence}


def _clip(text: str, limit: int = MAX_LINE_CHARS) -> str:
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _is_agent_file(rel: str) -> bool:
    return classify_path(rel)[0] == AGENT_CONFIG


# ---------------------------------------------------------------------------
# human != bytes: hidden content
# ---------------------------------------------------------------------------

def _invisible_kind(cp: int) -> str | None:
    """Which family of invisible character this code point belongs to."""
    if 0xE0000 <= cp <= 0xE007F:
        return "tag"                # Unicode tags: ASCII nobody can see
    if cp in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067,
              0x2068, 0x2069, 0x200E, 0x200F, 0x061C):
        return "bidi"               # reorders what is displayed (Trojan Source)
    if cp in (0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063,
              0x2064, 0xFEFF, 0x180E):
        return "zero_width"
    if 0xE0100 <= cp <= 0xE01EF or 0xFE00 <= cp <= 0xFE0D:
        return "variation_selector"  # can carry bytes after any character
    return None


_TAG_DESCRIPTIONS = {
    "tag": "Unicode tag characters",
    "bidi": "bidirectional control characters",
    "zero_width": "zero-width characters",
    "variation_selector": "variation selectors",
}


def _benign_joiner(text: str, i: int) -> bool:
    """ZWJ and ZWNJ between two non-ASCII characters: an emoji sequence, or
    the joining rules of Persian, Arabic or an Indic script."""
    if text[i] not in "‌‍":
        return False
    before = text[i - 1] if i > 0 else ""
    after = text[i + 1] if i + 1 < len(text) else ""
    return bool(before and after and ord(before) > 0x7F and ord(after) > 0x7F)


def _benign_selector(text: str, i: int) -> bool:
    """A single variation selector right after a symbol is how text and emoji
    presentation are chosen. A run of them is how bytes are smuggled."""
    cp = ord(text[i])
    if not 0xFE00 <= cp <= 0xFE0D:
        return False
    before = text[i - 1] if i > 0 else ""
    after = text[i + 1] if i + 1 < len(text) else ""
    return (bool(before) and _invisible_kind(ord(before)) != "variation_selector"
            and (not after or _invisible_kind(ord(after)) != "variation_selector"))


_ANY_INVISIBLE = re.compile(
    "[\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069"
    "\ufe00-\ufe0d\ufeff\U000e0000-\U000e007f\U000e0100-\U000e01ef]")


def invisible_runs(text: str) -> list[dict]:
    """Every run of invisible characters: where, which, and what they spell.

    A BOM at the very start of a file is how some editors save UTF-8 and is
    not counted; neither are the joiners of emoji sequences and scripts that
    need them.
    """
    runs = []
    if not _ANY_INVISIBLE.search(text):
        return runs
    line, col = 1, 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\n":
            line, col = line + 1, 0
            i += 1
            continue
        kind = _invisible_kind(ord(ch))
        if (kind is None or (i == 0 and ch == "﻿")
                or _benign_joiner(text, i) or _benign_selector(text, i)):
            i, col = i + 1, col + 1
            continue
        start, start_col, kinds, cps = i, col, set(), []
        while i < n and text[i] != "\n" and _invisible_kind(ord(text[i])):
            kinds.add(_invisible_kind(ord(text[i])))
            cps.append(ord(text[i]))
            i, col = i + 1, col + 1
        runs.append({"line": line, "column": start_col + 1, "length": i - start,
                     "kinds": sorted(kinds), "code_points": cps,
                     "decoded": decode_hidden(cps)})
    return runs


def decode_hidden(code_points: list[int]) -> str | None:
    """What a run of invisible characters says, when it encodes text.

    Tag characters map one to one onto ASCII. Variation selectors can carry
    one byte each (the "emoji smuggling" encoding). Anything else is shown
    as code points only.
    """
    tags = [cp - 0xE0000 for cp in code_points if 0xE0020 <= cp <= 0xE007E]
    if len(tags) >= 2:
        return "".join(chr(c) for c in tags)
    data = bytearray()
    for cp in code_points:
        if 0xFE00 <= cp <= 0xFE0F:
            data.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            data.append(cp - 0xE0100 + 16)
    if len(data) >= 2:
        try:
            decoded = data.decode("utf-8")
        except UnicodeDecodeError:
            return None
        if decoded.isprintable():
            return decoded
    return None


def visible(text: str) -> str:
    """Text with every invisible character written out as <U+XXXX>."""
    return "".join(f"<U+{ord(c):04X}>" if _invisible_kind(ord(c)) else c
                   for c in text)


def human_text(text: str) -> str:
    """What a person reading the rendered file would see of a line."""
    return "".join(c for c in text if not _invisible_kind(ord(c)))


# Comments GitHub never renders.
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
_LINK_COMMENT = re.compile(r"^\[(?://|comment|_)\]:\s*#\s*[(\"'](.*)[)\"']\s*$",
                           re.MULTILINE | re.IGNORECASE)
_FENCE = re.compile(r"^(```|~~~)")

# What makes a hidden comment an instruction rather than a note to self.
_INSTRUCTION = re.compile(
    r"(?i)\b(ignore (?:all|any|the|previous|prior|above|earlier)|disregard|"
    r"(?:system|developer) prompt|you are (?:an?|the|now)|you must|"
    r"do not (?:tell|mention|reveal|show|inform)|without (?:telling|asking)|"
    r"assistant|\bAI\b|LLM|language model|claude|copilot|cursor|chatgpt|gpt|"
    r"gemini|agent|instructions?|execute|run (?:the|this|a)|curl|wget|"
    r"base64|bash -c|sh -c|powershell|exfiltrat|api[_ ]?key|token|secret|"
    r"password|credential|ignora|instruccion|debes|ejecuta|no (?:le )?digas)")
_HARMLESS_COMMENT = re.compile(
    r"(?i)^\s*(markdownlint|prettier|eslint|textlint|vale|toc|end ?toc|"
    r"all-contributors|badges?|omit in toc|start|end|todo|fixme|\w+:(?:start|end))\b")


def _markdown_comments(text: str) -> list[dict]:
    """HTML and link-reference comments outside code fences, with their lines."""
    # Comments inside fenced code are shown as code and are not hidden.
    lines = text.split("\n")
    in_fence = False
    masked = []
    for l in lines:
        if _FENCE.match(l.lstrip()):
            in_fence = not in_fence
            masked.append(" " * len(l))
        else:
            masked.append(" " * len(l) if in_fence else l)
    plain = "\n".join(masked)
    out = []
    for pattern in (_HTML_COMMENT, _LINK_COMMENT):
        for m in pattern.finditer(plain):
            start = plain.count("\n", 0, m.start()) + 1
            end = plain.count("\n", 0, m.end()) + 1
            out.append({"start": start, "end": end, "span": (m.start(), m.end()),
                        "text": m.group(1).strip()})
    return out


def _hidden_comment_reason(comment: str, agent_file: bool) -> str | None:
    body = human_text(comment)
    if len(body) < 20 or _HARMLESS_COMMENT.match(body):
        return None
    if _INSTRUCTION.search(body):
        return "reads like an instruction"
    if agent_file and len(body) >= 40:
        return "text in a file written for agents that no person sees"
    return None


def _excerpt(text: str, marked: dict[int, list], human_lines: dict[int, str | None],
             ) -> dict:
    """The lines around what differs, as each view shows them.

    marked maps a line number to the column spans that differ. human_lines
    overrides the human view of a line; None means the line is not shown at
    all (the whole line is inside a comment).
    """
    lines = text.split("\n")
    wanted = set()
    for n in marked:
        wanted.update(range(max(1, n - CONTEXT_LINES),
                            min(len(lines), n + CONTEXT_LINES) + 1))
    rows = []
    for n in sorted(wanted)[:MAX_EXCERPT_LINES]:
        raw = lines[n - 1]
        human = human_lines[n] if n in human_lines else human_text(raw)
        # A <U+XXXX> cut in half by the clip would read as text, not a mark.
        shown = re.sub(r"<(U(\+[0-9A-F]*)?)?…$", "…", _clip(visible(raw)))
        rows.append({"n": n, "a": None if human is None else _clip(human),
                     "b": shown, "marked": n in marked})
    return {"lines": rows, "truncated": len(wanted) > MAX_EXCERPT_LINES}


def hidden_content(rel: str, text: str) -> list[Divergence]:
    """Where the rendered file and the bytes are not the same text."""
    out = []
    agent = _is_agent_file(rel)
    runs = invisible_runs(text)
    if runs:
        kinds = sorted({k for r in runs for k in r["kinds"]})
        decoded = [r["decoded"] for r in runs if r["decoded"]]
        count = sum(r["length"] for r in runs)
        suffix = PurePosixPath(rel).suffix.lower()
        code = suffix not in (".md", ".mdx", ".txt", ".rst", "")
        if "tag" in kinds or decoded:
            severity = "critical" if agent else "high"
        elif "bidi" in kinds and code:
            severity = "high"       # the order shown is not the order run
        elif agent:
            severity = "high"
        else:
            severity = "medium"
        what = ", ".join(_TAG_DESCRIPTIONS[k] for k in kinds)
        detail = (f"{count} invisible character(s) ({what}) on "
                  f"{len({r['line'] for r in runs})} line(s): a person reading "
                  f"the file does not see them, a model reads them")
        if decoded:
            detail += f'; they spell "{_clip(decoded[0], 160)}"'
        marked = {}
        for r in runs:
            marked.setdefault(r["line"], []).append([r["column"], r["length"]])
        out.append(Divergence(rel, HIDDEN_CONTENT, detail, severity, {
            "technique": "invisible_unicode",
            "kinds": kinds,
            "occurrences": [{"line": r["line"], "column": r["column"],
                             "code_points": [f"U+{c:04X}" for c in r["code_points"][:64]],
                             "decoded": r["decoded"] and _clip(r["decoded"], 2000)}
                            for r in runs[:MAX_OCCURRENCES]],
            "more": max(0, len(runs) - MAX_OCCURRENCES),
            "excerpt": _excerpt(text, marked, {}),
        }))

    if PurePosixPath(rel).suffix.lower() in (".md", ".mdx", ".markdown"):
        flagged = []
        for c in _markdown_comments(text):
            reason = _hidden_comment_reason(c["text"], agent)
            if reason:
                flagged.append((c, reason))
        if flagged:
            # A line inside a comment is not shown at all...
            human_lines: dict[int, str | None] = {}
            for c, _ in flagged:
                for n in range(c["start"], c["end"] + 1):
                    human_lines[n] = None
            # ...but one that shares its line with text leaves that text behind.
            for c, _ in flagged:
                if c["start"] == c["end"]:
                    line = text.split("\n")[c["start"] - 1]
                    human_lines[c["start"]] = human_text(
                        _HTML_COMMENT.sub("", line)).rstrip() or None
            marked = {n: [] for c, _ in flagged
                      for n in range(c["start"], c["end"] + 1)}
            first = flagged[0][0]
            out.append(Divergence(
                rel, HIDDEN_CONTENT,
                f"{len(flagged)} comment(s) that the rendered page does not show "
                f"and a model reads in full; the first, on line {first['start']}, "
                f"{flagged[0][1]}: \"{_clip(human_text(first['text']), 160)}\"",
                "critical" if agent else "high", {
                    "technique": "hidden_comment",
                    "occurrences": [{"line": c["start"], "line_end": c["end"],
                                     "text": _clip(c["text"], 2000), "reason": r}
                                    for c, r in flagged[:MAX_OCCURRENCES]],
                    "more": max(0, len(flagged) - MAX_OCCURRENCES),
                    "excerpt": _excerpt(text, marked, human_lines),
                }))
    return out


# ---------------------------------------------------------------------------
# bytes != machine: what would run
# ---------------------------------------------------------------------------

# npm runs these on `npm install` in the project, or when it is installed as a
# dependency (prepare: from git).
NPM_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare",
                       "preprepare", "postprepare", "prepublish")
_SUSPICIOUS_COMMAND = re.compile(
    r"(?i)(curl|wget|https?://|\bnc\b|netcat|base64|\beval\b|node\s+-e|"
    r"python[0-9.]*\s+-c|\|\s*(ba|z)?sh\b|powershell|iex\b|invoke-webrequest|"
    r"\bchmod\s+\+x|/dev/tcp|\bxxd\b|\bopenssl\s+enc|fromcharcode|\\x[0-9a-f]{2})")


# What most projects run on install, and nobody is surprised by: still a
# divergence, but the least of them.
_ROUTINE_COMMAND = re.compile(
    r"^\s*(husky(\s+install)?|is-ci\s*\|\|\s*husky(\s+install)?|tsc(\s+-[\w-]+)*|"
    r"(npm|yarn|pnpm)\s+run\s+[\w:-]+|node-gyp\s+rebuild|patch-package|"
    r"simple-git-hooks|lefthook\s+install|ngcc|prisma\s+generate)\s*$")


def _command_severity(command: str, base: str) -> str:
    if _SUSPICIOUS_COMMAND.search(command):
        return "high"
    return "low" if _ROUTINE_COMMAND.match(command) else base


def _line_of(text: str, needle: str) -> int | None:
    for n, line in enumerate(text.split("\n"), 1):
        if needle in line:
            return n
    return None


def _strip_jsonc(text: str) -> str:
    """JSON with comments and trailing commas, as VS Code and devcontainers
    write it, made plain JSON. Strings are left intact."""
    out, i, n = [], 0, len(text)
    in_string = False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
            continue
        if c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            while i < n and text[i] != "\n":
                i += 1
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(c)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def _load_json(text: str):
    try:
        return json.loads(_strip_jsonc(text))
    except (json.JSONDecodeError, RecursionError):
        return None


def _execution(rel: str, text: str, trigger: str, command: str, severity: str,
               what: str) -> Divergence:
    line = _line_of(text, command.split("\n")[0][:80]) if command else None
    marked = {line: []} if line else {}
    return Divergence(rel, UNEXPECTED_EXECUTION,
                      f"{what} — runs on {trigger}: {_clip(command, 200)}", severity, {
                          "trigger": trigger, "command": _clip(command, 2000),
                          "line": line,
                          "excerpt": _excerpt(text, marked, {}) if marked else None,
                      })


def _package_json(rel: str, text: str, files: set[str]) -> list[Divergence]:
    data = _load_json(text)
    if not isinstance(data, dict):
        return []
    out = []
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    for name in NPM_INSTALL_SCRIPTS:
        command = scripts.get(name)
        if isinstance(command, str) and command.strip():
            out.append(_execution(
                rel, text, f"npm install ({name})", command,
                _command_severity(command, "medium"),
                f'the "{name}" script'))
    folder = str(PurePosixPath(rel).parent)
    gyp = "binding.gyp" if folder == "." else f"{folder}/binding.gyp"
    if gyp in files and not any(scripts.get(n) for n in ("install", "preinstall")):
        out.append(_execution(rel, text, "npm install (implicit)", "node-gyp rebuild",
                              "low", "binding.gyp makes npm build native code "
                                     "though no script says so"))
    return out


def _vscode_tasks(rel: str, text: str) -> list[Divergence]:
    data = _load_json(text)
    tasks = data.get("tasks") if isinstance(data, dict) else None
    out = []
    for task in tasks if isinstance(tasks, list) else []:
        if not isinstance(task, dict):
            continue
        run_on = (task.get("runOptions") or {}).get("runOn") \
            if isinstance(task.get("runOptions"), dict) else None
        if run_on != "folderOpen":
            continue
        command = " ".join(str(x) for x in [task.get("command") or ""]
                           + [a if isinstance(a, str) else json.dumps(a)
                              for a in (task.get("args") or [])
                              if isinstance(task.get("args"), list)])
        out.append(_execution(rel, text, "opening the folder in VS Code",
                              command.strip() or str(task.get("label") or "task"),
                              "high", f"the task \"{task.get('label', '')}\""))
    return out


_DEVCONTAINER_COMMANDS = {
    # Runs on the developer's own machine, before any container exists.
    "initializeCommand": ("opening the dev container (on the host)", "high"),
    "onCreateCommand": ("creating the dev container", "medium"),
    "updateContentCommand": ("creating the dev container", "medium"),
    "postCreateCommand": ("creating the dev container", "medium"),
    "postStartCommand": ("every start of the dev container", "medium"),
    "postAttachCommand": ("every attach to the dev container", "medium"),
}


def _devcontainer(rel: str, text: str) -> list[Divergence]:
    data = _load_json(text)
    if not isinstance(data, dict):
        return []
    out = []
    for key, (trigger, base) in _DEVCONTAINER_COMMANDS.items():
        value = data.get(key)
        if isinstance(value, dict):
            commands = [v if isinstance(v, str) else " ".join(map(str, v))
                        for v in value.values() if v]
        elif isinstance(value, list):
            commands = [" ".join(map(str, value))]
        elif isinstance(value, str):
            commands = [value]
        else:
            commands = []
        for command in commands:
            if command.strip():
                out.append(_execution(rel, text, trigger, command,
                                      _command_severity(command, base), key))
    return out


_CLAUDE_COMMAND_KEYS = {
    "apiKeyHelper": "the agent's key helper, run to obtain credentials",
    "awsCredentialExport": "a credential command the agent runs",
    "awsAuthRefresh": "a credential command the agent runs",
    "otelHeadersHelper": "a helper the agent runs for telemetry headers",
}


def _claude_settings(rel: str, text: str) -> list[Divergence]:
    data = _load_json(text)
    if not isinstance(data, dict):
        return []
    out = []
    hooks = data.get("hooks") if isinstance(data.get("hooks"), dict) else {}
    for event, matchers in hooks.items():
        for matcher in matchers if isinstance(matchers, list) else []:
            entries = matcher.get("hooks") if isinstance(matcher, dict) else None
            for hook in entries if isinstance(entries, list) else []:
                command = hook.get("command") if isinstance(hook, dict) else None
                if isinstance(command, str) and command.strip():
                    out.append(_execution(
                        rel, text, f"the agent's {event} event", command, "high",
                        "a hook an AI agent runs in this repository"))
    for key, what in _CLAUDE_COMMAND_KEYS.items():
        if isinstance(data.get(key), str) and data[key].strip():
            out.append(_execution(rel, text, "the agent starting", data[key],
                                  "high", what))
    status = data.get("statusLine")
    if isinstance(status, dict) and isinstance(status.get("command"), str):
        out.append(_execution(rel, text, "every refresh of the agent's status line",
                              status["command"],
                              _command_severity(status["command"], "medium"),
                              "the status line command"))
    return out


def _mcp_config(rel: str, text: str, auto_approved: bool) -> list[Divergence]:
    data = _load_json(text)
    servers = (data.get("mcpServers") or data.get("servers")) \
        if isinstance(data, dict) else None
    out = []
    for name, server in (servers.items() if isinstance(servers, dict) else []):
        if not isinstance(server, dict) or not isinstance(server.get("command"), str):
            continue
        args = server.get("args") if isinstance(server.get("args"), list) else []
        command = " ".join([server["command"], *map(str, args)])
        trigger = ("an agent opening the repository (approved in advance)"
                   if auto_approved else "an agent enabling the project's MCP servers")
        out.append(_execution(rel, text, trigger, command,
                              _command_severity(command,
                                                "high" if auto_approved else "medium"),
                              f'the MCP server "{name}"'))
    return out


# Diff, merge and filter drivers git has built in or that LFS installs: naming
# one of these runs nothing that is not already there.
_BUILTIN_DRIVERS = {
    "lfs", "binary", "text", "union", "ada", "bash", "bibtex", "cpp", "csharp",
    "css", "dts", "elixir", "fortran", "fountain", "golang", "html", "java",
    "kotlin", "markdown", "matlab", "objc", "pascal", "perl", "php", "python",
    "ruby", "rust", "scheme", "tex",
}
_ATTRIBUTE_DRIVER = re.compile(r"(?<![\w-])(filter|diff|merge)=([\w.-]+)")


def _gitattributes(rel: str, text: str) -> list[Divergence]:
    out = []
    for n, line in enumerate(text.split("\n"), 1):
        if line.lstrip().startswith("#"):
            continue
        for attr, driver in _ATTRIBUTE_DRIVER.findall(line):
            if driver.lower() in _BUILTIN_DRIVERS:
                continue
            out.append(Divergence(rel, UNEXPECTED_EXECUTION,
                                  f'line {n} hands files to a "{driver}" {attr} '
                                  f"driver: git runs whatever command a local "
                                  f"config gives that name, on checkout or diff",
                                  "low", {"trigger": f"git {attr}", "line": n,
                                          "command": line.strip(),
                                          "excerpt": _excerpt(text, {n: []}, {})}))
    return out


_GIT_HOOK_NAMES = {
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit",
    "pre-merge-commit", "prepare-commit-msg", "commit-msg", "post-commit",
    "pre-rebase", "post-checkout", "post-merge", "pre-push", "post-rewrite",
    "pre-auto-gc", "reference-transaction", "push-to-checkout",
}
_HOOKS_PATH = re.compile(r"core\.hookspath|\bhusky\b|simple-git-hooks|lefthook|"
                         r"pre-commit install", re.IGNORECASE)


def _git_hooks(texts: dict[str, str]) -> list[Divergence]:
    """Hook scripts kept in the repository, and whether something installs them."""
    installer = next((rel for rel, text in texts.items()
                      if PurePosixPath(rel).name.lower() in (
                          "package.json", "makefile", ".pre-commit-config.yaml",
                          "lefthook.yml", "lefthook.yaml", "setup.sh", "install.sh",
                          "bootstrap.sh", "justfile")
                      and _HOOKS_PATH.search(text)), None)
    out = []
    for rel, text in texts.items():
        p = PurePosixPath(rel)
        if p.name not in _GIT_HOOK_NAMES or "_" in p.parts[:-1]:
            continue
        if not any(d in (".husky", ".githooks", "githooks", "hooks", ".hooks")
                   for d in p.parts[:-1]):
            continue
        body = "\n".join(l for l in text.split("\n")
                         if l.strip() and not l.lstrip().startswith("#"))
        if not body.strip():
            continue
        if installer:
            trigger = f"git {p.name}, once {installer} installs the hooks"
            severity = _command_severity(body, "medium")
        else:
            trigger = f"git {p.name}, if someone points core.hooksPath here"
            severity = _command_severity(body, "low")
        first = next(l for l in text.split("\n")
                     if l.strip() and not l.lstrip().startswith("#"))
        out.append(_execution(rel, text, trigger, first.strip(), severity,
                              "a git hook kept in the repository"))
    return out


_RUNS_AT_IMPORT = {"system", "popen", "run", "call", "check_call", "check_output",
                   "Popen", "exec", "eval", "urlopen", "urlretrieve", "get", "post",
                   "spawn", "execv", "execve", "execvp", "startfile", "b64decode",
                   "create_connection", "connect"}


def _setup_py(rel: str, text: str) -> list[Divergence]:
    """What `pip install` of this source would run besides setup() itself."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    out = []
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef,
                             ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for call in (n for n in ast.walk(node) if isinstance(n, ast.Call)):
            name = (call.func.attr if isinstance(call.func, ast.Attribute)
                    else call.func.id if isinstance(call.func, ast.Name) else "")
            if name == "setup":
                for kw in call.keywords:
                    if kw.arg == "cmdclass":
                        out.append(_execution(
                            rel, text, "pip install", ast.get_source_segment(text, kw)
                            or "cmdclass=...", "medium",
                            "setup() replaces the install commands with its own"))
            elif name in _RUNS_AT_IMPORT:
                segment = ast.get_source_segment(text, call) or name
                out.append(_execution(rel, text, "pip install", segment, "high",
                                      "setup.py calls this at top level"))
    return out


def _pyproject(rel: str, text: str) -> list[Divergence]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError):
        return []
    build = data.get("build-system") if isinstance(data.get("build-system"), dict) else {}
    if build.get("backend-path"):
        return [_execution(rel, text, "pip install or any build",
                           f"build-backend = {build.get('build-backend')} from "
                           f"{build.get('backend-path')}", "medium",
                           "the package is built by code in the repository itself")]
    return []


def _pth(rel: str, text: str) -> list[Divergence]:
    lines = [l for l in text.split("\n") if re.match(r"\s*import\s", l)]
    if not lines:
        return []
    return [_execution(rel, text, "every start of Python, once installed", lines[0],
                       "high", "a .pth file whose import lines Python runs")]


_EXECUTABLE_SETTING = re.compile(r"(?i)(\.path|path|executable|interpreter|"
                                 r"runtime|command|shellArgs)$")


def _vscode_settings(rel: str, text: str, files: set[str]) -> list[Divergence]:
    """Editor settings that point a tool at a program inside the repository:
    opening the folder runs it. A path to something the repository does not
    hold (a local .venv) is the developer's own machine, not the repository."""
    data = _load_json(text)
    if not isinstance(data, dict):
        return []
    out = []
    for key, value in data.items():
        if not isinstance(value, str) or not _EXECUTABLE_SETTING.search(key):
            continue
        target = re.sub(r"^(\$\{workspace(Folder|Root)\}/|\./)", "", value)
        if target in files and not value.startswith(("/", "~")):
            out.append(_execution(rel, text, "opening the folder in the editor",
                                  f'"{key}": "{value}"', "medium",
                                  "an editor setting that runs a program from "
                                  "the repository"))
    return out


def git_symlinks(project: Path) -> dict[str, str]:
    """Links recorded in git, and where each points.

    The checkout is made with core.symlinks off, so each link is a plain file
    holding its target. Which of them really are links is only known to git.
    """
    if not (project / ".git").exists():
        return {}
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    try:
        r = subprocess.run(["git", "-c", "core.fsmonitor=false", "-C", str(project),
                            "ls-files", "-s", "-z"], capture_output=True, text=True,
                           env=env, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    links = {}
    for record in r.stdout.split("\0") if r.returncode == 0 else []:
        meta, _, path = record.partition("\t")
        if meta.startswith("120000"):
            full = project / path
            target = full.read_text(errors="replace") if full.is_file() and \
                not full.is_symlink() else (os.readlink(full) if full.is_symlink() else "")
            links[path] = target.strip()
    return links


def _symlink(rel: str, target: str) -> Divergence | None:
    resolved = os.path.normpath(os.path.join(os.path.dirname(rel), target))
    outside = target.startswith(("/", "~")) or resolved.startswith("..") \
        or re.match(r"^[A-Za-z]:[\\/]", target)
    if not outside:
        return None
    return Divergence(rel, UNEXPECTED_EXECUTION,
                      f"is a link to {_clip(target, 200)}, outside the repository: a "
                      f"tool or agent that opens it reads that file instead",
                      "high", {"trigger": "any tool that follows links",
                               "command": target[:2000], "line": None,
                               "excerpt": None})


def unexpected_execution(project: Path, texts: dict[str, str]) -> list[Divergence]:
    files = set(texts)
    auto_approved = False
    for rel in files:
        if PurePosixPath(rel).name in ("settings.json", "settings.local.json") \
                and ".claude" in PurePosixPath(rel).parts:
            data = _load_json(texts[rel])
            if isinstance(data, dict) and data.get("enableAllProjectMcpServers") is True:
                auto_approved = True
    out: list[Divergence] = []
    for rel, text in sorted(texts.items()):
        p = PurePosixPath(rel)
        name = p.name.lower()
        parts = [x.lower() for x in p.parts[:-1]]
        if name == "package.json" and "node_modules" not in parts:
            out += _package_json(rel, text, files)
        elif name == "tasks.json" and ".vscode" in parts:
            out += _vscode_tasks(rel, text)
        elif name == "settings.json" and ".vscode" in parts:
            out += _vscode_settings(rel, text, files)
        elif name in ("devcontainer.json", ".devcontainer.json"):
            out += _devcontainer(rel, text)
        elif name in ("settings.json", "settings.local.json") and ".claude" in parts:
            out += _claude_settings(rel, text)
        elif name in (".mcp.json", "mcp.json"):
            out += _mcp_config(rel, text, auto_approved)
        elif name == ".gitattributes":
            out += _gitattributes(rel, text)
        elif name == "setup.py" and not parts:
            out += _setup_py(rel, text)
        elif name == "pyproject.toml" and not parts:
            out += _pyproject(rel, text)
        elif p.suffix == ".pth":
            out += _pth(rel, text)
    out += _git_hooks(texts)
    for rel, target in sorted(git_symlinks(project).items()):
        d = _symlink(rel, target)
        if d:
            out.append(d)
    return out


# ---------------------------------------------------------------------------
# bytes != llm: what the auditor was not shown
# ---------------------------------------------------------------------------

def _tier(row: dict) -> int:
    try:
        return int(row.get("risk_tier"))
    except (TypeError, ValueError):
        return CODE


def audit_blind_spots(coverage: list[dict] | None,
                      coverage_summary: dict | None = None) -> list[Divergence]:
    """What the coverage report says the auditor never saw, or saw in part.

    High-risk files are reported one by one; ordinary code is reported as a
    single list, since a long tail of low-risk files left out of a budget is
    expected and should not bury the ones that matter.
    """
    rows = [r for r in coverage or [] if isinstance(r, dict) and r.get("file")]
    out: list[Divergence] = []
    tail_missing, tail_partial, skipped_dirs = [], [], []
    for r in rows:
        rel, reason, tier = str(r["file"]), str(r.get("reason") or ""), _tier(r)
        if rel.endswith("/"):
            if "dependency or build directory" in reason \
                    and rel.rstrip("/").split("/")[-1] in SKIP_DIRS:
                skipped_dirs.append(rel)
            continue
        ignored = "ignored by git" in reason
        if ignored or "symbolic link" in reason:
            continue                # not part of the repository, or a link
        if not r.get("audited"):
            if "not text" in reason and tier > AGENT_CONFIG:
                continue            # an image or a binary asset
            if "not a source, configuration" in reason:
                continue
            if tier <= AGENT_CONFIG:
                severity = "high"
            elif tier <= AUTH_SECRETS:
                severity = "medium"
            elif tier == CODE:
                tail_missing.append(rel)
                continue
            else:
                continue            # tests, docs and data
            out.append(Divergence(rel, AUDIT_BLIND_SPOT,
                                  f"the auditor never saw this file ({reason})",
                                  severity, {"reason": reason, "risk_tier": tier}))
        elif reason.startswith("audited in part"):
            if tier <= AUTH_SECRETS:
                out.append(Divergence(rel, AUDIT_BLIND_SPOT,
                                      f"the auditor saw only part of this file "
                                      f"({reason.removeprefix('audited in part: ')})",
                                      "medium" if tier <= AGENT_CONFIG else "low",
                                      {"reason": reason, "risk_tier": tier}))
            elif tier == CODE:
                tail_partial.append(rel)
    if tail_missing:
        out.append(Divergence("", AUDIT_BLIND_SPOT,
                              f"{len(tail_missing)} code file(s) were left out of "
                              f"the audit to stay within its budget",
                              "low", {"files": tail_missing[:MAX_LISTED],
                                      "more": max(0, len(tail_missing) - MAX_LISTED)}))
    if tail_partial:
        out.append(Divergence("", AUDIT_BLIND_SPOT,
                              f"{len(tail_partial)} code file(s) were audited only "
                              f"in part", "low",
                              {"files": tail_partial[:MAX_LISTED],
                               "more": max(0, len(tail_partial) - MAX_LISTED)}))
    for rel in skipped_dirs:
        out.append(Divergence(rel, AUDIT_BLIND_SPOT,
                              "a dependency or build directory committed to the "
                              "repository; its code is never audited, and what "
                              "runs may be what is in it", "low",
                              {"reason": "dependency or build directory"}))
    summary = coverage_summary if isinstance(coverage_summary, dict) else {}
    if summary.get("padding_suspected"):
        padded = [str(r["file"]) for r in rows
                  if any(isinstance(s, dict) and s.get("kind") in (
                      "near_duplicate", "oversized", "anomalous_size")
                         for s in r.get("signals") or [])]
        missed = sum(1 for r in rows if not r.get("audited")
                     and _tier(r) <= AUTH_SECRETS)
        out.append(Divergence("", AUDIT_BLIND_SPOT,
                              f"{len(padded)} file(s) look like filler (near-identical "
                              f"copies or outsized files), the cheapest way to push "
                              f"something out of the auditor's context"
                              + (f"; {missed} high-risk file(s) were left out"
                                 if missed else ""),
                              "high" if missed else "medium",
                              {"files": padded[:MAX_LISTED],
                               "more": max(0, len(padded) - MAX_LISTED),
                               "technique": "padding"}))
    return out


# ---------------------------------------------------------------------------
# git != published: the package on the registry
# ---------------------------------------------------------------------------

REGISTRY_HOSTS = {"pypi.org", "files.pythonhosted.org", "registry.npmjs.org"}
MAX_PACKAGE_BYTES = 30 * 1024 * 1024
REGISTRY_TIMEOUT = 20
# Files a registry or a build tool writes into every package: never in git.
_GENERATED = re.compile(r"(^|/)(PKG-INFO|[^/]+\.egg-info/.*|[^/]+\.dist-info/.*|"
                        r"\.npmignore|npm-shrinkwrap\.json)$")
_VERSION_FILE = re.compile(r"(^|/)_?version\.py$")
_BUILD_OUTPUT = re.compile(r"(^|/)(dist|build|lib|es|esm|cjs|umd|out)/|"
                           r"\.(min\.js|d\.ts|map|mjs\.map)$")
_CODE_LIKE = {".py", ".js", ".mjs", ".cjs", ".ts", ".sh", ".bash", ".m4", ".pth",
              ".pl", ".rb", ".php", ".c", ".h", ".so", ".node", ".cfg", ".in", ".ac",
              ".am", ".bat", ".ps1"}
_BUILT_SUFFIXES = (".js", ".mjs", ".cjs", ".map", ".ts")
_CODE_LIKE_NAMES = {"configure", "makefile", "setup.py", "package.json",
                    "build-to-host.m4", "install.sh"}


class RegistryError(Exception):
    pass


class _NoForeignRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).hostname not in REGISTRY_HOSTS:
            raise RegistryError(f"refused a redirect to {newurl}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def registry_get(url: str, limit: int = MAX_PACKAGE_BYTES) -> bytes:
    """GET from an official registry, and nowhere else."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in REGISTRY_HOSTS:
        raise RegistryError(f"not an official registry address: {url}")
    opener = urllib.request.build_opener(_NoForeignRedirects)
    request = urllib.request.Request(url, headers={"User-Agent": "secaudit"})
    try:
        with opener.open(request, timeout=REGISTRY_TIMEOUT) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise FileNotFoundError(url) from e
        raise RegistryError(f"{parts.hostname} answered {e.code}") from e
    except (urllib.error.URLError, OSError) as e:
        raise RegistryError(f"cannot reach {parts.hostname}: {e}") from e
    if len(data) > limit:
        raise RegistryError(f"the package is larger than {limit} bytes")
    return data


_VERSION_ASSIGNMENT = re.compile(
    r"""(?m)^__version__\s*(?::\s*str\s*)?=\s*["']([0-9][^"']*)["']""")


def _module_version(project: Path, name: str) -> str | None:
    """__version__ as a literal in the package's own module, where flit,
    setup.cfg's attr: and most setup.py files read it from. Read, never run."""
    pkg = re.sub(r"[-.]+", "_", name).lower()
    for rel in (f"{pkg}/__init__.py", f"src/{pkg}/__init__.py", f"{pkg}/__version__.py",
                f"src/{pkg}/__version__.py", f"{pkg}/_version.py", f"{pkg}/version.py",
                f"{pkg}.py", f"src/{pkg}.py"):
        path = project / rel
        if path.is_file() and not path.is_symlink():
            m = _VERSION_ASSIGNMENT.search(read_text(path) or "")
            if m:
                return m.group(1)
    return None


def _python_package(project: Path) -> dict | None:
    name = version = None
    computed = False
    text = read_text(project / "pyproject.toml") if (project / "pyproject.toml").is_file() else None
    if text:
        try:
            meta = tomllib.loads(text).get("project") or {}
        except (tomllib.TOMLDecodeError, ValueError):
            meta = {}
        name, version = meta.get("name"), meta.get("version")
        computed = "version" in (meta.get("dynamic") or [])
    if (project / "setup.cfg").is_file():
        cfg = read_text(project / "setup.cfg") or ""
        m = re.search(r"(?ms)^\[metadata\](.*?)(^\[|\Z)", cfg)
        if m:
            nm = re.search(r"(?m)^name\s*=\s*(\S+)", m.group(1))
            vm = re.search(r"(?m)^version\s*=\s*([0-9][^\s]*)", m.group(1))
            name = name or (nm and nm.group(1))
            version = version or (vm and vm.group(1))
            computed = computed or bool(re.search(r"(?m)^version\s*=\s*attr:", m.group(1)))
    if (project / "setup.py").is_file() and not (name and version):
        try:
            tree = ast.parse(read_text(project / "setup.py") or "")
        except (SyntaxError, ValueError, RecursionError):
            tree = None
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)) if tree else []:
            kws = {k.arg: k.value for k in call.keywords if k.arg}
            if isinstance(kws.get("name"), ast.Constant):
                name = name or kws["name"].value
                if isinstance(kws.get("version"), ast.Constant):
                    version = version or kws["version"].value
                elif "version" in kws:
                    computed = True
                break
    if not name:
        return None
    if not version:
        version = _module_version(project, str(name))
    if not version and computed:
        return {"ecosystem": "pypi", "name": str(name), "version": None,
                "note": "the version is computed at build time (from git, or by "
                        "code), so the published package cannot be matched to it"}
    if not version:
        return None
    return {"ecosystem": "pypi", "name": str(name), "version": str(version)}


def package_identity(project: Path) -> list[dict]:
    """The packages this checkout declares at its root: ecosystem, name, version."""
    found = []
    python = _python_package(project)
    if python:
        found.append(python)
    pkg = project / "package.json"
    if pkg.is_file():
        data = _load_json(read_text(pkg) or "")
        if isinstance(data, dict) and data.get("name") and data.get("version") \
                and data.get("private") is not True:
            found.append({"ecosystem": "npm", "name": str(data["name"]),
                          "version": str(data["version"])})
    return found


def _fetch_package(ecosystem: str, name: str, version: str, get=registry_get
                   ) -> tuple[str, bytes] | None:
    """The published archive of this version: (filename, bytes), or None."""
    if ecosystem == "pypi":
        url = (f"https://pypi.org/pypi/{urllib.parse.quote(name)}/"
               f"{urllib.parse.quote(version)}/json")
        try:
            meta = json.loads(get(url, 5 * 1024 * 1024))
        except FileNotFoundError:
            return None
        files = meta.get("urls") or []
        sdist = [f for f in files if f.get("packagetype") == "sdist"]
        wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
        chosen = (sdist or wheels or [None])[0]
        if not chosen:
            return None
        return chosen.get("filename") or "package", get(chosen["url"])
    if ecosystem == "npm":
        quoted = urllib.parse.quote(name, safe="@")
        url = f"https://registry.npmjs.org/{quoted.replace('/', '%2F')}/" \
              f"{urllib.parse.quote(version)}"
        try:
            meta = json.loads(get(url, 5 * 1024 * 1024))
        except FileNotFoundError:
            return None
        tarball = (meta.get("dist") or {}).get("tarball")
        if not tarball:
            return None
        return tarball.rsplit("/", 1)[-1], get(tarball)
    return None


MAX_MEMBER_BYTES = 4 * 1024 * 1024
# A compressed archive of a few megabytes can unpack to gigabytes.
MAX_UNPACKED_BYTES = 200 * 1024 * 1024
MAX_MEMBERS = 20_000


def archive_files(filename: str, data: bytes) -> dict[str, bytes]:
    """Members of a package archive, read in memory and never extracted.

    The common top directory (name-1.0/ in an sdist, package/ in npm) is
    dropped so paths line up with the repository's.
    """
    members: dict[str, bytes] = {}
    total = 0

    def keep(name: str, size: int) -> bool:
        nonlocal total
        if size > MAX_MEMBER_BYTES:
            return False
        if len(members) >= MAX_MEMBERS or total + size > MAX_UNPACKED_BYTES:
            raise RegistryError("the package unpacks to more than can be compared")
        total += size
        return True

    if filename.endswith((".whl", ".zip")):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if not info.is_dir() and keep(info.filename, info.file_size):
                    members[info.filename] = z.read(info)[:MAX_MEMBER_BYTES]
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
            for m in t:
                if m.isfile() and keep(m.name, m.size):
                    fh = t.extractfile(m)
                    if fh is not None:
                        members[m.name] = fh.read(MAX_MEMBER_BYTES)
    clean = {}
    for path, content in members.items():
        p = path.replace("\\", "/").lstrip("/")
        if ".." in PurePosixPath(p).parts:
            continue
        clean[p] = content
    tops = {p.split("/", 1)[0] for p in clean}
    if len(tops) == 1 and all("/" in p for p in clean) \
            and not filename.endswith(".whl"):
        clean = {p.split("/", 1)[1]: c for p, c in clean.items()}
    return clean


def _normal(content: bytes) -> bytes:
    return content.replace(b"\r\n", b"\n").rstrip()


def _setup_cfg_core(text: str) -> str:
    """What setup.cfg says, without the [egg_info] section a build adds to it.

    A build rewrites the file through configparser, which respaces every
    key, turns indentation into tabs and drops blank lines, so the two are
    compared by their sections and values, not as text.
    """
    parser = configparser.RawConfigParser(interpolation=None, strict=False)
    try:
        parser.read_string(text)
    except configparser.Error:
        return re.sub(r"(?ms)^\[egg_info\].*?(?=^\[|\Z)", "", text).strip()
    return json.dumps({
        section: {k: " ".join(v.split()) for k, v in parser.items(section)}
        for section in parser.sections() if section != "egg_info"}, sort_keys=True)


def _package_json_core(text: str) -> dict | None:
    data = _load_json(text)
    if not isinstance(data, dict):
        return None
    return {k: v for k, v in data.items() if not k.startswith("_") and k != "gitHead"}


def _diff_excerpt(a: str, b: str) -> dict:
    """Both versions of the lines that differ, aligned for side-by-side view."""
    al, bl = a.split("\n"), b.split("\n")
    rows = []
    for tag, i1, i2, j1, j2 in difflib.SequenceMatcher(None, al, bl,
                                                       autojunk=False).get_opcodes():
        if tag == "equal":
            continue
        lo_a, lo_b = max(0, i1 - CONTEXT_LINES), max(0, j1 - CONTEXT_LINES)
        for k in range(i1 - lo_a):
            rows.append({"n": lo_a + k + 1, "a": _clip(al[lo_a + k]),
                         "b": _clip(bl[lo_b + k]) if lo_b + k < len(bl) else None,
                         "marked": False})
        span = max(i2 - i1, j2 - j1)
        for k in range(span):
            rows.append({"n": i1 + k + 1 if i1 + k < i2 else None,
                         "a": _clip(al[i1 + k]) if i1 + k < i2 else None,
                         "b": _clip(bl[j1 + k]) if j1 + k < j2 else None,
                         "marked": True})
        if len(rows) >= MAX_EXCERPT_LINES:
            break
    return {"lines": rows[:MAX_EXCERPT_LINES],
            "truncated": len(rows) > MAX_EXCERPT_LINES}


def compare_release(git_files: dict[str, bytes], published: dict[str, bytes],
                    wheel: bool = False) -> list[dict]:
    """Files the package has that git does not, or has differently."""
    by_suffix: dict[str, str] = {}
    if wheel:
        # A wheel installs src/pkg/x.py as pkg/x.py.
        for path in git_files:
            parts = path.split("/")
            for i in range(len(parts)):
                by_suffix.setdefault("/".join(parts[i:]), path)
    out = []
    for path, content in sorted(published.items()):
        if _GENERATED.search(path):
            continue
        source = path if path in git_files else by_suffix.get(path)
        name = PurePosixPath(path).name.lower()
        suffix = PurePosixPath(path).suffix.lower()
        if source is None:
            if _VERSION_FILE.search(path) and len(content) < 2000:
                continue            # written by setuptools-scm and the like
            if name == "setup.cfg" and _setup_cfg_core(
                    content.decode("utf-8", "replace")) in ("", "{}"):
                continue            # only the [egg_info] section a build adds
            out.append({"path": path, "change": "added",
                        "code": suffix in _CODE_LIKE or name in _CODE_LIKE_NAMES,
                        "build_output": bool(_BUILD_OUTPUT.search(path))})
            continue
        ours = git_files[source]
        if _normal(ours) == _normal(content):
            continue
        if b"\0" in ours or b"\0" in content:
            out.append({"path": path, "source": source, "change": "modified",
                        "code": True, "excerpt": None, "binary": True})
            continue
        a, b = ours.decode("utf-8", "replace"), content.decode("utf-8", "replace")
        if name == "setup.cfg" and _setup_cfg_core(a) == _setup_cfg_core(b):
            continue
        if name == "package.json":
            core_a, core_b = _package_json_core(a), _package_json_core(b)
            if core_a is not None and core_a == core_b:
                continue
        out.append({"path": path, "source": source, "change": "modified",
                    "code": suffix in _CODE_LIKE or name in _CODE_LIKE_NAMES,
                    "excerpt": _diff_excerpt(a, b)})
    return out


# Protocols git may use to reach the audited repository's origin for its tags.
# Same rule as web/gitclone: only HTTPS in production.
ALLOWED_PROTOCOLS = ("https",)


def _git_run(project: Path, *args, timeout: int = 120, binary: bool = False):
    """git on the untrusted checkout, reading no config but its own, with no
    hook, filter or fsmonitor that could run anything."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
               GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1")
    config = ["-c", "core.fsmonitor=false", "-c", f"core.hooksPath={os.devnull}",
              "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=",
              "-c", "protocol.allow=never"]
    for protocol in ALLOWED_PROTOCOLS:
        config += ["-c", f"protocol.{protocol}.allow=always"]
    return subprocess.run(["git", *config, "-C", str(project), *args],
                          capture_output=True, text=not binary, env=env,
                          timeout=timeout)


def find_tag(project: Path, name: str, version: str) -> tuple[str, str] | None:
    """The tag this version was released from, and the commit it names."""
    try:
        r = _git_run(project, "ls-remote", "--tags", "origin")
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    refs: dict[str, str] = {}
    for line in r.stdout.splitlines():
        sha, _, ref = line.partition("\t")
        tag = ref.removeprefix("refs/tags/")
        if tag.endswith("^{}"):
            refs[tag[:-3]] = sha        # the commit an annotated tag points at
        else:
            refs.setdefault(tag, sha)
    short = name.rsplit("/", 1)[-1]
    for candidate in (f"v{version}", version, f"{name}-{version}", f"{short}-{version}",
                      f"{name}@{version}", f"{short}@{version}", f"release-{version}"):
        if candidate in refs:
            return candidate, refs[candidate]
    return None


def git_tree(project: Path, sha: str) -> dict[str, str]:
    """Every file at that commit and its blob, fetched if the shallow
    checkout does not have it. Nothing is checked out."""
    r = _git_run(project, "cat-file", "-e", f"{sha}^{{commit}}")
    if r.returncode != 0:
        f = _git_run(project, "fetch", "--depth", "1", "--no-recurse-submodules",
                     "--no-tags", "origin", sha, timeout=300)
        if f.returncode != 0:
            raise RegistryError("could not fetch the tagged commit")
    r = _git_run(project, "ls-tree", "-r", "-z", "--full-tree", sha)
    if r.returncode != 0:
        raise RegistryError("could not list the tagged commit")
    tree = {}
    for record in r.stdout.split("\0"):
        meta, _, path = record.partition("\t")
        bits = meta.split()
        if len(bits) == 3 and bits[1] == "blob" and bits[0] != "120000":
            tree[path] = bits[2]
    return tree


def read_blobs(project: Path, blobs: dict[str, str]) -> dict[str, bytes]:
    """The content of these blobs (path -> sha), in one `git cat-file --batch`."""
    if not blobs:
        return {}
    order = list(blobs.items())
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
    r = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "-C", str(project), "cat-file", "--batch"],
        input="".join(f"{sha}\n" for _, sha in order).encode(),
        capture_output=True, env=env, timeout=300)
    if r.returncode != 0:
        raise RegistryError("could not read the tagged files")
    out, pos, data = {}, 0, r.stdout
    for path, _ in order:
        end = data.index(b"\n", pos)
        header = data[pos:end].split()
        pos = end + 1
        if len(header) < 3 or header[1] != b"blob":
            continue                # "<sha> missing"
        size = int(header[2])
        if size <= MAX_MEMBER_BYTES:
            out[path] = data[pos:pos + size]
        pos += size + 1
    return out


def _sources_needed(tree: dict[str, str], published: dict[str, bytes],
                    wheel: bool) -> dict[str, str]:
    """The tagged files the package's files will be compared with."""
    if not wheel:
        return {p: tree[p] for p in published if p in tree}
    wanted = set(published)
    return {p: sha for p, sha in tree.items()
            if any("/".join(p.split("/")[i:]) in wanted
                   for i in range(p.count("/") + 1))}


def release_mismatch(project: Path, fetch=_fetch_package) -> tuple[list[Divergence], dict]:
    """Compare each package this checkout declares with what the registry serves.

    Returns the divergences and a note per package of what was compared with
    what, or why nothing was: an unpublished version, no tag to compare with,
    a registry that could not be reached. Those are said, never guessed.
    """
    out: list[Divergence] = []
    notes = []
    for pkg in package_identity(project):
        note = {k: pkg[k] for k in ("ecosystem", "name", "version")}
        if not pkg["version"]:
            notes.append({**note, "compared": False, "reason": pkg.get("note")})
            continue
        try:
            archive = fetch(pkg["ecosystem"], pkg["name"], pkg["version"])
        except (RegistryError, ValueError, json.JSONDecodeError) as e:
            notes.append({**note, "compared": False,
                          "reason": f"the registry could not be read: {e}"})
            continue
        if archive is None:
            notes.append({**note, "compared": False,
                          "reason": "this version is not published"})
            continue
        tag = find_tag(project, pkg["name"], pkg["version"])
        if tag is None:
            notes.append({**note, "compared": False,
                          "reason": f"no git tag for version {pkg['version']}, so "
                                    f"there is no source of that release to compare "
                                    f"the package with"})
            continue
        wheel = archive[0].endswith(".whl")
        try:
            published = archive_files(archive[0], archive[1])
            tree = git_tree(project, tag[1])
            contents = read_blobs(project, _sources_needed(tree, published, wheel))
            # Every tagged path is known, whether or not its content was read:
            # a file is "added" only if git does not have it at all.
            source = {p: contents.get(p, b"") for p in tree}
        except (RegistryError, tarfile.TarError, zipfile.BadZipFile, OSError,
                EOFError, ValueError, subprocess.TimeoutExpired) as e:
            notes.append({**note, "compared": False, "reason": str(e)[:200]})
            continue
        changes = compare_release(source, published, wheel=wheel)
        notes.append({**note, "compared": True, "tag": tag[0], "commit": tag[1],
                      "archive": archive[0], "published_files": len(published),
                      "differences": len(changes)})
        label = f"{pkg['name']} {pkg['version']} on {pkg['ecosystem']}"
        # Compiled JavaScript and type stubs under dist/ are expected in an npm
        # package; a Python file or a shell script there is not.
        built = [c for c in changes if c["change"] == "added" and c["build_output"]
                 and (not c["code"] or c["path"].endswith(_BUILT_SUFFIXES))]
        for c in changes:
            if c in built:
                continue
            if c["change"] == "modified":
                severity = "high" if c["code"] else "medium"
                detail = (f"{c['path']} in the package {label} is not the file at "
                          f"tag {tag[0]}")
                evidence = {"tag": tag[0], "archive": archive[0],
                            "change": "modified", "excerpt": c["excerpt"],
                            "binary": bool(c.get("binary"))}
            else:
                severity = "high" if c["code"] else "low"
                detail = (f"{c['path']} is in the package {label} but not in git "
                          f"at tag {tag[0]}")
                evidence = {"tag": tag[0], "archive": archive[0], "change": "added"}
            out.append(Divergence(c["path"], RELEASE_MISMATCH, detail, severity,
                                  evidence))
        if built:
            out.append(Divergence(
                "", RELEASE_MISMATCH,
                f"{len(built)} built file(s) in the package {label} have no "
                f"counterpart in git: what is installed was never reviewed as source",
                "low", {"tag": tag[0], "archive": archive[0], "change": "added",
                        "files": [c["path"] for c in built][:MAX_LISTED],
                        "more": max(0, len(built) - MAX_LISTED)}))
    return out, {"packages": notes}


# ---------------------------------------------------------------------------
# All of it
# ---------------------------------------------------------------------------

MAX_SCAN_CHARS = 2_000_000
MAX_DIVERGENCES = 300


def repository_texts(project: Path) -> dict[str, str]:
    """Every text file of the checkout, outside dependency and VCS folders."""
    texts = {}
    for root, dirs, files in os.walk(project, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d != ".git" and d not in SKIP_DIRS)
        for name in sorted(files):
            full = Path(root) / name
            if full.is_symlink():
                continue
            try:
                if full.stat().st_size > MAX_SCAN_CHARS:
                    continue
            except OSError:
                continue
            text = read_text(full)
            if text is not None:
                texts[full.relative_to(project).as_posix()] = text
    return texts


def published_check_enabled() -> bool:
    return os.environ.get("SECAUDIT_PUBLISHED_CHECK", "1").strip().lower() \
        not in ("0", "false", "no", "off")


def analyze(project: Path | None, coverage: list[dict] | None = None,
            coverage_summary: dict | None = None, published: bool | None = None,
            fetch=_fetch_package) -> dict:
    """Every divergence between the views of this checkout.

    With no checkout (a runner's commit the server could not fetch), only the
    blind spots can be told, from the coverage the runner reported.
    """
    divergences: list[Divergence] = []
    release = {"packages": [], "checked": False}
    if project is not None:
        texts = repository_texts(project)
        links = set(git_symlinks(project))
        for rel, text in texts.items():
            if rel not in links:
                divergences += hidden_content(rel, text)
        divergences += unexpected_execution(
            project, {r: t for r, t in texts.items() if r not in links})
        if published if published is not None else published_check_enabled():
            found, release = release_mismatch(project, fetch)
            release["checked"] = True
            divergences += found
        else:
            release["reason"] = "the published view is turned off on this instance"
    divergences += audit_blind_spots(coverage, coverage_summary)
    order = {s: i for i, s in enumerate(SEVERITIES)}
    # A repository can be built to produce thousands: the worst are kept.
    divergences.sort(key=lambda d: (order.get(d.severity, 9), KINDS.index(d.kind), d.file))
    left_out = max(0, len(divergences) - MAX_DIVERGENCES)
    divergences = divergences[:MAX_DIVERGENCES]
    divergences.sort(key=lambda d: (KINDS.index(d.kind), order.get(d.severity, 9),
                                    d.file))
    return {"divergences": [d.to_dict() for d in divergences], "published": release,
            "left_out": left_out}


def _storable(value):
    """PostgreSQL refuses NUL in text and in JSON: none survives."""
    if isinstance(value, str):
        return value.replace("\0", "")
    if isinstance(value, dict):
        return {_storable(k): _storable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_storable(v) for v in value]
    return value


def normalize_kind_severity(d: dict) -> dict:
    """A divergence dict as storable: known kind, known severity, bounded text."""
    kind = d.get("kind") if d.get("kind") in KINDS else AUDIT_BLIND_SPOT
    severity = d.get("severity") if d.get("severity") in SEVERITIES else "info"
    view_a, view_b = VIEWS[kind]
    evidence = d.get("evidence") if isinstance(d.get("evidence"), dict) else None
    return _storable({
        "file": str(d.get("file") or "")[:512], "view_a": view_a,
        "view_b": view_b, "kind": kind, "severity": severity,
        "detail": unicodedata.normalize("NFC", str(d.get("detail") or ""))[:4000],
        "evidence": evidence})
