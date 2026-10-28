"""Checking a finding's evidence against the code it claims to quote.

A backend reports each finding with a snippet it says it copied from a file.
Until now "verified" meant the model said so. Here the snippet is looked up in
the real file, at the audited commit, within the lines that were actually sent
to the request that produced the finding. If it is there, the finding gets the
line range it occupies; if not, it is not evidence, whatever the model said.

The comparison ignores differences in whitespace, so re-indentation by the
model does not count against it, but nothing else: a paraphrase, an elision
or code written from memory does not match.
"""

import hashlib
import re
from pathlib import Path

from .chunking import read_text

# How engine.redact_secrets masks a value: a type-free tag with the first six
# hex digits of the value's SHA-256. The snippet stored for a finding is
# already redacted, so a masked value has to be matched against the secret
# still sitting in the file — and the hash says whether it is that secret.
_MASK = re.compile(r"\[REDACTED:([0-9a-f]{6})\]")
_SECRET_VALUE = r"([A-Za-z0-9+/=_\-.]{8,})"

# A snippet copied with the excerpt's reading aid still on it: "   12| code".
_LINE_NUMBER = re.compile(r"^\s*\d+\s*\|\s?")

# A one-line snippet is matched anywhere inside a line, so it has to be long
# enough that matching it means something.
MIN_SINGLE_LINE_CHARS = 6

NOT_IN_FILE = "the code_snippet does not appear in {file} at the audited commit"
NOT_SENT = "{file} was not among the files sent to the auditor in this request"
NO_FILE = "{file} does not exist in the audited checkout"


def normalize(line: str) -> str:
    return re.sub(r"\s+", " ", line).strip()


def _snippet_lines(snippet: str) -> list[str]:
    lines = snippet.splitlines()
    numbered = [l for l in lines if l.strip()]
    if numbered and all(_LINE_NUMBER.match(l) for l in numbered):
        lines = [_LINE_NUMBER.sub("", l, count=1) for l in lines]
    return [n for n in (normalize(l) for l in lines) if n]


class _Line:
    """One snippet line, and how it may match a line of the file."""

    def __init__(self, text: str):
        self.text = text
        self.hashes = _MASK.findall(text)
        if self.hashes:
            parts = _MASK.split(text)[::2]     # split keeps the groups; drop them
            self.pattern = _SECRET_VALUE.join(re.escape(p) for p in parts)

    def matches(self, line: str, mode: str) -> bool:
        if not self.hashes:
            return {"equal": line == self.text,
                    "suffix": line.endswith(self.text),
                    "prefix": line.startswith(self.text),
                    "inside": self.text in line}[mode]
        anchored = {"equal": f"^{self.pattern}$", "suffix": f"{self.pattern}$",
                    "prefix": f"^{self.pattern}", "inside": self.pattern}[mode]
        m = re.search(anchored, line)
        if not m:
            return False
        return all(hashlib.sha256(value.encode()).hexdigest()[:6] == h
                   for value, h in zip(m.groups(), self.hashes))


def locate(snippet: str, text: str, hint: int | None = None,
           first_line: int = 1) -> tuple[int, int] | None:
    """The line range snippet occupies in text, or None if it is not there.

    text starts at line first_line of its file. Blank lines are skipped on
    both sides. The first line of a multi-line snippet may begin partway
    into a line of the file and its last line may stop short of the end, as
    when a model starts quoting mid-statement; every line in between must be
    whole. When the snippet occurs more than once, the occurrence nearest to
    the line the model pointed at wins.
    """
    wanted = [_Line(l) for l in _snippet_lines(snippet)]
    if not wanted:
        return None
    if len(wanted) == 1 and len(wanted[0].text.replace(" ", "")) < MIN_SINGLE_LINE_CHARS:
        modes = ["equal"]
    elif len(wanted) == 1:
        modes = ["inside"]
    else:
        modes = ["suffix"] + ["equal"] * (len(wanted) - 2) + ["prefix"]

    lines = [(i, normalize(l)) for i, l in enumerate(text.splitlines(), first_line)]
    lines = [(i, l) for i, l in lines if l]
    found = []
    for start in range(len(lines) - len(wanted) + 1):
        if all(w.matches(lines[start + k][1], modes[k])
               for k, w in enumerate(wanted)):
            found.append((lines[start][0], lines[start + len(wanted) - 1][0]))
    if not found:
        return None
    if hint:
        return min(found, key=lambda r: abs(r[0] - hint))
    return found[0]


def _sent_ranges(manifest, path: str, chunk: int | None) -> list[tuple[int, int]] | None:
    """The line ranges of path that the request shown the finding carried.

    None when there is no manifest to go by, which means the whole file.
    """
    if manifest is None:
        return None
    ranges = []
    for part in manifest:
        if chunk is not None and part.get("index") != chunk:
            continue
        for f in part.get("files") or []:
            if f.get("file") == path:
                ranges.append((int(f.get("start") or 1), int(f.get("end") or 0)))
    return ranges


def _read_in(project: Path, path: str) -> str | None:
    """A file of the checkout, refusing anything that resolves outside it."""
    root = project.resolve()
    target = (project / path)
    try:
        resolved = target.resolve()
    except (OSError, RuntimeError):
        return None
    if root not in resolved.parents or target.is_symlink() or not resolved.is_file():
        return None
    return read_text(resolved)


def check(project: Path, finding: dict, manifest=None) -> dict:
    """What the evidence check concludes about one finding.

    Returns the fields to update: line, line_end, and — only ever downwards —
    verification_status and verification_note. A finding never becomes
    verified here; it can only stop being so.
    """
    out = {"line": None, "line_end": None}
    # Only a leading "./" goes: lstrip("./") would turn ".env" into "env".
    path = re.sub(r"^(\./)+", "", str(finding.get("file") or "").strip())
    snippet = str(finding.get("code_snippet") or "")
    if not path or not snippet.strip():
        return out                     # already unverified for lack of evidence

    def degrade(note: str) -> dict:
        if finding.get("verification_status") == "verified":
            out.update(verification_status="unverified",
                       verification_note=f"degraded to unverified: {note}")
        return out

    text = _read_in(project, path)
    if text is None:
        return degrade(NO_FILE.format(file=path))
    chunk = finding.get("chunk") if isinstance(finding.get("chunk"), int) else None
    ranges = _sent_ranges(manifest, path, chunk)
    if ranges == []:
        return degrade(NOT_SENT.format(file=path))

    hint = finding.get("line") if isinstance(finding.get("line"), int) else None
    all_lines = text.splitlines()
    for start, end in ranges or [(1, len(all_lines))]:
        window = "\n".join(all_lines[start - 1:end])
        where = locate(snippet, window, hint, first_line=start)
        if where:
            out["line"], out["line_end"] = where
            return out
    return degrade(NOT_IN_FILE.format(file=path))


def verify_findings(project: Path, findings: list[dict], manifest=None) -> list[dict]:
    """check() every finding and apply the result in place."""
    for finding in findings:
        finding.update(check(project, finding, manifest))
    return findings
