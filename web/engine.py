"""Thin wrapper around the CLI engine (secaudit.py, imported unmodified)."""

import os
import shutil
import sys
from dataclasses import asdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import secaudit as engine


class AuditError(Exception):
    """The engine could not produce findings."""


def run_audit(project: Path) -> list[dict]:
    """Run a full structured audit on a checked-out project directory.

    Returns findings as JSON-serialisable dicts (Finding fields).
    """
    backend_name = os.environ.get("SECAUDIT_BACKEND") or None
    timeout = int(os.environ.get("SECAUDIT_TIMEOUT", "3600"))
    try:
        backend = engine.select_backend(backend_name)
        prompt = engine.build_diff_prompt(None, "all", None)
        raw_output = backend.run(project, prompt, timeout=timeout)
    except SystemExit as e:  # the engine reports failures via sys.exit()
        raise AuditError(str(e.code) if e.code else "engine aborted") from e

    raw = engine.extract_json_findings(raw_output)
    if raw is engine._PARSE_FAILED:
        raise AuditError("backend output was not parseable as JSON findings")
    # classify() with empty saved state: builds Finding objects, redacts
    # secrets and computes fingerprints without touching CLI state files.
    _, findings = engine.classify(raw, {})
    return [asdict(f) for f in findings]


_READINESS = {
    "claude-code": lambda: bool(os.environ.get("CLAUDE_BIN") or shutil.which("claude")),
    "anthropic-api": lambda: bool(os.environ.get("ANTHROPIC_API_KEY")),
    "openai-api": lambda: bool(os.environ.get("OPENAI_API_KEY")),
    "ollama": lambda: True,
}


def backend_status() -> dict:
    """Report which backend is configured and whether it looks usable."""
    flag = os.environ.get("SECAUDIT_BACKEND") or None
    try:
        engine.select_backend(flag)
    except SystemExit as e:
        return {"name": flag, "ready": False, "detail": str(e.code)}
    name = flag or engine.load_config().get("backend", "claude-code")
    ready = _READINESS.get(name, lambda: True)()
    return {
        "name": name,
        "ready": ready,
        "detail": None if ready else "missing credentials or binary",
    }
