"""Thin wrapper around the CLI engine (secaudit.py, imported unmodified)."""

import json
import os
import shutil
import sys
import urllib.request
from dataclasses import asdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import secaudit as engine


class AuditError(Exception):
    """The engine could not produce findings."""


# Every backend option the CLI reads from its config file must also be
# settable through the environment: a container has no config file.
_ENV_CONFIG = {
    "SECAUDIT_BACKEND": "backend",
    "SECAUDIT_MODEL": "model",
    "SECAUDIT_OLLAMA_URL": "ollama_url",
}


def backend_config(overrides: dict | None = None) -> dict:
    """Engine configuration, in increasing order of precedence.

    The CLI's config file, then the environment, then whatever was configured
    from the dashboard.
    """
    config = dict(engine.load_config())
    for env_name, key in _ENV_CONFIG.items():
        value = os.environ.get(env_name)
        if value:
            config[key] = value
    config.update(overrides or {})
    return config


def run_audit(project: Path, config: dict | None = None) -> list[dict]:
    """Run a full structured audit on a checked-out project directory.

    Returns findings as JSON-serialisable dicts (Finding fields).
    """
    timeout = int(os.environ.get("SECAUDIT_TIMEOUT", "3600"))
    try:
        backend = engine.select_backend(None, config or backend_config())
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


OLLAMA_PROBE_TIMEOUT = 2


def _ollama_ready(config: dict) -> tuple[bool, str | None]:
    """Ask the Ollama server whether it is up and has a model to generate with.

    An embedding-only model cannot produce findings, so a reachable server with
    no generative model is reported as not ready.
    """
    base = (config.get("ollama_url") or engine.OllamaBackend.DEFAULT_URL).rstrip("/")
    want = config.get("model") or engine.OllamaBackend.DEFAULT_MODEL
    try:
        with urllib.request.urlopen(f"{base}/api/tags",
                                    timeout=OLLAMA_PROBE_TIMEOUT) as resp:
            models = [m.get("name", "") for m in json.loads(resp.read()).get("models", [])]
    except Exception as e:
        return False, f"cannot reach Ollama at {base}: {e}"
    if not models:
        return False, f"Ollama at {base} has no models pulled"
    if not any(m == want or m.split(":")[0] == want.split(":")[0] for m in models):
        return False, f"model '{want}' not pulled; available: {', '.join(models)}"
    return True, None


def _credential_ready(env_name: str) -> tuple[bool, str | None]:
    if os.environ.get(env_name):
        return True, None
    return False, f"{env_name} is not set"


def _claude_code_ready() -> tuple[bool, str | None]:
    if os.environ.get("CLAUDE_BIN") or shutil.which("claude"):
        return True, None
    return False, "the 'claude' binary is not on PATH"


def backend_status(config: dict | None = None) -> dict:
    """Report which backend is configured and whether it looks usable."""
    config = config or backend_config()
    name = config.get("backend", "claude-code")
    try:
        engine.select_backend(None, config)
    except SystemExit as e:
        return {"name": name, "ready": False, "detail": str(e.code), "model": None}

    if name == "ollama":
        ready, detail = _ollama_ready(config)
        model = config.get("model") or engine.OllamaBackend.DEFAULT_MODEL
    elif name == "anthropic-api":
        ready, detail = _credential_ready("ANTHROPIC_API_KEY")
        model = config.get("model") or engine.AnthropicAPIBackend.DEFAULT_MODEL
    elif name == "openai-api":
        ready, detail = _credential_ready("OPENAI_API_KEY")
        model = config.get("model") or engine.OpenAIBackend.DEFAULT_MODEL
    elif name == "claude-code":
        ready, detail = _claude_code_ready()
        model = None
    else:
        ready, detail, model = True, None, config.get("model")

    return {"name": name, "ready": ready, "detail": detail, "model": model}
