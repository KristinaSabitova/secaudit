"""Thin wrapper around the CLI engine (secaudit.py, imported unmodified)."""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import asdict
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import secaudit as engine


log = logging.getLogger(__name__)


class AuditError(Exception):
    """The engine could not produce findings."""


# Everything the audit process is given, and nothing else. This was a denylist
# of the two API-key variables, which meant the rest of the server's
# environment travelled with it: SECAUDIT_SECRET_KEY, the master key that
# decrypts every user's stored credential, DATABASE_URL with the database
# password, and the OAuth and webhook secrets. That process runs the engine
# over a repository a caller chose, and with the claude-code backend it runs an
# agent with that untrusted checkout as its working directory. A denylist only
# withholds the leaks somebody thought to name, so the rule is inverted: the
# child starts from nothing and is handed what the engine actually reads.
_ENV_ALLOWLIST = (
    # Enough of an environment to start a Python process and find a binary.
    "PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ",
    "SYSTEMROOT", "TEMP", "TMP",                 # Windows needs these to spawn
    # Read by the engine itself (secaudit.py).
    "SHELL", "CLAUDE_BIN",
    # Engine configuration. Not secret, and the config also travels in the
    # request, but the child reads the environment for anything the caller
    # left unset.
    "SECAUDIT_BACKEND", "SECAUDIT_MODEL", "SECAUDIT_OLLAMA_URL",
    "SECAUDIT_CONTEXT_CHARS", "SECAUDIT_MAX_OUTPUT_TOKENS", "SECAUDIT_TIMEOUT",
)

# Every backend option the CLI reads from its config file must also be
# settable through the environment: a container has no config file.
_ENV_CONFIG = {
    "SECAUDIT_BACKEND": "backend",
    "SECAUDIT_MODEL": "model",
    "SECAUDIT_OLLAMA_URL": "ollama_url",
    # How much source a single-request backend may be handed per audit.
    "SECAUDIT_CONTEXT_CHARS": "context_chars",
    # Room the backend has to write the findings in.
    "SECAUDIT_MAX_OUTPUT_TOKENS": "max_output_tokens",
}


# Shapes that are worth masking even before knowing which SDK produced them:
# an exception message is written by someone else's library, and some of them
# quote the request they just made.
_KEY_PATTERNS = (
    re.compile(r'sk-ant-[A-Za-z0-9_\-]{8,}'),
    re.compile(r'sk-[A-Za-z0-9_\-]{16,}'),
    re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}'),
    re.compile(r'(?i)\b(ANTHROPIC_API_KEY|OPENAI_API_KEY|x-api-key|authorization)'
               r'\b(\s*[:=]\s*|\s+)(?:bearer\s+)?[A-Za-z0-9+/=_\-]{8,}'),
)

MASK = "[REDACTED]"


def sanitize_error(message: str) -> str:
    """Mask anything credential-shaped in an error before it is stored or shown.

    Audit failures are persisted on the audit and served over the API, and the
    text comes from a backend SDK's exception — which is free to quote the
    request it just made, key header included.
    """
    if not message:
        return message
    text = engine.redact_secrets(str(message))
    for pattern in _KEY_PATTERNS:
        text = pattern.sub(
            lambda m: (f"{m.group(1)}{m.group(2)}{MASK}"
                       if m.re.groups >= 2 else MASK),
            text,
        )
    return text


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


def run_audit_in_process(project: Path, config: dict, timeout: int) -> list[dict]:
    """Drive the engine directly. Only web/runner.py should call this.

    Everything else goes through run_audit(), which isolates the credentials.
    """
    language = config.get("language") or engine.LANGUAGES[0]
    try:
        backend = engine.select_backend(None, config)
        prompt = engine.build_diff_prompt(None, "all", None, language)
        # Hands the checkout to a backend that cannot open files itself.
        prompt = backend.prepare(project, prompt)
        raw_output = backend.run(project, prompt, timeout=timeout)
    except SystemExit as e:  # the engine reports failures via sys.exit()
        raise AuditError(sanitize_error(str(e.code)) if e.code
                         else "engine aborted") from e

    raw = engine.extract_json_findings(raw_output)
    if raw is engine._PARSE_FAILED:
        # Distinguish the two ways this happens, because the fix differs: a
        # cut-off answer needs more room, anything else is the backend not
        # answering in the requested format at all.
        if raw_output.lstrip().startswith("[") or '"category"' in raw_output:
            raise AuditError(
                "the backend's answer was cut off before it could be read as "
                "findings — raise SECAUDIT_MAX_OUTPUT_TOKENS or audit a "
                "smaller scope")
        raise AuditError("backend output was not parseable as JSON findings")
    # classify() with empty saved state: builds Finding objects, redacts
    # secrets and computes fingerprints without touching CLI state files.
    # The checkout decides whether a proxy-provided control can be judged
    # missing from here at all.
    _, findings = engine.classify(
        raw, {}, engine.project_has_server_config(project))
    return [asdict(f) for f in findings]


def run_audit(project: Path, config: dict | None = None,
              credentials: dict[str, str] | None = None) -> list[dict]:
    """Run a full structured audit on a checked-out project directory.

    credentials are the environment variables holding this audit's API key.
    They are passed to a dedicated process rather than exported here, so
    concurrent audits for different users cannot see each other's key.
    """
    timeout = int(os.environ.get("SECAUDIT_TIMEOUT", "3600"))
    request = json.dumps({
        "project": str(project),
        "config": config if config is not None else backend_config(),
        "timeout": timeout,
    })
    # Build the child's environment from nothing: it gets what the engine
    # reads and this audit's own credentials, and no other secret the server
    # happens to be holding.
    env = {name: os.environ[name] for name in _ENV_ALLOWLIST if name in os.environ}
    env.update(credentials or {})

    try:
        result = subprocess.run(
            [sys.executable, "-m", "web.runner"],
            input=request, capture_output=True, text=True, env=env,
            cwd=str(_ROOT), timeout=timeout + 30,
        )
    except subprocess.TimeoutExpired:
        raise AuditError(f"audit timed out after {timeout}s")

    try:
        response = json.loads(result.stdout)
    except json.JSONDecodeError:
        # stderr is a traceback from someone else's SDK: mask it before it is
        # stored on the audit and served back over the API.
        detail = (result.stderr or "").strip().splitlines()
        raise AuditError(sanitize_error(
            f"audit process produced no result: "
            f"{detail[-1] if detail else f'exit {result.returncode}'}"))
    if "error" in response:
        raise AuditError(sanitize_error(str(response["error"])))
    return response["findings"]


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
        # Whether the connection was refused, timed out or was filtered tells a
        # caller who chose this address what is listening behind the server.
        # The operator gets that detail in the log; the API gets none of it.
        log.info("Ollama probe of %s failed: %s", base, e)
        return False, f"cannot reach Ollama at {base}"
    if not models:
        return False, f"Ollama at {base} has no models pulled"
    if not any(m == want or m.split(":")[0] == want.split(":")[0] for m in models):
        return False, f"model '{want}' not pulled; available: {', '.join(models)}"
    return True, None


def _credential_ready(env_name: str, credentials: dict) -> tuple[bool, str | None]:
    if credentials.get(env_name) or os.environ.get(env_name):
        return True, None
    return False, f"{env_name} is not set"


def _claude_code_ready() -> tuple[bool, str | None]:
    if os.environ.get("CLAUDE_BIN") or shutil.which("claude"):
        return True, None
    return False, "the 'claude' binary is not on PATH"


def backend_status(config: dict | None = None,
                   credentials: dict[str, str] | None = None) -> dict:
    """Report which backend is configured and whether it looks usable."""
    config = config or backend_config()
    credentials = credentials or {}
    name = config.get("backend", "claude-code")
    try:
        engine.select_backend(None, config)
    except SystemExit as e:
        return {"name": name, "ready": False, "detail": str(e.code), "model": None}

    if name == "ollama":
        ready, detail = _ollama_ready(config)
        model = config.get("model") or engine.OllamaBackend.DEFAULT_MODEL
    elif name == "anthropic-api":
        ready, detail = _credential_ready("ANTHROPIC_API_KEY", credentials)
        model = config.get("model") or engine.AnthropicAPIBackend.DEFAULT_MODEL
    elif name == "openai-api":
        ready, detail = _credential_ready("OPENAI_API_KEY", credentials)
        model = config.get("model") or engine.OpenAIBackend.DEFAULT_MODEL
    elif name == "claude-code":
        ready, detail = _claude_code_ready()
        model = None
    else:
        ready, detail, model = True, None, config.get("model")

    return {"name": name, "ready": ready, "detail": detail, "model": model}
