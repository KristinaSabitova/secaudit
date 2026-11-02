"""Run analysis/scan.py in a child process with limits (B19).

The child gets:

- an environment with nothing secret in it (PATH, locale, temp dir, and the
  scan bounds);
- CPU time, address space and file-size limits (RLIMIT_CPU, RLIMIT_AS,
  RLIMIT_FSIZE), where the platform supports them;
- a wall-clock timeout, after which it is killed;
- the secaudit checkout as its working directory, never the audited one, and
  Python started with -E -s (no PYTHON* variables, no user site-packages).

What it prints is parsed as JSON and nothing else: a crash, a timeout or a
memory error comes back as ScanError, and the audit records the scanners as
failed instead of failing itself.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

_ENV = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TMPDIR", "TZ", "HOME",
        "SECAUDIT_MAX_SCAN_CHARS", "SECAUDIT_MAX_SCAN_FILES")

DEFAULT_TIMEOUT = 600
DEFAULT_MEMORY_MB = 2048
MAX_OUTPUT = 200_000_000


class ScanError(Exception):
    pass


def _limits(cpu_seconds: int, memory_mb: int):
    def apply():
        try:
            import resource
        except ImportError:         # not on this platform
            return
        for name, value in (("RLIMIT_CPU", cpu_seconds),
                            ("RLIMIT_AS", memory_mb * 1024 * 1024),
                            ("RLIMIT_FSIZE", 64 * 1024 * 1024),
                            ("RLIMIT_CORE", 0)):
            limit = getattr(resource, name, None)
            if limit is None:
                continue
            try:
                resource.setrlimit(limit, (value, value))
            except (ValueError, OSError):
                pass                # macOS refuses some (RLIMIT_AS); Linux keeps them
    return apply


def timeout_from_env() -> int:
    try:
        return max(30, int(os.environ.get("SECAUDIT_SCAN_TIMEOUT", DEFAULT_TIMEOUT)))
    except ValueError:
        return DEFAULT_TIMEOUT


def memory_from_env() -> int:
    try:
        return max(256, int(os.environ.get("SECAUDIT_SCAN_MEMORY_MB", DEFAULT_MEMORY_MB)))
    except ValueError:
        return DEFAULT_MEMORY_MB


def run_scan(project: Path, language: str, history: int,
             timeout: int | None = None) -> dict:
    timeout = timeout or timeout_from_env()
    env = {k: os.environ[k] for k in _ENV if k in os.environ}
    request = json.dumps({"project": str(project), "language": language,
                          "history": history})
    try:
        r = subprocess.run([sys.executable, "-E", "-s", "-m", "analysis.scan"],
                           input=request, capture_output=True, text=True, cwd=ROOT,
                           env=env, timeout=timeout,
                           preexec_fn=_limits(timeout, memory_from_env())
                           if os.name == "posix" else None)
    except subprocess.TimeoutExpired:
        raise ScanError(f"the scanners took longer than {timeout}s and were stopped")
    if r.returncode != 0:
        tail = (r.stderr or "").strip().splitlines()[-1:] or [f"exit {r.returncode}"]
        raise ScanError(f"the scanner process failed: {tail[0][:300]}")
    if len(r.stdout) > MAX_OUTPUT:
        raise ScanError("the scanner output is too large")
    try:
        return json.loads(r.stdout)
    except ValueError:
        raise ScanError("the scanner process did not return JSON")
