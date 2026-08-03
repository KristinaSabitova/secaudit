"""Validation and shallow cloning of GitHub repositories."""

import os
import re
import subprocess
from pathlib import Path

# Only HTTPS github.com URLs with exactly owner/repo are accepted.
_GITHUB_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9][A-Za-z0-9_.\-]*)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)

CLONE_TIMEOUT = int(os.environ.get("SECAUDIT_CLONE_TIMEOUT", "120"))


class CloneError(Exception):
    """git clone failed or the cloned repo is unusable."""


def validate_repo_url(url: str) -> str:
    """Return the normalised clone URL, or raise ValueError."""
    m = _GITHUB_RE.match(url.strip())
    if not m:
        raise ValueError(
            "repo_url must be an HTTPS github.com repository URL "
            "(https://github.com/<owner>/<repo>)"
        )
    owner, repo = m.groups()
    if repo.startswith("-") or repo in (".", ".."):
        raise ValueError("invalid repository name")
    return f"https://github.com/{owner}/{repo}.git"


def clone_repo(url: str, dest: Path, timeout: int = CLONE_TIMEOUT) -> str:
    """Shallow-clone url into dest and return the HEAD commit sha."""
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        r = subprocess.run(
            ["git", "clone", "--depth", "1", "--", url, str(dest)],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        raise CloneError(f"git clone timed out after {timeout}s")
    if r.returncode != 0:
        detail = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else f"exit {r.returncode}"
        raise CloneError(f"git clone failed: {detail}")

    rev = subprocess.run(
        ["git", "-C", str(dest), "rev-parse", "HEAD"],
        capture_output=True, text=True,
    )
    if rev.returncode != 0:
        raise CloneError("could not resolve HEAD of cloned repository")
    return rev.stdout.strip()
