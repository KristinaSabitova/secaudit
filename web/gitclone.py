"""Validation and shallow cloning of GitHub repositories."""

import os
import re
import subprocess
from pathlib import Path

# Only HTTPS github.com URLs with exactly owner/repo are accepted.
_GITHUB_RE = re.compile(
    r"^https://github\.com/([A-Za-z0-9][A-Za-z0-9_.\-]*)/([A-Za-z0-9_.\-]+?)(?:\.git)?/?$"
)

# Conservative subset of git's ref rules: no leading dash (which git would read
# as an option), no "..", no whitespace or shell-significant characters.
_BRANCH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,254}$")

CLONE_TIMEOUT = int(os.environ.get("SECAUDIT_CLONE_TIMEOUT", "120"))

# The repository being cloned is untrusted, and so is anything that could make
# git act on it. Cloning runs on the server and also through the runner on the
# owner's own computer, where git reads that person's global and system config:
# a global core.hooksPath runs its post-checkout hook in the fresh checkout, the
# LFS filter that `git lfs install` registers globally downloads whatever the
# repository's .gitattributes points it at, and credential helpers offer the
# keychain to whatever host the clone talks to. So none of that is read. git is
# told to use no global or system config at all, and the settings that decide
# whether anything in the checkout runs or escapes it are pinned explicitly,
# both for the clone itself and in the checkout's own config, which every later
# git command in it reads.
_HARDENED_CONFIG = (
    f"core.hooksPath={os.devnull}",     # no hook runs, from any directory
    "core.symlinks=false",              # a link is checked out as a plain file
    "core.fsmonitor=false",             # fsmonitor is a command git would run
    "submodule.recurse=false",
    "filter.lfs.smudge=",               # never fetch LFS objects on checkout
    "filter.lfs.process=",
    "filter.lfs.required=false",
)

# Protocols git may use, for the clone and for anything it would follow from
# there (a submodule URL, a redirect). Only HTTPS is ever cloned in production.
ALLOWED_PROTOCOLS = ("https",)


def git_env() -> dict:
    """The environment for every git command run on an untrusted checkout.

    The GIT_* variables of the calling process are dropped as well: one of them
    (GIT_CONFIG_PARAMETERS, GIT_CONFIG_COUNT, GIT_DIR...) is enough to bring
    configuration back or to point git somewhere else.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_LFS_SKIP_SMUDGE": "1",
    })
    return env


def git_config_args() -> list[str]:
    """`git -c` options that apply the hardened config to a single command."""
    args = []
    for setting in _HARDENED_CONFIG:
        args += ["-c", setting]
    args += ["-c", "protocol.allow=never"]
    for protocol in ALLOWED_PROTOCOLS:
        args += ["-c", f"protocol.{protocol}.allow=always"]
    return args


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


def validate_branch(name: str) -> str:
    """Return the branch name unchanged, or raise ValueError."""
    name = name.strip()
    if not _BRANCH_RE.match(name) or ".." in name or name.endswith(".lock"):
        raise ValueError("invalid branch name")
    return name


_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _git(args: list[str], timeout: int, what: str) -> None:
    try:
        r = subprocess.run(["git", *git_config_args(), *args], capture_output=True,
                           text=True, timeout=timeout, env=git_env())
    except subprocess.TimeoutExpired:
        raise CloneError(f"{what} timed out after {timeout}s")
    if r.returncode != 0:
        detail = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else f"exit {r.returncode}"
        raise CloneError(f"{what} failed: {detail}")


def clone_at_commit(url: str, dest: Path, sha: str,
                    timeout: int = CLONE_TIMEOUT) -> str:
    """Check out exactly this commit, whatever the branch points at now.

    Used to check a runner's findings: the branch may have moved since the
    runner cloned it, and the evidence has to be read from the code that was
    audited, not from what came after. Same hardening as clone_repo.
    """
    if not _SHA_RE.match(sha or ""):
        raise CloneError("not a full commit sha")
    clone_repo(url, dest, timeout=timeout, no_checkout=True)
    _git(["-C", str(dest), "fetch", "--depth", "1", "--no-recurse-submodules",
          "origin", sha], timeout, "git fetch")
    _git(["-C", str(dest), "checkout", "-q", "--detach", sha], timeout,
         "git checkout")
    return sha


def clone_repo(url: str, dest: Path, timeout: int = CLONE_TIMEOUT,
               branch: str | None = None, no_checkout: bool = False) -> str:
    """Shallow-clone url into dest and return the HEAD commit sha.

    With no branch, git checks out the repository's default branch.
    """
    cmd = ["git", *git_config_args(), "clone", "--depth", "1",
           "--no-recurse-submodules",
           # No template: a template directory is where hooks would come from.
           "--template="]
    if no_checkout:
        cmd.append("--no-checkout")
    for setting in _HARDENED_CONFIG:
        cmd += ["--config", setting]
    if branch is not None:
        cmd += ["--branch", validate_branch(branch), "--single-branch"]
    cmd += ["--", url, str(dest)]

    env = git_env()
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, env=env,
        )
    except subprocess.TimeoutExpired:
        raise CloneError(f"git clone timed out after {timeout}s")
    if r.returncode != 0:
        detail = r.stderr.strip().splitlines()[-1] if r.stderr.strip() else f"exit {r.returncode}"
        raise CloneError(f"git clone failed: {detail}")

    rev = subprocess.run(
        ["git", *git_config_args(), "-C", str(dest), "rev-parse", "HEAD"],
        capture_output=True, text=True, env=env,
    )
    if rev.returncode != 0:
        raise CloneError("could not resolve HEAD of cloned repository")
    return rev.stdout.strip()
