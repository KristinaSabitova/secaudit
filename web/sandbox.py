"""Running a repository's tests in a throwaway container, for What If (C29).

This is the one place secaudit runs code from an audited repository, so it
is off unless the administrator turns it on (SECAUDIT_WHATIF_SANDBOX=docker)
and needs a Docker daemon on the host that runs the server.

Each run:

- works on a copy of the checkout made for it, never the clone the audit
  used and never the person's repository;
- runs as nobody (65534), with every capability dropped, no-new-privileges,
  a read-only root filesystem, a small /tmp, and limits on memory, CPU,
  processes and time (SECAUDIT_SANDBOX_MEMORY_MB, _CPUS, _TIMEOUT);
- has no network while the tests run. Installing dependencies needs it, so
  that step only happens with SECAUDIT_SANDBOX_INSTALL=1, in its own
  container, and npm runs with --ignore-scripts. A pip install can still run
  a package's build code: that is why it is opt-in, and why it happens inside
  the container too;
- uses an image already on the host (--pull=never): nothing is downloaded
  behind the administrator's back.

The same tests run on the audited commit and on the patched one, so a test
that already failed is not blamed on the patch.

Do not enable this where the server itself runs in a container with the
Docker socket mounted: whoever controls that socket controls the host, and
the server would hold it.
"""

import json
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path

from analysis.secrets_scan import redact_line

MODE_ENV = "SECAUDIT_WHATIF_SANDBOX"
INSTALL_ENV = "SECAUDIT_SANDBOX_INSTALL"
DEFAULT_IMAGES = {"python": "python:3.12-slim", "node": "node:20-slim"}
OUTPUT_TAIL = 4000


class SandboxError(Exception):
    pass


def _int_env(name: str, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(os.environ.get(name, default))))
    except ValueError:
        return default


def docker_bin() -> str | None:
    return shutil.which("docker")


def enabled() -> bool:
    return os.environ.get(MODE_ENV, "").strip().lower() == "docker" and bool(docker_bin())


def status() -> dict:
    """Whether tests can run, and if not, why: for the result and the UI."""
    mode = os.environ.get(MODE_ENV, "").strip().lower()
    if mode != "docker":
        return {"available": False, "reason": "off"}
    if not docker_bin():
        return {"available": False, "reason": "no_docker"}
    return {"available": True, "install": install_enabled()}


def install_enabled() -> bool:
    return os.environ.get(INSTALL_ENV, "").strip() == "1"


def image_for(kind: str) -> str:
    return os.environ.get(f"SECAUDIT_SANDBOX_{kind.upper()}_IMAGE", DEFAULT_IMAGES[kind])


def detect(project: Path) -> dict | None:
    """Which test runner the repository uses, by its files. None if unknown."""
    pkg = project / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(errors="replace"))
        except ValueError:
            data = {}
        test = ((data.get("scripts") or {}).get("test") or "")
        if test and "no test specified" not in test:
            return {"kind": "node", "install": ["npm", "ci", "--ignore-scripts", "--no-audit",
                                                "--no-fund"]
                    if (project / "package-lock.json").is_file() else
                    ["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund"],
                    "test": ["npm", "test", "--silent"]}
    has_tests = any(project.glob("test_*.py")) or any(project.glob("tests/**/test_*.py")) or \
        any(project.glob("**/tests/test_*.py"))
    if has_tests:
        reqs = [f for f in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt")
                if (project / f).is_file()]
        install = ["python", "-m", "pip", "install", "--no-cache-dir", "--disable-pip-version-check",
                   "--target", "/work/.secaudit-deps", "pytest"]
        for r in reqs:
            install += ["-r", r]
        return {"kind": "python", "install": install,
                "test": ["python", "-m", "pytest", "-q", "-rA", "-p", "no:cacheprovider",
                         "--color=no"]}
    return None


def _copy(src: Path, dest: Path) -> None:
    shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    # The container runs as nobody: it needs to write caches in its copy.
    for root, dirs, files in os.walk(dest):
        for name in dirs + files:
            p = os.path.join(root, name)
            if not os.path.islink(p):
                os.chmod(p, 0o777 if os.path.isdir(p) else 0o666)
    os.chmod(dest, 0o777)


def _docker(work: Path, image: str, command: list[str], network: bool, timeout: int) -> dict:
    name = f"secaudit-sbx-{uuid.uuid4().hex[:12]}"
    memory = _int_env("SECAUDIT_SANDBOX_MEMORY_MB", 1024, 128, 8192)
    cpus = _int_env("SECAUDIT_SANDBOX_CPUS", 1, 1, 8)
    cmd = [docker_bin(), "run", "--rm", "--name", name, "--pull=never",
           "--network", "bridge" if network else "none",
           "--read-only", "--tmpfs", "/tmp:rw,nosuid,size=256m",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--pids-limit", "256", "--memory", f"{memory}m", "--memory-swap", f"{memory}m",
           "--cpus", str(cpus), "--user", "65534:65534",
           "-e", "HOME=/tmp", "-e", "PYTHONDONTWRITEBYTECODE=1",
           "-e", "PYTHONPATH=/work/.secaudit-deps", "-e", "npm_config_cache=/tmp/npm",
           "-e", "CI=1",
           "-v", f"{work}:/work:rw", "-w", "/work", image, *command]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                           env={"PATH": os.environ.get("PATH", ""),
                                "HOME": os.environ.get("HOME", "/tmp"),
                                **({"DOCKER_HOST": os.environ["DOCKER_HOST"]}
                                   if os.environ.get("DOCKER_HOST") else {})})
    except subprocess.TimeoutExpired:
        subprocess.run([docker_bin(), "kill", name], capture_output=True, timeout=30)
        return {"exit": None, "timed_out": True, "output": ""}
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode == 125 and re.search(r"No such image|Unable to find image|"
                                         r"pull access denied", out):
        raise SandboxError(f"image {image} is not on the host: docker pull {image}")
    tail = "\n".join(redact_line(line) for line in out[-OUTPUT_TAIL * 2:].splitlines())
    return {"exit": r.returncode, "timed_out": False, "output": tail[-OUTPUT_TAIL:]}


_PYTEST_LINE = re.compile(r"^(PASSED|FAILED|ERROR)\s+(\S+)")


def _results(kind: str, run: dict) -> dict:
    out = {"exit": run["exit"], "timed_out": run["timed_out"],
           "passed": run["exit"] == 0 and not run["timed_out"]}
    if kind == "python":
        per = {}
        for line in run["output"].splitlines():
            m = _PYTEST_LINE.match(line.strip())
            if m:
                per[m.group(2)] = m.group(1)
        out["tests"] = per
        m = re.search(r"(\d+) passed", run["output"])
        out["count_passed"] = int(m.group(1)) if m else 0
        m = re.search(r"(\d+) failed", run["output"])
        out["count_failed"] = int(m.group(1)) if m else 0
        if run["exit"] == 5:                  # pytest: no tests collected
            out["passed"] = None
    return out


def run_tests(before: Path, after: Path, scratch: Path) -> dict:
    """Run the repository's tests on the audited commit and on the patched one."""
    if not enabled():
        raise SandboxError("the sandbox is off")
    runner = detect(after)
    if runner is None:
        return {"run": False, "reason": "no_runner"}
    image = image_for(runner["kind"])
    timeout = _int_env("SECAUDIT_SANDBOX_TIMEOUT", 300, 30, 3600)
    result = {"run": True, "kind": runner["kind"], "image": image, "network_during_tests": False,
              "installed": False}
    runs = {}
    for label, src in (("before", before), ("after", after)):
        work = scratch / f"sbx-{label}"
        _copy(src, work)
        if install_enabled():
            inst = _docker(work, image, runner["install"], True, timeout)
            result["installed"] = inst["exit"] == 0
            if inst["exit"] != 0:
                result[f"install_{label}"] = {"exit": inst["exit"],
                                              "timed_out": inst["timed_out"],
                                              "output": inst["output"][-1500:]}
        run = _docker(work, image, runner["test"], False, timeout)
        runs[label] = run
        result[label] = _results(runner["kind"], run)
        result[f"{label}_output"] = run["output"]
    b, a = result["before"].get("tests") or {}, result["after"].get("tests") or {}
    result["broken_by_patch"] = sorted(t for t, s in a.items()
                                       if s != "PASSED" and b.get(t) == "PASSED")
    result["fixed_by_patch"] = sorted(t for t, s in a.items()
                                      if s == "PASSED" and b.get(t) in ("FAILED", "ERROR"))
    result["regressed"] = bool(result["broken_by_patch"]) or (
        result["before"]["passed"] is True and result["after"]["passed"] is False)
    return result
