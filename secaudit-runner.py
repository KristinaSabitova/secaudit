#!/usr/bin/env python3
"""Run a hosted instance's audits on this machine.

The `claude-code` backend authenticates a person on a machine, so the hosted
instance cannot use it. This polls that instance for audits queued against your
account, clones and audits each one here with your Claude subscription, and
posts the findings back. Nothing but the findings leaves this machine — the
subscription and the checked-out code stay local.

    export SECAUDIT_RUNNER_TOKEN=...          # from the dashboard
    ./secaudit-runner.py https://secaudit.example.com

It only works while this machine is awake and the script is running; audits
queued in the meantime are picked up on the next poll.
"""

import argparse
import json
import os
import signal
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from web.engine import AuditError, backend_config, run_audit_in_process
from web.gitclone import CloneError, clone_repo

POLL_SECONDS = 15
BACKOFF_MAX = 300
TOKEN_ENV = "SECAUDIT_RUNNER_TOKEN"

_stopping = False


def _stop(*_):
    global _stopping
    _stopping = True
    print("\n[*] finishing the current audit, then stopping…", file=sys.stderr)


def request(server: str, path: str, token: str, payload=None, timeout=60):
    """POST to the server; returns (status, parsed body or None)."""
    data = json.dumps(payload).encode() if payload is not None else b""
    req = urllib.request.Request(
        f"{server.rstrip('/')}{path}", data=data, method="POST",
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read()
            return response.status, (json.loads(body) if body else None)
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")
        return e.code, {"detail": detail}


def run_one(server: str, token: str, job: dict, timeout: int) -> None:
    audit_id = job["id"]
    print(f"[*] {audit_id}  {job['repo_url']}", file=sys.stderr)
    result = {"audit_id": audit_id}
    with tempfile.TemporaryDirectory(prefix="secaudit-runner-") as tmp:
        dest = Path(tmp) / "repo"
        try:
            result["commit_sha"] = clone_repo(job["repo_url"], dest,
                                              branch=job.get("branch"))
            config = backend_config({"backend": "claude-code"})
            result["findings"] = run_audit_in_process(dest, config, timeout)
        except (CloneError, AuditError) as e:
            result["error"] = str(e)
        except Exception as e:                       # never drop the audit
            result["error"] = f"runner error: {e}"

    status, body = request(server, "/api/runner/result", token, result)
    if status >= 400:
        print(f"[!] {audit_id}: server rejected the result ({status}): "
              f"{(body or {}).get('detail')}", file=sys.stderr)
    else:
        outcome = result.get("error") or f"{len(result.get('findings') or [])} findings"
        print(f"[+] {audit_id}: {outcome}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("server", help="e.g. https://secaudit.example.com")
    parser.add_argument("--once", action="store_true",
                        help="take at most one audit, then exit")
    parser.add_argument("--timeout", type=int,
                        default=int(os.environ.get("SECAUDIT_TIMEOUT", "1800")),
                        help="seconds allowed for a single audit")
    args = parser.parse_args()

    token = os.environ.get(TOKEN_ENV, "").strip()
    if not token:
        print(f"error: {TOKEN_ENV} is not set. Create a runner token in the "
              "dashboard under 'backend'.", file=sys.stderr)
        return 2

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    print(f"[*] polling {args.server} every {POLL_SECONDS}s — ctrl-c to stop",
          file=sys.stderr)
    backoff = POLL_SECONDS
    while not _stopping:
        status, body = request(args.server, "/api/runner/claim", token)
        if status == 401:
            print("error: the server rejected this runner token.", file=sys.stderr)
            return 1
        if status >= 400 or status == 0:
            print(f"[!] server returned {status}; retrying in {backoff}s",
                  file=sys.stderr)
            time.sleep(backoff)
            backoff = min(backoff * 2, BACKOFF_MAX)
            continue

        backoff = POLL_SECONDS
        if status == 204 or not body:
            if args.once:
                print("[=] nothing queued", file=sys.stderr)
                return 0
            time.sleep(POLL_SECONDS)
            continue

        run_one(args.server, token, body, args.timeout)
        if args.once:
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
