"""Run one audit in its own process.

Credentials belong to the user who asked for the audit, and the engine reads
them from environment variables. A process per audit is what keeps one user's
key from leaking into another user's concurrent audit — os.environ is global to
the process, so an in-process approach could not isolate them. It also bounds a
runaway audit and keeps an engine crash out of the web server.

Invoked as `python -m web.runner`: reads {"project", "config", "timeout"} as
JSON on stdin and writes {"findings"} or {"error"} as JSON on stdout.
"""

import json
import sys
from pathlib import Path


def main() -> int:
    request = json.load(sys.stdin)
    # Imported here so a malformed request fails before the engine is loaded.
    from .engine import AuditError, run_audit_in_process

    try:
        findings = run_audit_in_process(
            Path(request["project"]),
            request.get("config") or {},
            int(request.get("timeout") or 3600),
        )
    except AuditError as e:
        json.dump({"error": str(e)}, sys.stdout)
        return 1
    except Exception as e:  # never let a traceback masquerade as findings
        json.dump({"error": f"internal error: {e}"}, sys.stdout)
        return 1

    json.dump({"findings": findings}, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
