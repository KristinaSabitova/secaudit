"""Every deterministic scanner over a checkout, in one process meant to be isolated.

The scanners parse text an attacker wrote: Python with ast, JSON, TOML, YAML
by pattern, long regular expressions over every file. A file crafted to
exhaust the parser (deep nesting, pathological backtracking, a huge literal)
should take down this process, not the web server. So the server runs this
module as a child (web/scanproc.py) with CPU, memory and file-size limits
and a timeout, an environment reduced to what it needs, and reads one JSON
document back.

Nothing here touches the network: OSV and registry lookups stay in the
server, behind their own opt-in settings.

    echo '{"project": "/path", "language": "es", "history": 200}' | \\
        python3 -m analysis.scan
"""

import json
import sys
from pathlib import Path

from . import deadcode, deps, doc_claims, mcp_audit, secrets_scan, surface, taint
from .parallax import repository_texts

SCAN_VERSION = "1"


def _safe(name: str, fn, errors: dict):
    try:
        return fn()
    except Exception as e:      # one scanner failing never hides the others
        errors[name] = f"{type(e).__name__}: {str(e)[:300]}"
        return None


def run(project: Path, language: str = "en", history: int = 200) -> dict:
    texts = repository_texts(project)
    errors: dict[str, str] = {}
    out: dict = {"version": SCAN_VERSION, "errors": errors,
                 "read": {"files": len(texts), "skipped": len(getattr(texts, "skipped", [])),
                          "truncated": bool(getattr(texts, "truncated", False))}}

    def secrets():
        found, summary = secrets_scan.scan(texts, language)
        return {"findings": found, "summary": summary,
                "timeline": secrets_scan.timeline(project, history)}

    def dependencies():
        inv = deps.inventory(texts)
        return {"inventory": inv,
                "signals": deps.signal_findings(inv["signals"], language, texts),
                "ghosts": deps.ghost_dependencies(inv["components"], texts, inv["manifests"]),
                # Manifest lines, for registry findings the server makes later.
                "manifest_texts": {m: texts[m] for m in inv["manifests"][:200]
                                   if len(texts.get(m, "")) < 2_000_000}}

    def taint_():
        result = taint.analyze(texts)
        result["findings"] = taint.to_findings(result.pop("raw"), language)
        result["limits"] = taint.LIMITS["es" if language == "es" else "en"]
        return result

    out["secrets"] = _safe("secrets", secrets, errors)
    out["dependencies"] = _safe("dependencies", dependencies, errors)
    out["mcp"] = _safe("mcp", lambda: mcp_audit.analyze(texts, language), errors)
    out["surface"] = _safe("surface", lambda: surface.analyze(texts), errors)
    out["taint"] = _safe("taint", taint_, errors)
    out["claims"] = _safe("claims", lambda: doc_claims.analyze(texts, language), errors)
    out["deadcode"] = _safe("deadcode", lambda: deadcode.analyze(texts), errors)
    return out


def main() -> int:
    request = json.load(sys.stdin)
    result = run(Path(request["project"]), request.get("language") or "en",
                 int(request.get("history") or 200))
    json.dump(result, sys.stdout, default=str)
    return 0


if __name__ == "__main__":
    sys.exit(main())
