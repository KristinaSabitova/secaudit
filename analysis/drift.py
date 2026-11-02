"""What changed since the last audit, and whether a control got weaker (B14, C24).

Two commits of the same repository — the one the previous audit read and
the one being audited — compared with git on the server's checkout (diff
drivers and text conversions off). Reported:

- the files changed between them, and among those the critical ones: what
  runs on its own (CI workflows, install scripts, hooks), what agents read,
  entry points and auth code — the risk tiers of analysis/chunking;
- security drift: lines added or removed that weaken a control. Auth checks
  removed, CORS opened to any origin, TLS verification turned off, debug
  turned on, CSRF exemptions, cookies losing Secure/HttpOnly, workflow
  permissions widened, pull_request_target introduced, input validation
  dropped. Each item says which commit range, file and line, and what the
  line says — a pattern on a diff, so a place to look, not a verdict.

When the previous commit is not in the fetched history (a force-push, or a
history longer than SECAUDIT_HISTORY_DEPTH), nothing is compared and the
result says so.
"""

import re
from pathlib import Path

from .chunking import AGENT_CONFIG, AUTH_SECRETS, AUTO_EXECUTION, ENTRY_POINT, classify_path
from .parallax import _git_run

DRIFT_VERSION = "1"
MAX_DIFF_CHARS = 20_000_000
MAX_ITEMS = 200

# (kind, rule, side, pattern): side "+" means the weakening is the added line,
# "-" means it is the removed one (a control that was there and is gone).
RULES = [
    ("auth", "auth_check_removed", "-", re.compile(
        r"(@login_required|@\w*auth\w*_required|@permission_required|@jwt_required|"
        r"Depends\(\s*(get_current|require|auth|verify)\w*|requireAuth|isAuthenticated|"
        r"ensureLoggedIn|@PreAuthorize|authorize\(|check_permission|has_perm)")),
    ("auth", "allow_any", "+", re.compile(
        r"(AllowAny|permitAll\(\)|@csrf_exempt|skip_before_action\s+:authenticate|"
        r"auth\s*[:=]\s*(False|false|None|null)|anonymous\s*[:=]\s*(True|true))")),
    ("cors", "cors_any_origin", "+", re.compile(
        r"""(allow_origins\s*=\s*\[\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|"""
        r"""origin\s*:\s*(["']\*["']|true)|CORS_ORIGIN_ALLOW_ALL\s*=\s*True|"""
        r"""CORS_ALLOW_ALL_ORIGINS\s*=\s*True|cors\(\s*\))""")),
    ("tls", "tls_verification_off", "+", re.compile(
        r"(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|"
        r"InsecureSkipVerify\s*:\s*true|CERT_NONE|check_hostname\s*=\s*False|--insecure\b|-k\s+https)")),
    ("debug", "debug_on", "+", re.compile(
        r"""(\bDEBUG\s*=\s*True\b|debug\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|"""
        r"""FLASK_DEBUG\s*=\s*1|NODE_ENV\s*[:=]\s*["']?development|"""
        r"""showStackTrace\s*:\s*true|DEBUG_PROPAGATE_EXCEPTIONS)""")),
    ("cookies", "cookie_flags_off", "+", re.compile(
        r"(?i)(secure\s*[:=]\s*(False|false)|httponly\s*[:=]\s*(False|false)|"
        r"samesite\s*[:=]\s*['\"]?none|SESSION_COOKIE_SECURE\s*=\s*False|"
        r"CSRF_COOKIE_SECURE\s*=\s*False)")),
    ("csrf", "csrf_off", "+", re.compile(
        r"(?i)(csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*[:=]\s*false|"
        r"protect_from_forgery\s+except|disable\(\)\s*\.csrf|csrf\(\)\.disable)")),
    ("permissions", "workflow_permissions_widened", "+", re.compile(
        r"^\s*(permissions:\s*write-all|contents:\s*write|id-token:\s*write|"
        r"pull-requests:\s*write|actions:\s*write|packages:\s*write)")),
    ("permissions", "pull_request_target", "+", re.compile(r"\bpull_request_target\b")),
    ("permissions", "file_mode_open", "+", re.compile(r"\b(chmod\s+(-R\s+)?777|0o?777\b)")),
    ("validation", "validation_removed", "-", re.compile(
        r"(validate\w*\(|sanitiz\w*\(|escape\(|bleach\.clean|schema\.(load|validate)|"
        r"\.parse\(|zod|Joi\.|pydantic|secure_filename|is_relative_to|realpath)")),
    ("secrets", "secret_scanning_bypass", "+", re.compile(
        r"(#\s*nosec|//\s*nosemgrep|#\s*nosemgrep|gitleaks:allow|detect-secrets:\s*allowlist)")),
]

LABELS = {
    "auth_check_removed": ("an authentication or authorization check was removed",
                           "se quitó una comprobación de autenticación o autorización"),
    "allow_any": ("access opened to anyone", "acceso abierto a cualquiera"),
    "cors_any_origin": ("CORS opened to any origin", "CORS abierto a cualquier origen"),
    "tls_verification_off": ("TLS verification turned off", "verificación TLS desactivada"),
    "debug_on": ("debug mode turned on", "modo depuración activado"),
    "cookie_flags_off": ("cookie protection flags turned off",
                         "desactivadas protecciones de las cookies"),
    "csrf_off": ("CSRF protection turned off", "protección CSRF desactivada"),
    "workflow_permissions_widened": ("workflow permissions widened",
                                     "permisos del workflow ampliados"),
    "pull_request_target": ("pull_request_target introduced: runs with secrets on forks' PRs",
                            "pull_request_target añadido: ejecuta con secretos en PRs de forks"),
    "file_mode_open": ("files made world-writable", "ficheros con permisos para todos"),
    "validation_removed": ("input validation removed", "validación de entrada eliminada"),
    "secret_scanning_bypass": ("a scanner suppression was added",
                               "se añadió una supresión del escáner"),
}

CRITICAL_TIERS = {AUTO_EXECUTION, AGENT_CONFIG, ENTRY_POINT, AUTH_SECRETS}


def _has_commit(project: Path, sha: str) -> bool:
    r = _git_run(project, "cat-file", "-e", f"{sha}^{{commit}}")
    return r.returncode == 0


def changed_files(project: Path, base: str, head: str = "HEAD") -> list[dict]:
    r = _git_run(project, "diff", "--name-status", "--no-renames", "--no-ext-diff",
                 "--no-textconv", base, head)
    if r.returncode != 0:
        return []
    out = []
    for line in r.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0][:1], parts[-1]
        tier, label = classify_path(path)
        out.append({"file": path, "status": status, "risk_tier": tier,
                    "critical": tier in CRITICAL_TIERS
                    or path.startswith(".github/workflows/")})
    return out


def drift(project: Path, base: str, head: str = "HEAD", language: str = "en") -> list[dict]:
    r = _git_run(project, "diff", "-U0", "--no-color", "--no-ext-diff", "--no-textconv",
                 "--no-renames", base, head)
    if r.returncode != 0:
        return []
    text = r.stdout[:MAX_DIFF_CHARS]
    es = language == "es"
    items, file, new_line = [], None, 0
    added = _added_by_file(text)
    for raw in text.split("\n"):
        if raw.startswith("+++ "):
            file = raw[6:] if raw.startswith("+++ b/") else None
            continue
        if raw.startswith("--- "):
            if raw.startswith("--- a/") and file is None:
                file = raw[6:]
            continue
        if raw.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", raw)
            new_line = int(m.group(1)) if m else 0
            continue
        if not raw or raw[0] not in "+-" or file is None or len(raw) > 2000:
            continue
        side, body = raw[0], raw[1:]
        for kind, rule, want, pattern in RULES:
            if want != side or not pattern.search(body):
                continue
            # A removed control that comes back on an added line in the same
            # file was moved, not removed.
            if side == "-" and pattern.search(body).group(0) in added.get(file, ""):
                continue
            items.append({"kind": kind, "rule": rule, "file": file,
                          "line": new_line if side == "+" else None,
                          "side": "added" if side == "+" else "removed",
                          "text": _clip(body.strip()),
                          "label": LABELS[rule][1 if es else 0]})
            break
        if side == "+":
            new_line += 1
        if len(items) >= MAX_ITEMS:
            break
    return items


def _added_by_file(diff: str) -> dict[str, str]:
    """Every added line of the diff, per file, to tell a move from a removal."""
    out: dict[str, list[str]] = {}
    file = None
    for raw in diff.split("\n"):
        if raw.startswith("+++ "):
            file = raw[6:] if raw.startswith("+++ b/") else None
        elif raw.startswith("+") and file:
            out.setdefault(file, []).append(raw[1:])
    return {f: "\n".join(lines) for f, lines in out.items()}


def _clip(text: str, limit: int = 300) -> str:
    from .secrets_scan import redact_line
    text = redact_line(text)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def compare(project: Path, base: str | None, language: str = "en") -> dict:
    """Changed files and drift between base and the checkout's HEAD."""
    if not base:
        return {"compared": False, "reason": "no previous audited commit", "base": None}
    if not _has_commit(project, base):
        return {"compared": False, "base": base,
                "reason": ("el commit anterior no está en el historial descargado "
                           "(force-push o historial más largo que SECAUDIT_HISTORY_DEPTH)"
                           if language == "es" else
                           "the previous commit is not in the fetched history "
                           "(a force-push, or more history than SECAUDIT_HISTORY_DEPTH)")}
    files = changed_files(project, base)
    items = drift(project, base, language=language)
    by_kind: dict[str, int] = {}
    for d in items:
        by_kind[d["kind"]] = by_kind.get(d["kind"], 0) + 1
    return {"compared": True, "base": base, "version": DRIFT_VERSION,
            "files": files[:500], "files_changed": len(files),
            "critical_changed": [f for f in files if f["critical"]][:100],
            "workflows_changed": [f["file"] for f in files
                                  if f["file"].startswith(".github/workflows/")],
            "drift": items, "drift_by_kind": by_kind}


def finding_diff(previous: list[dict], current: list[dict],
                 fixed_before: set[str] | None = None) -> dict:
    """New, fixed, persisting and reintroduced findings, by fingerprint.

    previous and current are finding dicts with a fingerprint; fixed_before
    holds fingerprints of findings fixed in any earlier audit of the project.
    """
    fixed_before = fixed_before or set()
    prev = {f["fingerprint"]: f for f in previous if f.get("fingerprint")}
    cur = {f["fingerprint"]: f for f in current if f.get("fingerprint")}
    out = {"new": [], "persisting": [], "fixed": [], "reintroduced": []}
    for fp, f in cur.items():
        if fp in prev:
            out["persisting"].append(f)
        elif fp in fixed_before or f.get("zombie_of"):
            out["reintroduced"].append(f)
        else:
            out["new"].append(f)
    out["fixed"] = [f for fp, f in prev.items() if fp not in cur]
    return out
