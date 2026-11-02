"""Where outside input enters, and what it can reach (C27, B21).

An inventory of the attack surface read from the code, never by running it:
HTTP endpoints (Flask, FastAPI, Django, Express-style routers), webhooks,
file upload handlers, CLI entry points, scheduled jobs and MCP tools. For
each entry: the file and line, method and path when stated, whether an
authentication marker is visible on it, and what it touches — database,
filesystem, network, subprocess.

The trust boundaries are drawn from that: untrusted input crosses into the
application at each entry, and from there into each kind of asset it
touches. "auth: none_seen" means no decorator, dependency or middleware
marker was seen on that handler or in its file — the check may live in a
gateway, a parent router or a middleware registered elsewhere, so it is a
place to look, never a finding by itself.

Python is read with ast; JavaScript and TypeScript by pattern, with lower
confidence. Other languages are not inventoried, and the result says so.
"""

import ast
import re
from pathlib import PurePosixPath

SURFACE_VERSION = "1"
MAX_ITEMS = 400

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "route",
                "api_route", "websocket", "add_url_rule"}
_AUTH_DECORATORS = re.compile(
    r"(?i)(login_required|auth|jwt_required|permission|requires?_|roles?_required|"
    r"admin_required|authenticated|protected|verify|token|security|scope)")
_AUTH_DEP = re.compile(r"(?i)Depends\(\s*(get_current|current_|require|auth|verify|"
                       r"oauth2|api_key|security)")
_PUBLIC_HINT = re.compile(r"(?i)(webhook|callback|hook|public|health|login|signup|register)")

_TOUCH = {
    "database": re.compile(r"\b(execute|executemany|raw|cursor|session\.(query|execute|add)|"
                           r"\.objects\.|select\(|insert\(|query\(|findOne|findMany|"
                           r"prisma\.|knex|sequelize|mongoose|\.find\(|\.aggregate\()"),
    "filesystem": re.compile(r"\b(open\(|read_text|write_text|read_bytes|send_file|"
                             r"FileResponse|os\.remove|unlink|shutil\.|readFile|writeFile|"
                             r"createReadStream|fs\.)"),
    "network": re.compile(r"\b(requests\.|httpx\.|urlopen|aiohttp|fetch\(|axios|got\(|"
                          r"http\.request|https\.get)"),
    "subprocess": re.compile(r"\b(subprocess\.|os\.system|os\.popen|child_process|exec\(|"
                             r"execSync|spawn\()"),
    "deserialization": re.compile(r"\b(pickle\.loads?|yaml\.load\(|marshal\.loads|"
                                  r"unserialize|jsonpickle)"),
    "template": re.compile(r"\b(render_template_string|Markup\(|mark_safe|"
                           r"dangerouslySetInnerHTML|innerHTML|v-html)"),
}
_UPLOAD = re.compile(r"\b(request\.files|UploadFile|multer|formidable|busboy|"
                     r"FileStorage|request\.FILES)")
_SCHEDULE = re.compile(r"\b(@(app\.)?(task|periodic_task|scheduled_job|cron)|"
                       r"schedule\.every|BackgroundScheduler|celery|cron\.schedule)")


def _touches(src: str) -> list[str]:
    return sorted(k for k, rx in _TOUCH.items() if rx.search(src))


def _const(node):
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _python(rel: str, text: str) -> list[dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    lines = text.splitlines()
    file_auth = bool(re.search(r"(?i)(login_manager|before_request|middleware|"
                               r"HTTPBearer|OAuth2PasswordBearer|APIKeyHeader)", text))
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        src = "\n".join(lines[node.lineno - 1:getattr(node, "end_lineno", node.lineno)])
        decos = [ast.unparse(d) if hasattr(ast, "unparse") else "" for d in node.decorator_list]
        for dec in node.decorator_list:
            call = dec if isinstance(dec, ast.Call) else None
            target = dec.func if call else dec
            attr = target.attr if isinstance(target, ast.Attribute) else None
            if attr in ("tool", "resource", "prompt") and call is not None:
                out.append({"kind": "mcp_tool", "file": rel, "line": node.lineno,
                            "name": node.name, "method": None, "path": None,
                            "auth": "unknown", "touches": _touches(src), "confidence": "high"})
                break
            if attr not in HTTP_METHODS:
                continue
            path = _const(call.args[0]) if call and call.args else None
            methods = [attr.upper()] if attr not in ("route", "api_route", "add_url_rule") else []
            for kw in (call.keywords if call else []):
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
                    methods = [str(_const(e)).upper() for e in kw.value.elts if _const(e)]
            auth_seen = any(_AUTH_DECORATORS.search(d) for d in decos if d != ast.unparse(dec)) \
                or bool(_AUTH_DEP.search(ast.unparse(node.args))) \
                or any(_AUTH_DEP.search(ast.unparse(k.value)) for k in (call.keywords if call else [])
                       if k.arg == "dependencies")
            kind = "webhook" if path and re.search(r"(?i)webhook|hook|callback", path) else \
                "file_upload" if _UPLOAD.search(src) else \
                "websocket" if attr == "websocket" else "endpoint"
            out.append({"kind": kind, "file": rel, "line": node.lineno, "name": node.name,
                        "method": ",".join(methods) or None, "path": path,
                        "auth": "declared" if auth_seen else
                        "file_level" if file_auth else "none_seen",
                        "touches": _touches(src), "confidence": "high"})
            break
        else:
            if _SCHEDULE.search("\n".join(decos)):
                out.append({"kind": "scheduled", "file": rel, "line": node.lineno,
                            "name": node.name, "method": None, "path": None,
                            "auth": "not_applicable", "touches": _touches(src),
                            "confidence": "medium"})
    # Django URLconfs.
    for m in re.finditer(r"""\b(re_)?path\(\s*r?["']([^"']*)["']\s*,\s*([\w.]+)""", text):
        line = text.count("\n", 0, m.start()) + 1
        out.append({"kind": "endpoint", "file": rel, "line": line, "name": m.group(3),
                    "method": None, "path": "/" + m.group(2), "auth": "unknown",
                    "touches": [], "confidence": "medium"})
    if re.search(r"""if\s+__name__\s*==\s*["']__main__["']""", text) and \
            re.search(r"\b(argparse|click|typer|sys\.argv|fire\.Fire)\b", text):
        out.append({"kind": "cli", "file": rel, "line": next(
            (i for i, l in enumerate(lines, 1) if "__main__" in l), 1), "name": PurePosixPath(rel).stem,
            "method": None, "path": None, "auth": "not_applicable",
            "touches": _touches(text), "confidence": "medium"})
    return out


_JS_ROUTE = re.compile(
    r"""\b(app|router|server|api|fastify|route[r]?s?)\.(get|post|put|patch|delete|all|use)\(\s*"""
    r"""(["'`])([^"'`]{0,200})\3\s*,([^\n]{0,300})""")


def _javascript(rel: str, text: str) -> list[dict]:
    out = []
    file_auth = bool(re.search(r"(?i)(passport\.|express-jwt|requireAuth|authenticate|"
                               r"jwt\.verify|clerkMiddleware|getServerSession|isAuthenticated)", text))
    for m in _JS_ROUTE.finditer(text):
        method, path, rest = m.group(2), m.group(4), m.group(5)
        if method == "use" and not path.startswith("/"):
            continue
        line = text.count("\n", 0, m.start()) + 1
        window = text[m.start():m.start() + 1500]
        auth_seen = bool(re.search(r"(?i)\b(auth|authenticate|requireAuth|isAuthenticated|"
                                   r"verifyToken|jwt|protect|ensureLoggedIn|checkRole)\w*\b", rest))
        kind = "webhook" if re.search(r"(?i)webhook|hook|callback", path) else \
            "file_upload" if _UPLOAD.search(window) else "endpoint"
        out.append({"kind": kind, "file": rel, "line": line, "name": None,
                    "method": method.upper() if method not in ("all", "use") else method,
                    "path": path, "auth": "declared" if auth_seen else
                    "file_level" if file_auth else "none_seen",
                    "touches": _touches(window), "confidence": "medium"})
    # Next.js / file-based API routes.
    if re.search(r"(^|/)(pages/api|app/api)/", rel) and \
            re.search(r"export\s+(default\s+)?(async\s+)?function|export\s+const\s+(GET|POST|PUT|DELETE)", text):
        route = "/" + re.sub(r"(^|.*/)(pages|app)/", "", rel).rsplit(".", 1)[0]
        out.append({"kind": "endpoint", "file": rel, "line": 1, "name": None, "method": None,
                    "path": re.sub(r"/(route|index)$", "", route),
                    "auth": "file_level" if file_auth else "none_seen",
                    "touches": _touches(text), "confidence": "medium"})
    return out


def analyze(texts: dict[str, str]) -> dict:
    items, languages, skipped = [], set(), set()
    for rel in sorted(texts):
        low = rel.lower()
        if re.search(r"(?i)(^|/)(tests?|spec|__tests__|node_modules|dist|build)/", rel):
            continue
        if low.endswith(".py"):
            languages.add("python")
            items += _python(rel, texts[rel])
        elif low.endswith((".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")):
            languages.add("javascript")
            items += _javascript(rel, texts[rel])
        elif low.endswith((".go", ".java", ".rb", ".php", ".cs", ".rs", ".kt", ".scala")):
            skipped.add(low.rsplit(".", 1)[1])
    items = items[:MAX_ITEMS]
    boundaries = {}
    for it in items:
        if it["kind"] in ("cli", "scheduled"):
            continue
        for asset in it["touches"] or ["application"]:
            key = (it["kind"], asset)
            b = boundaries.setdefault(key, {"from": "untrusted_input", "via": it["kind"],
                                            "to": asset, "entries": 0, "auth_none_seen": 0})
            b["entries"] += 1
            b["auth_none_seen"] += it["auth"] == "none_seen"
    by_kind: dict[str, int] = {}
    for it in items:
        by_kind[it["kind"]] = by_kind.get(it["kind"], 0) + 1
    return {"version": SURFACE_VERSION, "items": items, "by_kind": by_kind,
            "boundaries": sorted(boundaries.values(), key=lambda b: (-b["auth_none_seen"],
                                                                     -b["entries"])),
            "languages": sorted(languages),
            "not_inventoried": sorted(skipped),
            "unauthenticated_seen": sum(1 for i in items if i["auth"] == "none_seen"
                                        and not _PUBLIC_HINT.search(i.get("path") or ""))}
