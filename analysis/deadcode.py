"""Code that looks unused: functions, files and routes nothing refers to (C23).

Dead code is attack surface nobody maintains: an old handler still served, a
helper with the bug fixed everywhere else. This lists what nothing in the
repository mentions:

- functions and classes defined at module level whose name appears nowhere
  but in their own definition (Python and JavaScript/TypeScript exports);
- source files whose module name no other file mentions, and that are not an
  entry point themselves;
- Flask blueprints created and never registered, so their routes are either
  dead or registered somewhere this repository does not show.

"Mentions" is a word count over every text file of the checkout, strings and
configuration included, so a name built at runtime (getattr, importlib,
plugin registries, entry points in another repository, reflection) is
missed: everything here is "apparently unused", a list to look at, never a
finding.
"""

import ast
import re
from collections import Counter
from pathlib import PurePosixPath

DEADCODE_VERSION = "1"
MAX_ITEMS = 200

_WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
_SKIP_DIR = re.compile(r"(?i)(^|/)(tests?|spec|__tests__|node_modules|vendor|dist|build|"
                       r"migrations|docs?|examples?|scripts?|\.github)/")
_ENTRY_FILES = {"__init__", "__main__", "main", "app", "manage", "wsgi", "asgi", "setup",
                "conftest", "index", "server", "cli", "settings", "config", "urls",
                "admin", "apps", "models", "views", "tasks", "celery", "gunicorn.conf",
                "vite.config", "webpack.config", "next.config", "jest.config",
                "tailwind.config", "postcss.config", "babel.config", "eslint.config",
                "middleware", "layout", "page", "route", "_app", "_document"}
_KEEP_NAMES = re.compile(r"^(main|setup|teardown|test_\w*|Test\w*|handler|lambda_handler|"
                         r"default|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|"
                         r"getServerSideProps|getStaticProps|getStaticPaths|generateMetadata|"
                         r"metadata|config|loader|action|middleware|_\w*)$")
_PY = (".py",)
_JS = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx")


def _counts(texts: dict[str, str]) -> Counter:
    words: Counter = Counter()
    for text in texts.values():
        words.update(_WORD.findall(text))
    return words


def _python_defs(rel: str, text: str) -> list[dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    exported = set()
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            exported |= {e.value for e in getattr(node.value, "elts", [])
                         if isinstance(e, ast.Constant)}
    out = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if node.decorator_list or node.name in exported or _KEEP_NAMES.match(node.name):
            continue                # routes, tools, fixtures, tasks: called by a framework
        out.append({"kind": "class" if isinstance(node, ast.ClassDef) else "function",
                    "name": node.name, "file": rel, "line": node.lineno})
    return out


_JS_EXPORT = re.compile(r"^export\s+(?:async\s+)?(?:function\*?|class|const|let)\s+"
                        r"([A-Za-z_$][\w$]*)", re.M)


def _js_defs(rel: str, text: str) -> list[dict]:
    out = []
    for m in _JS_EXPORT.finditer(text):
        if _KEEP_NAMES.match(m.group(1)):
            continue
        out.append({"kind": "export", "name": m.group(1), "file": rel,
                    "line": text.count("\n", 0, m.start()) + 1})
    return out


def analyze(texts: dict[str, str]) -> dict:
    words = _counts(texts)
    items: list[dict] = []
    files = sorted(r for r in texts if r.lower().endswith(_PY + _JS)
                   and not _SKIP_DIR.search(r) and not r.lower().endswith(".min.js")
                   and not re.search(r"(^|/)test_[^/]*\.py$|\.(test|spec)\.\w+$", r))
    for rel in files:
        text = texts[rel]
        defs = _python_defs(rel, text) if rel.lower().endswith(_PY) else _js_defs(rel, text)
        for d in defs:
            if words[d["name"]] <= 1:
                items.append({**d, "reason": "name_mentioned_once"})
        stem = PurePosixPath(rel).stem
        base = stem.split(".")[0]
        if base in _ENTRY_FILES or stem in _ENTRY_FILES:
            continue
        if re.search(r"""if\s+__name__\s*==\s*["']__main__["']""", text):
            continue
        if re.search(r"(^|/)(pages|app|routes|api)/", rel) and rel.lower().endswith(_JS):
            continue                # file-based routing: the file name is the route
        # The file's own name does not count: words come from the texts only.
        if words[stem] == 0 and words[base] == 0:
            items.append({"kind": "file", "name": stem, "file": rel, "line": 1,
                          "reason": "module_never_mentioned"})
    for rel in files:
        if not rel.lower().endswith(_PY):
            continue
        for m in re.finditer(r"^(\w+)\s*=\s*Blueprint\(", texts[rel], re.M):
            var = m.group(1)
            registered = any(re.search(rf"register_blueprint\(\s*(\w+\.)?{re.escape(var)}\b", t)
                             for t in texts.values())
            if not registered:
                items.append({"kind": "blueprint", "name": var, "file": rel,
                              "line": texts[rel].count("\n", 0, m.start()) + 1,
                              "reason": "blueprint_never_registered"})
    by_kind: dict[str, int] = {}
    for i in items:
        by_kind[i["kind"]] = by_kind.get(i["kind"], 0) + 1
    return {"version": DEADCODE_VERSION, "items": items[:MAX_ITEMS], "by_kind": by_kind,
            "files_read": len(files), "truncated": len(items) > MAX_ITEMS}
