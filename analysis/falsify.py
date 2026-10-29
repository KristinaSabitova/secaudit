"""Module 2, falsifiability: a finding is a hypothesis, and secaudit tries to
refute it.

The model states each finding as a flow: where attacker-controlled input
enters (source), the dangerous use it reaches (sink), the functions between
(path) and what must hold for it to happen (preconditions). Here that claim is
attacked with what can be checked without the model, on the audited checkout,
by reading it — the code is parsed with ast, never imported or run:

  callgraph     is there any chain of calls or references from source to sink?
  sanitizer     is what reaches the sink only literals, parameterised, or
                passed through a function that makes it safe?
  reachability  can the sink's function be reached from a real entry point?

A fourth attempt, the devil's advocate, is a second model call told to prove
the finding false by quoting code. It runs where the audit runs (it needs the
user's key); its quotes are checked here, like any other evidence, and a
refutation whose quotes are not in the repository does not count.

The flow analysis covers Python only. A finding anywhere else can be refuted
by the devil's advocate, but never rises above "exists", and says why.

The call graph is built from names, not types: a call to `run` links to every
function called run. That over-approximates on purpose. "No chain at all" in
an over-approximation is strong evidence; a chain found is only a chain that
may exist, which is why surviving it is not the same as being proved.
"""

import ast
import re
from collections import Counter, deque
from dataclasses import dataclass, field
from pathlib import Path

from .chunking import SKIP_DIRS, read_text
from .evidence import _read_in, locate

EXISTS = "exists"
REACHABLE = "reachable"
CORROBORATED = "corroborated"
REFUTED = "refuted"
INCONCLUSIVE = "inconclusive"

SURVIVED = "survived"

CALLGRAPH = "callgraph"
SANITIZER = "sanitizer"
REACHABILITY = "reachability"
DEVIL = "devil_advocate"
METHODS = (CALLGRAPH, SANITIZER, REACHABILITY, DEVIL)

MAX_FILE_CHARS = 400_000         # a file bigger than this is not parsed
MAX_FIELD_CHARS = 500
MAX_PATH_STEPS = 12

PYTHON_ONLY = ("flow analysis covers Python only; {file} can be refuted but "
               "not shown reachable, so it stays at exists")
# Kinds of finding that are a flow from an input to a use, so that code
# nothing can run cannot carry them. A committed secret in dead code is still
# committed, and is not one of them.
FLOW_CATEGORIES = {"injection", "xss", "file_handling", "authz", "sessions",
                   "csrf", "client_security"}
INCOMPLETE = "no complete hypothesis (source and sink) was given, so there was nothing to refute"


# ---------------------------------------------------------------------------
# The hypothesis as the model gave it
# ---------------------------------------------------------------------------

def _text(value) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:MAX_FIELD_CHARS]


def normalize_hypothesis(raw) -> dict | None:
    """The hypothesis of a raw finding, in a fixed shape, or None.

    Complete means it names both a source and a sink: without them there is
    no flow to refute and the finding stays at exists.
    """
    if not isinstance(raw, dict):
        return None
    steps = raw.get("path") if isinstance(raw.get("path"), list) else []
    pre = raw.get("preconditions") if isinstance(raw.get("preconditions"), list) else []
    hypothesis = {
        "source": _text(raw.get("source")),
        "sink": _text(raw.get("sink")),
        "path": [_text(s) for s in steps if _text(s)][:MAX_PATH_STEPS],
        "preconditions": [_text(p) for p in pre if _text(p)][:MAX_PATH_STEPS],
    }
    if not any(hypothesis.values()):
        return None
    hypothesis["complete"] = bool(hypothesis["source"] and hypothesis["sink"])
    return hypothesis


# ---------------------------------------------------------------------------
# What the checkout's Python looks like
# ---------------------------------------------------------------------------

# The last name of a decorator that puts a function behind a door someone
# outside can knock on: web routes, CLI commands, task queues, signal and
# event handlers, MCP tools.
ENTRY_DECORATORS = {
    "route", "get", "post", "put", "patch", "delete", "head", "options",
    "websocket", "api_route", "api_view", "action", "view_config", "command",
    "group", "task", "shared_task", "receiver", "on_event", "on", "event",
    "listener", "callback", "tool", "resource", "prompt", "handler",
    "message_handler", "subscribe", "consumer", "endpoint", "rpc",
}
# Methods of a class-based view that a framework dispatches requests to.
VIEW_METHODS = {"get", "post", "put", "patch", "delete", "head", "options",
                "dispatch", "handle", "on_get", "on_post", "on_put",
                "on_delete", "list", "create", "retrieve", "update",
                "partial_update", "destroy", "perform_create"}
VIEW_BASES = re.compile(r"(View|ViewSet|Resource|Handler|Endpoint|Consumer)$")
# Module-level calls that register a function as a handler.
REGISTRARS = {"path", "re_path", "url", "add_url_rule", "add_api_route",
              "add_route", "register", "add_command", "connect", "add_handler",
              "add_resource", "route"}


@dataclass
class Function:
    qualname: str
    name: str
    file: str
    line: int
    end: int
    node: ast.AST
    refs: set = field(default_factory=set)
    entry: str | None = None          # why it is an entry point, if it is

    def where(self) -> str:
        return f"{self.file}:{self.qualname}"


def _last_name(node) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _refs(node) -> set:
    """Every name a piece of code mentions: called, passed or looked up."""
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.add(n.id)
        elif isinstance(n, ast.Attribute):
            out.add(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) \
                and n.value.isidentifier():
            out.add(n.value)          # getattr(obj, "handler") dispatch
    return out


def _is_main_guard(node) -> bool:
    return (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
            and isinstance(node.test.left, ast.Name)
            and node.test.left.id == "__name__")


_MENTION = re.compile(
    r"[\w./-]+\.py\s*[:#]\s*([A-Za-z_][\w.]*)"
    r"|\b(?:in|inside|function|method|handler|view|from)\s+`?([A-Za-z_][\w.]*)")


def named_functions(text: str) -> list[str]:
    """Function names a hypothesis field mentions explicitly, in order."""
    names = []
    for m in _MENTION.finditer(text or ""):
        dotted = (m.group(1) or m.group(2)).rstrip(".")
        names.append(dotted.split(".")[-1])
    return names


class Index:
    """The functions of every Python file in the checkout, and their links."""

    def __init__(self, project: Path):
        self.project = Path(project)
        self.functions: list[Function] = []
        self.by_name: dict[str, list[Function]] = {}
        self.modules: dict[str, ast.Module] = {}
        self.mentions: Counter = Counter()      # name -> times referenced
        self.entry_names: set = set()           # registered at module level
        for path in sorted(self.project.rglob("*.py")):
            rel = path.relative_to(self.project)
            if any(part in SKIP_DIRS for part in rel.parts[:-1]) or path.is_symlink():
                continue
            text = read_text(path)
            if text is None or len(text) > MAX_FILE_CHARS:
                continue
            try:
                tree = ast.parse(text)
            except (SyntaxError, ValueError):
                continue
            self.modules[rel.as_posix()] = tree
            self._collect(rel.as_posix(), tree)
        for fn in self.functions:
            self.by_name.setdefault(fn.name, []).append(fn)
            if fn.entry is None and fn.name in self.entry_names:
                fn.entry = "registered as a handler at module level"

    def _collect(self, file: str, tree: ast.Module) -> None:
        def visit(node, stack, view_class):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    fn = Function(".".join(stack + [child.name]), child.name, file,
                                  child.lineno, child.end_lineno or child.lineno, child)
                    fn.refs = _refs(child) - {child.name}
                    for dec in child.decorator_list:
                        self.mentions.update(_refs(dec))
                        if _last_name(dec) in ENTRY_DECORATORS:
                            fn.entry = f"decorated @{ast.unparse(dec)[:80]}"
                    if view_class and child.name in VIEW_METHODS:
                        fn.entry = f"a request method of {view_class}"
                    self.mentions.update(fn.refs)
                    self.functions.append(fn)
                    visit(child, stack + [child.name], None)
                elif isinstance(child, ast.ClassDef):
                    bases = [ast.unparse(b) for b in child.bases]
                    is_view = any(VIEW_BASES.search(b) for b in bases)
                    self.mentions.update(_refs(ast.Module(body=child.bases,
                                                          type_ignores=[])))
                    visit(child, stack + [child.name], child.name if is_view else None)
                elif not stack:
                    self._module_level(child)
                else:
                    visit(child, stack, view_class)
        visit(tree, [], None)

    def _module_level(self, node) -> None:
        """Code that runs on import or as a script: its calls are entries."""
        self.mentions.update(_refs(node))
        for n in ast.walk(node):
            if not isinstance(n, ast.Call):
                continue
            callee = _last_name(n)
            if _is_main_guard(node) or callee in REGISTRARS:
                for arg in list(n.args) + [k.value for k in n.keywords]:
                    name = _last_name(arg)
                    if name:
                        self.entry_names.add(name)
            if callee and _is_main_guard(node):
                self.entry_names.add(callee)

    # -- lookups ------------------------------------------------------------

    def function_at(self, file: str, line: int | None) -> Function | None:
        """The innermost function of file that contains line."""
        if not line:
            return None
        inside = [f for f in self.functions
                  if f.file == file and f.line <= line <= f.end]
        return max(inside, key=lambda f: f.line, default=None)

    def resolve(self, text: str, near: str | None = None) -> Function | None:
        """The function a piece of hypothesis prose names, if it names one.

        Only explicit mentions count — "app/views.py:search" or "in search" —
        never any identifier in the text: "request.args.get" must not resolve
        to a view method that happens to be called get.
        """
        for name in reversed(named_functions(text)):
            candidates = self.by_name.get(name)
            if not candidates:
                continue
            files = set(re.findall(r"[\w./-]+\.py", text))
            for pick in ([c for c in candidates if c.file in files],
                         [c for c in candidates if c.file == near]):
                if pick:
                    return pick[0]
            return candidates[0]
        return None

    def callees(self, fn: Function) -> list[Function]:
        out = []
        for name in fn.refs:
            out.extend(self.by_name.get(name, []))
        return out

    def chain(self, start: Function, goal: Function) -> list[Function] | None:
        """The shortest chain of references from start to goal, or None."""
        seen = {id(start)}
        queue = deque([[start]])
        while queue:
            path = queue.popleft()
            if path[-1] is goal:
                return path
            for nxt in self.callees(path[-1]):
                if id(nxt) not in seen:
                    seen.add(id(nxt))
                    queue.append(path + [nxt])
        return None

    def entries(self) -> list[Function]:
        return [f for f in self.functions if f.entry]

    def from_entry(self, goal: Function) -> list[Function] | None:
        """The shortest chain from any entry point to goal, or None."""
        best = None
        for entry in self.entries():
            path = self.chain(entry, goal)
            if path and (best is None or len(path) < len(best)):
                best = path
        return best


# ---------------------------------------------------------------------------
# Refutation 1: call graph
# ---------------------------------------------------------------------------

def _steps(path: list[Function]) -> list[str]:
    return [f.where() for f in path]


def try_callgraph(index: Index, hypothesis: dict, sink: Function) -> dict:
    source = index.resolve(hypothesis["source"], near=sink.file)
    if source is None:
        # Input read inside the sink's own function names no other function.
        if not named_functions(hypothesis["source"]):
            source = sink
        else:
            return {"result": INCONCLUSIVE,
                    "note": "the source names no function found in the checkout"}
    path = index.chain(source, sink)
    if path:
        return {"result": SURVIVED, "evidence": {"chain": _steps(path)},
                "note": "a chain of calls links the source to the sink"}
    # Two doors of their own: one request leaves state (a session, a row)
    # that another reads, so no call joins them and none is expected to.
    if source.entry and sink.entry:
        return {"result": INCONCLUSIVE,
                "evidence": {"source": source.where(), "sink": sink.where()},
                "note": f"{source.where()} and {sink.where()} are separate entry "
                        f"points: what links them is stored state, not a call"}
    return {"result": REFUTED, "evidence": {"source": source.where(), "sink": sink.where()},
            "note": f"nothing in {source.where()} calls or refers to anything "
                    f"that leads to {sink.where()}"}


# ---------------------------------------------------------------------------
# Refutation 2: what reaches the sink
# ---------------------------------------------------------------------------

# Calls the sink is likely to be, when the hypothesis does not say which.
DANGEROUS = {"execute", "executemany", "executescript", "raw", "extra",
             "system", "popen", "Popen", "run", "call", "check_call",
             "check_output", "spawn", "eval", "exec", "compile", "loads",
             "load", "render_template_string", "Markup", "mark_safe",
             "open", "send_file", "send_from_directory", "redirect",
             "urlopen", "get", "post", "request", "Template", "from_string",
             "text", "write", "unlink", "remove", "rmtree"}
QUERY_CALLS = {"execute", "executemany", "raw", "text"}
# The objects a web framework hands the incoming request in.
INPUT_OBJECTS = {"request", "req"}
# A value passed through one of these comes out unable to carry the attack.
GENERIC_SANITIZERS = {"int", "float", "bool", "UUID", "abs", "len", "ord",
                      "hex", "Decimal", "date", "fromisoformat", "strptime"}
SANITIZERS = {
    "injection": {"quote", "escape_string", "Identifier", "Literal",
                  "quote_ident", "escape_identifier", "quote_plus"},
    "xss": {"escape", "clean", "escape_html", "quote", "sanitize", "striptags",
            "conditional_escape", "format_html"},
    "client_security": {"escape", "clean", "escape_html", "sanitize"},
    "file_handling": {"secure_filename", "basename", "safe_join"},
}
PASS_THROUGH = {"str", "repr", "format", "bytes"}
STR_METHODS = {"format", "join", "replace", "strip", "lstrip", "rstrip",
               "lower", "upper", "title", "encode", "decode", "format_map"}

CONSTANT, SANITIZED, TAINTED = "constant", "sanitized", "tainted"
_ORDER = {CONSTANT: 0, SANITIZED: 1, TAINTED: 2}


# How many calls up a parameter is followed to the arguments it is given.
MAX_CALLER_DEPTH = 2


class _Values:
    """Where a value inside one function comes from, as far as ast shows.

    A parameter is followed up to the places the function is called from, so
    a value cast by the caller is seen as cast: what reaches the sink is the
    worst of what every call site passes. A function nobody calls in the
    checkout, or one a framework calls (an entry point), gets its parameters
    from outside, and they are taken as attacker-controlled.
    """

    def __init__(self, fn: Function, module: ast.Module | None, category: str,
                 index: "Index | None" = None, depth: int = 0, used=None):
        self.fn = fn
        self.category = category
        self.index = index
        self.depth = depth
        self.sanitizers = GENERIC_SANITIZERS | SANITIZERS.get(category, set())
        self.params = {a.arg for a in ast.walk(fn.node.args) if isinstance(a, ast.arg)}
        self.local = self._assignments(fn.node)
        self.module = self._assignments(module, top_only=True) if module else {}
        self.used: list[str] = used if used is not None else []

    def _from_callers(self, param: str) -> str:
        fn = self.fn
        if self.index is None or self.depth >= MAX_CALLER_DEPTH or fn.entry:
            return TAINTED
        args = fn.node.args
        positional = [a.arg for a in args.posonlyargs + args.args]
        method = "." in fn.qualname and positional[:1] in (["self"], ["cls"])
        found = []
        for caller in self.index.functions:
            for call in ast.walk(caller.node):
                if not isinstance(call, ast.Call) or _last_name(call.func) != fn.name:
                    continue
                arg = next((k.value for k in call.keywords if k.arg == param), None)
                if arg is None and param in positional:
                    at = positional.index(param) - (1 if method else 0)
                    if any(isinstance(a, ast.Starred) for a in call.args):
                        return TAINTED
                    arg = call.args[at] if 0 <= at < len(call.args) else None
                if arg is None:
                    return TAINTED       # a default, **kwargs: not worth guessing
                upstream = _Values(caller, self.index.modules.get(caller.file),
                                   self.category, self.index, self.depth + 1, self.used)
                found.append(upstream.of(arg))
        return self._worst(found) if found else TAINTED

    @staticmethod
    def _assignments(tree, top_only=False) -> dict:
        found: dict[str, list] = {}
        nodes = tree.body if top_only else ast.walk(tree)
        for n in nodes:
            if isinstance(n, ast.Assign):
                for target in n.targets:
                    if isinstance(target, ast.Name):
                        found.setdefault(target.id, []).append(n.value)
            elif isinstance(n, (ast.AnnAssign, ast.AugAssign)) and \
                    isinstance(n.target, ast.Name) and n.value is not None:
                found.setdefault(n.target.id, []).append(n.value)
            elif isinstance(n, (ast.For, ast.AsyncFor, ast.With, ast.AsyncWith)):
                targets = [n.target] if isinstance(n, (ast.For, ast.AsyncFor)) \
                    else [i.optional_vars for i in n.items if i.optional_vars]
                for t in targets:
                    for name in ast.walk(t):
                        if isinstance(name, ast.Name):
                            found.setdefault(name.id, []).append(None)   # unknown
        return found

    def of(self, node, depth=0) -> str:
        if node is None or depth > 25:
            return TAINTED
        if isinstance(node, ast.Constant):
            return CONSTANT
        if isinstance(node, ast.Name):
            if node.id in self.params:
                return self._from_callers(node.id)
            sources = self.local.get(node.id) or self.module.get(node.id)
            if not sources:
                return TAINTED          # an import or a global: not ours to vouch for
            return self._worst(self.of(v, depth + 1) for v in sources)
        if isinstance(node, (ast.JoinedStr, ast.FormattedValue, ast.BinOp,
                             ast.Tuple, ast.List, ast.Set, ast.BoolOp, ast.IfExp)):
            return self._worst(self.of(c, depth + 1) for c in ast.iter_child_nodes(node)
                               if isinstance(c, ast.expr))
        if isinstance(node, ast.Call):
            name = _last_name(node.func)
            if name in self.sanitizers:
                self.used.append(name)
                return SANITIZED
            # str(x) is x as text: as safe or unsafe as x was.
            transparent = isinstance(node.func, ast.Name) and name in PASS_THROUGH
            if transparent or (isinstance(node.func, ast.Attribute) and name in STR_METHODS):
                receiver = [] if transparent else [node.func.value]
                parts = receiver + list(node.args) + [k.value for k in node.keywords]
                return self._worst(self.of(p, depth + 1) for p in parts)
            return TAINTED
        return TAINTED

    @staticmethod
    def _worst(values) -> str:
        values = list(values)
        return max(values, key=_ORDER.get) if values else CONSTANT


def _reads_input(call: ast.Call) -> bool:
    """request.args.get(...) and the like: where input comes in, never the
    dangerous use, however literal its arguments are."""
    node = call.func
    while isinstance(node, (ast.Attribute, ast.Subscript, ast.Call)):
        node = node.func if isinstance(node, ast.Call) else node.value
    return isinstance(node, ast.Name) and node.id in INPUT_OBJECTS


def _sink_call(fn: Function, hypothesis: dict, line: int | None,
               line_end: int | None) -> ast.Call | None:
    wanted = set(re.findall(r"[A-Za-z_]\w*", hypothesis["sink"]))
    calls = [n for n in ast.walk(fn.node) if isinstance(n, ast.Call)
             and not _reads_input(n)]
    in_evidence = [c for c in calls if line and
                   line <= c.lineno <= (line_end or line)]
    for group in (in_evidence, calls):
        for test in (lambda c: _last_name(c.func) in wanted,
                     lambda c: _last_name(c.func) in DANGEROUS):
            hits = [c for c in group if test(c)]
            if hits:
                return hits[0]
    return None


def try_sanitizer(index: Index, finding: dict, hypothesis: dict, sink: Function) -> dict:
    call = _sink_call(sink, hypothesis, finding.get("line"), finding.get("line_end"))
    if call is None:
        return {"result": INCONCLUSIVE,
                "note": f"no call in {sink.where()} matches the sink"}
    values = _Values(sink, index.modules.get(sink.file),
                     str(finding.get("category") or ""), index)
    callee = _last_name(call.func)
    where = {"call": ast.unparse(call.func)[:120], "line": call.lineno}
    params = len(call.args) >= 2 or any(k.arg in ("params", "parameters", "args")
                                        for k in call.keywords)
    if callee in QUERY_CALLS and call.args and params \
            and values.of(call.args[0]) == CONSTANT:
        return {"result": REFUTED, "evidence": {**where, "value": "parameterised"},
                "note": "the query is a literal and the values travel as parameters"}
    args = list(call.args) + [k.value for k in call.keywords]
    if callee in QUERY_CALLS and call.args:
        args = call.args[:1]
    verdict = values._worst(values.of(a) for a in args) if args else TAINTED
    if verdict == CONSTANT:
        return {"result": REFUTED, "evidence": {**where, "value": CONSTANT},
                "note": "what reaches the sink is built only from literals"}
    if verdict == SANITIZED:
        used = sorted(set(values.used))
        return {"result": REFUTED, "evidence": {**where, "value": SANITIZED,
                                                "through": used},
                "note": f"what reaches the sink passes through {', '.join(used)} first"}
    return {"result": SURVIVED, "evidence": {**where, "value": TAINTED},
            "note": "a value not built from literals nor sanitised reaches the sink"}


# ---------------------------------------------------------------------------
# Refutation 3: reachability
# ---------------------------------------------------------------------------

def try_reachability(index: Index, sink: Function) -> dict:
    if not index.entries():
        return {"result": INCONCLUSIVE,
                "note": "no entry point (route, command, handler, script) was "
                        "recognised in this repository"}
    path = index.from_entry(sink)
    if path:
        return {"result": SURVIVED,
                "evidence": {"entry": path[0].where(), "why": path[0].entry,
                             "chain": _steps(path)},
                "note": f"reached from {path[0].where()} ({path[0].entry})"}
    if index.mentions[sink.name] == 0:
        return {"result": REFUTED, "evidence": {"function": sink.where()},
                "note": f"{sink.where()} is never called or referred to: dead code"}
    return {"result": INCONCLUSIVE,
            "note": f"{sink.where()} is used, but by nothing an entry point reaches"}


# ---------------------------------------------------------------------------
# Refutation 4: the devil's advocate, checked
# ---------------------------------------------------------------------------

VERDICTS = ("false_positive", "holds", "unsure")


def check_devil(project: Path, claim) -> dict | None:
    """The devil's advocate's answer, with its quotes looked up in the code."""
    if not isinstance(claim, dict) or claim.get("verdict") not in VERDICTS:
        return None
    argument = str(claim.get("argument") or "").strip()[:4000]
    cited = []
    for c in (claim.get("citations") or [])[:8]:
        if not isinstance(c, dict):
            continue
        path = re.sub(r"^(\./)+", "", str(c.get("file") or "").strip())
        snippet = str(c.get("code_snippet") or "")[:2000]
        text = _read_in(project, path) if path else None
        where = locate(snippet, text) if text and snippet.strip() else None
        cited.append({"file": path, "code_snippet": snippet,
                      "line": where[0] if where else None,
                      "line_end": where[1] if where else None,
                      "found": bool(where)})
    found = [c for c in cited if c["found"]]
    evidence = {"verdict": claim["verdict"], "argument": argument, "citations": cited}
    if claim["verdict"] == "false_positive" and found:
        return {"result": REFUTED, "evidence": evidence,
                "note": "argued false, quoting code that is in the repository"}
    if claim["verdict"] == "false_positive":
        return {"result": SURVIVED, "evidence": evidence,
                "note": "argued false, but quoted no code that is in the "
                        "repository, so the argument does not count"}
    if claim["verdict"] == "holds":
        return {"result": SURVIVED, "evidence": evidence,
                "note": "could not argue it false"}
    return {"result": INCONCLUSIVE, "evidence": evidence,
            "note": "could neither argue it false nor confirm it"}


# ---------------------------------------------------------------------------
# The verdict
# ---------------------------------------------------------------------------

def decide(attempts: dict, python: bool) -> str:
    """The epistemic status a set of attempts leaves a verified finding in."""
    results = {m: a["result"] for m, a in attempts.items()}
    if REFUTED in results.values():
        return REFUTED
    if not python:
        return EXISTS
    if all(results.get(m) == SURVIVED for m in METHODS):
        return CORROBORATED
    if results.get(REACHABILITY) == SURVIVED:
        return REACHABLE
    if INCONCLUSIVE in results.values():
        return INCONCLUSIVE
    return EXISTS


def assess(project: Path, finding: dict, index: Index | None = None) -> dict:
    """Try to refute one finding. Never raises; never reads outside project.

    Returns {"hypothesis", "attempts": [...], "status", "note"}. status is None
    for a finding without evidence: it does not even exist yet.
    """
    hypothesis = normalize_hypothesis(finding.get("hypothesis"))
    out = {"hypothesis": hypothesis, "attempts": [], "status": None, "note": None}
    if finding.get("verification_status") != "verified":
        return out
    file = re.sub(r"^(\./)+", "", str(finding.get("file") or ""))
    if not hypothesis or not hypothesis["complete"]:
        out.update(status=EXISTS, note=INCOMPLETE)
        # Without a flow there is no chain to test, but two attempts need no
        # source: whether the code can run at all, and what reaches the call
        # the evidence points at. A model rarely names the source of dead
        # code or of a query made of constants, because there is none. Only
        # a refutation is recorded: anything else leaves it at exists.
        if file.endswith(".py") and finding.get("category") in FLOW_CATEGORIES:
            index = index or Index(project)
            sink = index.function_at(file, finding.get("line"))
            blank = hypothesis or {"source": "", "sink": "", "path": [],
                                   "preconditions": [], "complete": False}
            tries = [] if sink is None else [
                (REACHABILITY, try_reachability(index, sink)),
                (SANITIZER, try_sanitizer(index, finding, blank, sink))]
            refuted = [(m, a) for m, a in tries if a["result"] == REFUTED]
            if refuted:
                out["hypothesis"] = blank
                out["attempts"] = [{"method": m, "result": REFUTED,
                                    "evidence": a.get("evidence"), "note": a.get("note")}
                                   for m, a in refuted]
                out.update(status=REFUTED, note=None)
        return out

    python = file.endswith(".py")
    attempts: dict[str, dict] = {}
    if python:
        index = index or Index(project)
        sink = index.function_at(file, finding.get("line")) \
            or index.resolve(hypothesis["sink"], near=file)
        if sink is None:
            for method in (CALLGRAPH, SANITIZER, REACHABILITY):
                attempts[method] = {"result": INCONCLUSIVE,
                                    "note": "the sink is not inside any function "
                                            "found in the checkout"}
        else:
            attempts[CALLGRAPH] = try_callgraph(index, hypothesis, sink)
            attempts[SANITIZER] = try_sanitizer(index, finding, hypothesis, sink)
            attempts[REACHABILITY] = try_reachability(index, sink)
    else:
        out["note"] = PYTHON_ONLY.format(file=file or "this file")
    devil = check_devil(project, finding.get("devil_advocate"))
    if devil:
        attempts[DEVIL] = devil
    out["attempts"] = [{"method": m, "result": a["result"],
                        "evidence": a.get("evidence"), "note": a.get("note")}
                       for m, a in attempts.items()]
    out["status"] = decide(attempts, python)
    return out


# ---------------------------------------------------------------------------
# What the devil's advocate is shown
# ---------------------------------------------------------------------------

def context_for(project: Path, finding: dict, index: Index | None,
                limit: int = 6000) -> str:
    """The code a reviewer needs to argue about one finding, numbered."""
    file = re.sub(r"^(\./)+", "", str(finding.get("file") or ""))
    text = _read_in(project, file) if file else None
    if text is None:
        return ""
    lines = text.splitlines()
    spans: list[tuple[str, int, int]] = []
    if index is not None and file.endswith(".py"):
        hypothesis = normalize_hypothesis(finding.get("hypothesis")) or {}
        sink = index.function_at(file, finding.get("line"))
        picked = [sink] if sink else []
        for part in [hypothesis.get("source", "")] + hypothesis.get("path", []):
            fn = index.resolve(part, near=file)
            if fn and fn not in picked:
                picked.append(fn)
        spans = [(f.file, f.line, f.end) for f in picked if f]
    if not spans:
        centre = finding.get("line") or 1
        spans = [(file, max(1, centre - 30), min(len(lines), centre + 30))]
    parts, used = [], 0
    for path, start, end in spans:
        body = _read_in(project, path)
        if body is None:
            continue
        chunk = "\n".join(f"{n:>5}| {l}" for n, l in
                          enumerate(body.splitlines()[start - 1:end], start))
        block = f"--- {path} (lines {start}-{end}) ---\n{chunk}\n"
        if used + len(block) > limit:
            block = block[:max(0, limit - used)]
        parts.append(block)
        used += len(block)
        if used >= limit:
            break
    return "".join(parts)
