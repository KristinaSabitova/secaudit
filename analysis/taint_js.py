"""Taint for JavaScript and TypeScript on a real syntax tree (B11).

Uses tree-sitter (an optional dependency: tree-sitter, tree-sitter-javascript,
tree-sitter-typescript). When it is not installed, taint.py falls back to
reading JavaScript by pattern and says so.

What it follows, inside one file:

- sources: members of the request object (req.query, req.body, req.params,
  req.headers, req.cookies, ctx.request..., event.body...), the first
  parameter of a route callback whatever its name, location.search/hash;
- assignments and declarations, destructuring included;
- closures: a callback sees the tainted variables of the function it is
  written in at the point it is written (Express code is mostly callbacks);
- helper functions of the same file, up to three calls deep, into and out of
  them, as in the Python analysis;
- sanitizers by name (parseInt, Number, encodeURIComponent, escape*,
  sanitize*, validator.*, DOMPurify.sanitize, path.basename...).

Sinks: shell commands, eval and friends, SQL built as a string, NoSQL $where,
file paths, outgoing requests, HTML writes, redirects, responses and unsafe
deserialization.

Nothing is executed: the file is parsed, never run.
"""

import re

MAX_FILE = 600_000
_ROUNDS = 3

try:                                    # optional dependency
    import tree_sitter as _ts
    import tree_sitter_javascript as _ts_js
    import tree_sitter_typescript as _ts_ts
    _LANGS = {"javascript": _ts.Language(_ts_js.language()),
              "typescript": _ts.Language(_ts_ts.language_typescript()),
              "tsx": _ts.Language(_ts_ts.language_tsx())}
    AVAILABLE = True
except Exception:                       # not installed, or an incompatible build
    _LANGS = {}
    AVAILABLE = False

_FUNCS = {"function_declaration", "function_expression", "function", "arrow_function",
          "method_definition", "generator_function_declaration", "generator_function"}
_REQ_NAMES = {"req", "request"}
_REQ_PROPS = {"query", "body", "params", "headers", "cookies", "url", "originalUrl", "path",
              "files", "file", "hostname", "ip"}
_CTX_PROPS = {"query", "params", "body", "headers", "cookies", "url", "querystring"}
_EVENT_PROPS = {"body", "queryStringParameters", "pathParameters", "headers"}
_ROUTE_METHODS = {"get", "post", "put", "patch", "delete", "del", "all", "use", "options",
                  "head"}
_SANITIZER = re.compile(r"^(parseInt|parseFloat|Number|Boolean|encodeURIComponent|"
                        r"encodeURI|escape\w*|\w*\.escape\w*|sanitize\w*|\w*\.sanitize\w*|"
                        r"validator\.\w+|DOMPurify\.sanitize|path\.basename|xss|"
                        r"Joi\.\w+|z\.\w+|isValid\w*|Math\.\w+|String\(Number)$")
_CMD = re.compile(r"(^|\.)(exec|execSync)$")
_SPAWN = re.compile(r"(^|\.)(spawn|spawnSync|execFile|execFileSync)$")
_CODE = re.compile(r"^(eval|Function|vm\.runIn\w+|vm\.compileFunction|new Function)$")
_TIMER = re.compile(r"^(setTimeout|setInterval|setImmediate)$")
_SQL = re.compile(r"\.(query|raw|execute|\$queryRawUnsafe|\$executeRawUnsafe|"
                  r"unsafe)$")
_PATH = re.compile(r"^(fs(\.promises)?\.\w+|fsp\.\w+|readFile\w*|writeFile\w*|"
                   r"createReadStream|createWriteStream|unlink\w*|res\.sendFile|res\.download|"
                   r"res\.attachment)$")
_SSRF = re.compile(r"^(fetch|axios(\.\w+)?|got(\.\w+)?|needle(\.\w+)?|superagent\.\w+|"
                   r"https?\.(get|request)|request(\.\w+)?)$")
_REDIRECT = re.compile(r"^([\w$]+)\.redirect$")
_RESPONSE = re.compile(r"^([\w$]+)\.(send|write|end)$")
_RES_NAMES = {"res", "reply", "response", "ctx"}
_DESER = re.compile(r"(^|\.)(unserialize|deserialize)$")
_HTML_PROPS = {"innerHTML", "outerHTML"}
_LOCATION = re.compile(r"^(window\.)?(document\.)?location(\.href)?$")


def _text(node) -> str:
    return node.text.decode("utf-8", "replace") if node is not None else ""


def _line_no(node) -> int:
    return node.start_point[0] + 1


class _File:
    def __init__(self, rel, text, lines, line_fn):
        self.rel, self.text, self.lines = rel, text, lines
        self.line = line_fn                      # (lines, n) -> redacted text
        self.out, self.seen = [], set()
        self.summaries: dict = {}

    def step(self, kind, node, what):
        n = _line_no(node)
        return {"step": kind, "line": n, "text": self.line(self.lines, n), "what": what}


def _own_nodes(fn):
    """The nodes of a function in source order, not descending into nested
    functions (they are returned themselves, so the caller can enter them
    with the variables known at that point)."""
    body = fn.child_by_field_name("body") or fn
    stack = [body]
    out = []
    while stack:
        node = stack.pop()
        out.append(node)
        if node is not body and node.type in _FUNCS:
            continue
        stack.extend(reversed(node.children))
    out.sort(key=lambda n: (n.start_byte, -n.end_byte))
    return out[1:]


def _callee(call) -> str:
    f = call.child_by_field_name("function") or call.child_by_field_name("constructor")
    name = _text(f)
    if call.type == "new_expression":
        name = "new " + name if name == "Function" else name
    return re.sub(r"\s+", "", name)


def _args(call) -> list:
    a = call.child_by_field_name("arguments")
    return [c for c in (a.named_children if a is not None else []) if c.type != "comment"]


def _root_ident(node):
    while node is not None and node.type in ("member_expression", "subscript_expression"):
        node = node.child_by_field_name("object")
    return _text(node) if node is not None and node.type == "identifier" else None


def _is_source(node, req_names) -> bool:
    if node.type != "member_expression":
        return False
    obj, prop = node.child_by_field_name("object"), _text(node.child_by_field_name("property"))
    o = _text(obj)
    if obj.type == "identifier" and o in req_names and prop in _REQ_PROPS:
        return True
    if o in ("ctx.request", "context.request") and prop in _REQ_PROPS:
        return True
    if obj.type == "identifier" and o == "ctx" and prop in _CTX_PROPS:
        return True
    if obj.type == "identifier" and o == "event" and prop in _EVENT_PROPS:
        return True
    if re.fullmatch(r"(window\.|document\.)?location", o) and prop in ("search", "hash"):
        return True
    return False


def _built(node) -> bool:
    if node is None:
        return False
    if node.type == "template_string":
        return any(c.type == "template_substitution" for c in node.children)
    if node.type == "binary_expression":
        return _text(node.child_by_field_name("operator")) == "+"
    if node.type == "call_expression":
        return _callee(node).endswith((".concat", ".join", ".replace", "util.format",
                                       ".format"))
    return node.type == "parenthesized_expression" and _built(node.named_children[0]
                                                              if node.named_children else None)


def _names_of(pattern) -> list[str]:
    if pattern is None:
        return []
    if pattern.type in ("identifier", "shorthand_property_identifier_pattern"):
        return [_text(pattern)]
    out = []
    for c in pattern.named_children:
        if c.type == "pair_pattern":
            out += _names_of(c.child_by_field_name("value"))
        elif c.type in ("assignment_pattern", "object_assignment_pattern"):
            out += _names_of(c.child_by_field_name("left") or c.named_children[0])
        elif c.type in ("rest_pattern",):
            out += _names_of(c.named_children[0] if c.named_children else None)
        elif c.type in ("identifier", "shorthand_property_identifier_pattern",
                        "object_pattern", "array_pattern"):
            out += _names_of(c)
    return out


def _params(fn) -> list[str]:
    p = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
    if p is None:
        return []
    if p.type == "identifier":
        return [_text(p)]
    out = []
    for c in p.named_children:
        if c.type in ("required_parameter", "optional_parameter"):
            c = c.child_by_field_name("pattern") or c.named_children[0]
        if c.type == "assignment_pattern":
            c = c.child_by_field_name("left")
        out.append(_text(c) if c is not None and c.type == "identifier" else "")
    return out


def _route_params(fn) -> tuple[str | None, str | None]:
    """The first two parameters of a function passed to app.get(...),
    router.post(...) and the like: the request and the response, whatever
    they are called."""
    parent = fn.parent
    if parent is None or parent.type != "arguments":
        return None, None
    call = parent.parent
    if call is None or call.type != "call_expression":
        return None, None
    f = call.child_by_field_name("function")
    if f is None or f.type != "member_expression":
        return None, None
    if _text(f.child_by_field_name("property")) not in _ROUTE_METHODS:
        return None, None
    params = _params(fn) + ["", ""]
    return params[0] or None, params[1] or None


class _Scope:
    def __init__(self, tainted: dict, built: set, req_names: set, res_names=_RES_NAMES):
        self.tainted = {k: list(v) for k, v in tainted.items()}
        self.built = set(built)
        self.req_names = set(req_names)
        self.res_names = set(res_names)


def _uses(node, sc: _Scope, summaries: dict):
    """The tainted name, or "<request>", an expression uses; None if a
    sanitizer wraps it or nothing tainted is in it."""
    if node is None or node.type in _FUNCS:
        return None
    if node.type in ("call_expression", "new_expression"):
        name = _callee(node)
        if _SANITIZER.match(name):
            return None
        if summaries.get(name):
            return None                      # left to _through
    if node.type == "identifier":
        return _text(node) if _text(node) in sc.tainted else None
    if _is_source(node, sc.req_names):
        return "<request>"
    if node.type == "member_expression":
        root = _root_ident(node)
        if root in sc.tainted:
            return root
    for c in node.named_children:
        hit = _uses(c, sc, summaries)
        if hit:
            return hit
    return None


def _flow_of(hit, sc, f: _File, node):
    if hit == "<request>":
        return [f.step("source", node, "request input")]
    return list(sc.tainted.get(hit) or [f.step("source", node, "request input")])


def _arg_for(call, params, i):
    args = _args(call)
    return args[i] if i < len(args) else None


def _through(node, sc, summaries, f: _File):
    """When an expression contains a call to a summarised helper whose result
    carries its input (or request input), that flow."""
    if node is None or node.type in _FUNCS:
        return None
    if node.type in ("call_expression", "new_expression"):
        name = _callee(node)
        if _SANITIZER.match(name):
            return None
        summ = summaries.get(name)
        if summ:
            call_step = f.step("call", node, f"{name}() returns it")
            if summ["returns_source"]:
                return [{"step": "source", "line": summ["source_line"],
                         "text": f.line(f.lines, summ["source_line"]),
                         "what": f"request input in {name}()"}, call_step]
            for i in summ["returns_params"]:
                arg = _arg_for(node, summ["params"], i)
                hit = _uses(arg, sc, summaries)
                if hit:
                    return (_flow_of(hit, sc, f, node) + [call_step])[-10:]
                deeper = _through(arg, sc, summaries, f)
                if deeper:
                    return (deeper + [call_step])[-10:]
            return None
    for c in node.named_children:
        got = _through(c, sc, summaries, f)
        if got:
            return got
    return None


def _taint_of(node, sc, summaries, f):
    """(flow, hit) for an expression: the flow it carries, if any."""
    hit = _uses(node, sc, summaries)
    if hit:
        return _flow_of(hit, sc, f, node), hit
    got = _through(node, sc, summaries, f)
    return (got, "<call>") if got else (None, None)


def _sink(call, sc, summaries):
    """(kind, argument) when this call is a sink for its arguments."""
    name = _callee(call)
    args = _args(call)
    first = args[0] if args else None
    if _CMD.search(name):
        # exec() from child_process; RegExp#exec, db.exec and the like are not.
        if name in ("exec", "execSync") or re.match(
                r"^(child_process|childProcess|cp|proc|shell)\.", name):
            return "command", first
        return None
    if _SPAWN.search(name):
        opts = " ".join(_text(a) for a in args[1:])
        if re.search(r"shell\s*:\s*true", opts):
            return "command", first
        return None
    if _CODE.match(name):
        return "code", first
    if _TIMER.match(name) and first is not None and first.type not in _FUNCS \
            and first.type != "identifier":
        return "code", first
    if _SQL.search(name) and first is not None:
        if _built(first) or (first.type == "identifier" and _text(first) in sc.built):
            return "sql", first
        return None
    if _PATH.match(name) and first is not None:
        return "path", first
    if _SSRF.match(name) and first is not None:
        return "ssrf", first
    if first is not None and (name in ("document.write", "document.writeln") or
                              (name.endswith(".html") and name.startswith(("$", "jQuery")))):
        return "template", first
    m = _REDIRECT.match(name)
    if m and args and m.group(1) in sc.res_names:
        return "redirect", args[-1]
    m = _RESPONSE.match(name)
    if m and first is not None and first.type != "object" and m.group(1) in sc.res_names:
        return "response", first
    if _DESER.search(name) and first is not None:
        return "deserialization", first
    return None


def _where_pairs(node):
    """$where values inside an object literal (MongoDB server-side JS)."""
    out = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type in _FUNCS:
            continue
        if n.type == "pair":
            key = _text(n.child_by_field_name("key")).strip("'\"")
            if key == "$where":
                out.append(n.child_by_field_name("value"))
        stack.extend(n.named_children)
    return out


def _report(f: _File, kind, flow, sink_node, what, confidence, sinks):
    flow = (flow + [f.step("sink", sink_node, what)])[-14:]
    sinks.append((kind, flow, confidence))


def _analyse(fn, sc: _Scope, f: _File, summaries: dict, sinks: list, returns: list,
             nested: bool = True):
    req, res = _route_params(fn) if fn.type in _FUNCS else (None, None)
    if req:
        sc.req_names.add(req)
    if res:
        sc.res_names.add(res)
    for node in _own_nodes(fn):
        t = node.type
        if t in _FUNCS:
            if nested:
                inner = _Scope(sc.tainted, sc.built, sc.req_names, sc.res_names)
                # Its own parameters shadow outer names.
                for p in _params(node):
                    inner.tainted.pop(p, None)
                _analyse(node, inner, f, summaries, sinks, [], nested)
            continue
        if t == "variable_declarator" or t == "assignment_expression" or \
                t == "augmented_assignment_expression":
            left = node.child_by_field_name("name") or node.child_by_field_name("left")
            value = node.child_by_field_name("value") or node.child_by_field_name("right")
            if left is None or value is None:
                continue
            # element.innerHTML = x / location.href = x
            if t != "variable_declarator" and left.type == "member_expression":
                prop = _text(left.child_by_field_name("property"))
                kind = "template" if prop in _HTML_PROPS else \
                    "redirect" if _LOCATION.match(_text(left)) else None
                if kind:
                    flow, _ = _taint_of(value, sc, summaries, f)
                    if flow:
                        _report(f, kind, flow, node, _text(left), "medium", sinks)
                continue
            if t != "variable_declarator" and _LOCATION.match(_text(left)):
                flow, _ = _taint_of(value, sc, summaries, f)
                if flow:
                    _report(f, "redirect", flow, node, _text(left), "medium", sinks)
                continue
            names = _names_of(left)
            if not names:
                continue
            if value.type in ("call_expression",) and _SANITIZER.match(_callee(value)):
                for n in names:
                    sc.tainted.pop(n, None)
                    sc.built.discard(n)
                continue
            flow, hit = _taint_of(value, sc, summaries, f)
            if flow:
                step = f.step("assign", node, ", ".join(names))
                for n in names:
                    sc.tainted[n] = (flow + [step])[-12:] if hit != "<request>" else \
                        [f.step("source", node, "request input")]
                    if _built(value):
                        sc.built.add(n)
            elif t != "augmented_assignment_expression":
                for n in names:
                    sc.tainted.pop(n, None)
                    sc.built.discard(n)
            if _built(value):
                for n in names:
                    sc.built.add(n)
        elif t == "return_statement":
            expr = node.named_children[0] if node.named_children else None
            if expr is not None:
                flow, _ = _taint_of(expr, sc, summaries, f)
                if flow:
                    returns.append(flow)
        elif t in ("call_expression", "new_expression"):
            for value in _where_pairs(node):
                flow, _ = _taint_of(value, sc, summaries, f)
                if flow:
                    _report(f, "nosql", flow, value, "$where", "medium", sinks)
            sink = _sink(node, sc, summaries)
            if sink and sink[1] is not None:
                kind, arg = sink
                flow, _ = _taint_of(arg, sc, summaries, f)
                if flow:
                    _report(f, kind, flow, node, _callee(node),
                            "low" if any(s["step"] == "call" for s in flow) else "medium",
                            sinks)
                continue
            summ = summaries.get(_callee(node))
            if not summ:
                continue
            for i, (kind, inner) in summ["param_sinks"]:
                arg = _arg_for(node, summ["params"], i)
                flow, _ = _taint_of(arg, sc, summaries, f) if arg is not None else (None, None)
                if not flow:
                    continue
                call_step = f.step("call", node, f"{_callee(node)}({summ['params'][i]})")
                sinks.append((kind, (flow + [call_step] + inner[1:])[-14:], "low"))


def _helpers(tree) -> dict:
    """Named functions of the file a call can reach by its plain name."""
    found: dict[str, list] = {}
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type in ("function_declaration", "generator_function_declaration"):
            found.setdefault(_text(n.child_by_field_name("name")), []).append(n)
        elif n.type == "variable_declarator":
            v = n.child_by_field_name("value")
            name = n.child_by_field_name("name")
            if v is not None and v.type in _FUNCS and name is not None and \
                    name.type == "identifier":
                found.setdefault(_text(name), []).append(v)
        stack.extend(n.named_children)
    return {k: v[0] for k, v in found.items() if len(v) == 1 and k}


def _summaries(tree, f: _File) -> dict:
    fns = _helpers(tree)
    summaries: dict = {}
    for _ in range(_ROUNDS):
        new = {}
        for name, fn in fns.items():
            params = _params(fn)
            seeds = {p: [{**f.step("source", fn, f"parameter {p}"), "param": p}]
                     for p in params if p}
            sinks, returns = [], []
            _analyse(fn, _Scope(seeds, set(), _REQ_NAMES), f, summaries, sinks, returns,
                     nested=True)
            param_sinks = [(params.index(flow[0]["param"]), (kind, flow))
                           for kind, flow, _ in sinks if flow[0].get("param") in params]
            ret_params = sorted({params.index(r[0]["param"]) for r in returns
                                 if r and r[0].get("param") in params})
            src = [r for r in returns if r and not r[0].get("param")]
            new[name] = {"params": params, "param_sinks": param_sinks[:10],
                         "returns_params": ret_params, "returns_source": bool(src),
                         "source_line": src[0][0]["line"] if src else None}
        if new == summaries:
            break
        summaries = new
    return summaries


def _grammar(rel: str):
    low = rel.lower()
    if low.endswith(".tsx"):
        return _LANGS.get("tsx")
    if low.endswith((".ts", ".mts", ".cts")):
        return _LANGS.get("typescript")
    return _LANGS.get("javascript")


def analyse_file(rel: str, text: str, line_fn, make) -> list[dict]:
    """Taint findings (raw, as taint._make builds them) for one file."""
    if not AVAILABLE or len(text) > MAX_FILE:
        return []
    lang = _grammar(rel)
    if lang is None:
        return []
    try:
        tree = _ts.Parser(lang).parse(text.encode("utf-8", "replace"))
    except Exception:
        return []
    f = _File(rel, text, text.split("\n"), line_fn)
    try:
        summaries = _summaries(tree, f)
        sinks: list = []
        _analyse(tree.root_node, _Scope({}, set(), _REQ_NAMES), f, summaries, sinks, [])
    except RecursionError:
        return []
    out, seen = [], set()
    for kind, flow, confidence in sinks:
        if flow[0].get("param"):
            continue                        # a helper's own parameter, not input
        key = (kind, flow[0]["line"], flow[-1]["line"])
        if key in seen:
            continue
        seen.add(key)
        out.append(make(rel, kind, flow, [], "javascript", confidence))
    return out
