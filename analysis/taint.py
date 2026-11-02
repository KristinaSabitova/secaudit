"""Bounded taint analysis: source -> transformations -> sink (B11).

What it does, and nothing more:

- Python, read with ast, one function at a time (intra-procedural). Sources
  are what a web request carries (Flask/Django/Starlette request objects,
  the parameters of a route handler), sys.argv and input(). A name assigned
  from a source, or from an expression that uses a tainted name, is tainted;
  a call to a known sanitizer or converter (int(), shlex.quote(),
  secure_filename(), html.escape(), ...) stops it. Sinks: SQL built as a
  string, shell commands, eval/exec, file paths, outgoing URLs, templates
  rendered from strings, unsafe deserialization and redirects.
- JavaScript and TypeScript, by pattern over the text of the file, with
  lower confidence: `req.query/body/params/headers/cookies` and names
  assigned or destructured from them, into exec/eval/query strings/fs
  paths/fetch URLs/innerHTML/res.send/res.redirect.

Limits, stated in every result: nothing crosses a function call (a value
passed to a helper that runs the query is not followed); no aliasing,
containers or attributes beyond the name; sanitizers are recognised by name,
not by what they do; other languages are not analysed. A finding is a flow
read from the code, assessed "potential": it says where to look and how the
value gets there, never that it is exploitable.
"""

import ast
import re

TAINT_VERSION = "1"
MAX_FINDINGS = 200
LANGUAGES = ("python", "javascript", "typescript")

# sink kind -> (category, cwe, severity, en title, es title)
SINKS = {
    "sql": ("injection", "CWE-89", "high", "SQL query built from request input",
            "Consulta SQL construida con entrada de la petición"),
    "command": ("injection", "CWE-78", "high", "Shell command built from request input",
                "Comando de shell construido con entrada de la petición"),
    "code": ("injection", "CWE-94", "critical", "Request input evaluated as code",
             "Entrada de la petición evaluada como código"),
    "path": ("file_handling", "CWE-22", "high", "File path taken from request input",
             "Ruta de fichero tomada de la entrada de la petición"),
    "ssrf": ("injection", "CWE-918", "high", "Outgoing request to a URL from request input",
             "Petición saliente a una URL de la entrada de la petición"),
    "template": ("xss", "CWE-79", "high", "Template or markup built from request input",
                 "Plantilla o HTML construidos con entrada de la petición"),
    "deserialization": ("injection", "CWE-502", "high",
                        "Request input deserialized unsafely",
                        "Entrada de la petición deserializada de forma insegura"),
    "redirect": ("injection", "CWE-601", "medium", "Redirect to a location from request input",
                 "Redirección a un destino de la entrada de la petición"),
    "response": ("xss", "CWE-79", "medium", "Request input written into the response",
                 "Entrada de la petición escrita en la respuesta"),
}

LIMITS = {
    "en": ("Python flows are followed into and out of helper functions of the same "
           "file (up to three calls deep); flows through attributes, containers, "
           "functions sharing a name, or other files are not followed. Sanitizers are recognised by name. "
           "JavaScript/TypeScript are read by pattern with low confidence; other "
           "languages are not analysed."),
    "es": ("En Python se siguen los flujos que entran y salen de funciones auxiliares "
           "del mismo fichero (hasta tres llamadas de profundidad); no se siguen a "
           "través de atributos, contenedores, funciones con el mismo nombre ni otros "
           "ficheros. Los saneadores se reconocen por "
           "su nombre. JavaScript/TypeScript se leen por patrón con confianza baja; el "
           "resto de lenguajes no se analiza."),
}

# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

_REQ_ATTRS = {"args", "form", "values", "json", "data", "files", "cookies", "headers",
              "GET", "POST", "COOKIES", "META", "FILES", "body", "query_params",
              "path_params", "query_string", "get_json", "get_data", "stream"}
_ROUTE_DECOS = {"get", "post", "put", "patch", "delete", "route", "api_route",
                "websocket"}
_SANITIZERS = {"int", "float", "bool", "len", "uuid.UUID", "UUID", "shlex.quote", "quote",
               "secure_filename", "escape", "html.escape", "markupsafe.escape",
               "bleach.clean", "os.path.basename", "basename", "urllib.parse.quote",
               "parse_int", "abs", "round", "validate", "clean", "sanitize",
               "re.escape", "ipaddress.ip_address"}
_CMD = {"os.system", "os.popen", "commands.getoutput", "subprocess.getoutput",
        "subprocess.getstatusoutput"}
_SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.check_call",
               "subprocess.check_output", "subprocess.Popen"}
_CODE = {"eval", "exec", "compile"}
_PATH = {"open", "send_file", "send_from_directory", "FileResponse", "os.remove",
         "os.unlink", "shutil.rmtree", "shutil.copy", "shutil.move", "os.rmdir",
         "Path", "pathlib.Path", "io.open", "codecs.open"}
_SSRF = {"requests.get", "requests.post", "requests.put", "requests.delete",
         "requests.request", "requests.head", "httpx.get", "httpx.post", "httpx.request",
         "urllib.request.urlopen", "urlopen", "urllib.request.Request"}
_TEMPLATE = {"render_template_string", "Markup", "mark_safe", "jinja2.Template",
             "Template", "SafeString"}
_DESER = {"pickle.loads", "pickle.load", "cPickle.loads", "marshal.loads",
          "jsonpickle.decode", "yaml.unsafe_load", "dill.loads", "shelve.open"}
_REDIRECT = {"redirect", "RedirectResponse", "HttpResponseRedirect"}
_SQL_METHODS = {"execute", "executemany", "executescript", "raw", "extra", "text"}


def _name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return ""


def _is_source(node) -> bool:
    """This node itself is request input: request.args, request.get_json,
    sys.argv, input(). Its children are looked at by whoever walks it."""
    if isinstance(node, ast.Attribute):
        if _name(node) == "sys.argv":
            return True
        if node.attr in _REQ_ATTRS and \
                _name(node.value).split(".")[-1] in ("request", "req"):
            return True
    if isinstance(node, ast.Call) and _name(node.func) in ("input", "raw_input"):
        return True
    return False


def _uses(node, tainted: set, summaries: dict | None = None) -> str | None:
    """The tainted name (or "<request>") an expression uses, unless a
    sanitizer wraps it. A call to a summarised helper of the same file is
    left to _call_taint, which knows whether its result carries the input."""
    if node is None:
        return None
    if isinstance(node, ast.Call) and _name(node.func) in _SANITIZERS:
        return None
    if summaries and isinstance(node, ast.Call) and _summary_of(node, summaries):
        return None
    if isinstance(node, ast.Name) and node.id in tainted:
        return node.id
    if _is_source(node):
        return "<request>"
    for child in ast.iter_child_nodes(node):
        hit = _uses(child, tainted, summaries)
        if hit:
            return hit
    return None


def _built_string(node) -> bool:
    """A string assembled from parts: f-string, +, %, .format()."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
            node.func.attr == "format":
        return True
    return False


def _sink_of(call: ast.Call) -> tuple[str, ast.AST] | None:
    """(kind, argument that matters) when this call is a sink."""
    name = _name(call.func)
    short = name.split(".")[-1]
    first = call.args[0] if call.args else None
    kw = {k.arg: k.value for k in call.keywords if k.arg}
    if name in _CMD:
        return "command", first
    if name in _SUBPROCESS:
        shell = kw.get("shell")
        if isinstance(shell, ast.Constant) and shell.value is True:
            return "command", first
        if first is not None and _built_string(first):
            return "command", first
        return None
    if name in _CODE:
        return "code", first
    if isinstance(call.func, ast.Attribute) and short in _SQL_METHODS and first is not None:
        # Parameters passed apart are bound by the driver: not a sink.
        if _built_string(first) or isinstance(first, ast.Name):
            return "sql", first
        return None
    if name in _PATH or short in ("send_file", "send_from_directory"):
        return "path", first if short != "send_from_directory" else (
            call.args[1] if len(call.args) > 1 else kw.get("path"))
    if name in _SSRF or (short in ("get", "post", "request") and
                         _name(call.func.value if isinstance(call.func, ast.Attribute)
                               else call.func) in ("requests", "httpx", "session", "client")):
        return "ssrf", first if first is not None else kw.get("url")
    if name in _TEMPLATE or short in ("render_template_string", "mark_safe"):
        return "template", first
    if name in _DESER:
        return "deserialization", first
    if name == "yaml.load":
        loader = kw.get("Loader")
        if loader is None or "Safe" not in _name(loader):
            return "deserialization", first
        return None
    if name in _REDIRECT or short in ("redirect",):
        return "redirect", first
    return None


def _route_params(fn) -> set:
    """Parameters of a route handler: they come from the URL or the body."""
    for d in fn.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, ast.Attribute) and target.attr in _ROUTE_DECOS:
            out = set()
            for a in fn.args.args + fn.args.kwonlyargs:
                ann = ast.unparse(a.annotation) if a.annotation is not None else ""
                if a.arg in ("self", "request", "req", "db", "session") or \
                        re.search(r"\b(int|bool|float|UUID|Depends|Session)\b", ann):
                    continue
                out.add(a.arg)
            return out
        if isinstance(target, ast.Attribute) and target.attr in ("tool", "resource", "prompt"):
            return set()        # MCP tools: the MCP auditor reads those
    return set()


def _line(lines: list[str], n: int) -> str:
    from .secrets_scan import redact_line
    return redact_line(lines[n - 1].strip()) if 0 < n <= len(lines) else ""


_SUMMARY_ROUNDS = 3       # helpers calling helpers: up to three levels deep


def _params(fn) -> list[str]:
    names = [a.arg for a in fn.args.posonlyargs + fn.args.args]
    return [n for n in names if n not in ("self", "cls")] + \
        [a.arg for a in fn.args.kwonlyargs]


def _arg_for(call: ast.Call, fn_params: list[str], index: int, is_method: bool):
    """The expression a call passes for a helper's index-th parameter."""
    name = fn_params[index]
    for k in call.keywords:
        if k.arg == name:
            return k.value
    if index < len(call.args) and not any(isinstance(a, ast.Starred) for a in call.args):
        return call.args[index]
    return None


def _summary_of(call: ast.Call, summaries: dict):
    """The summary of the same-file function a call reaches by its plain
    name (helper(x)) or as a method of self (self.helper(x))."""
    f = call.func
    if isinstance(f, ast.Name):
        return summaries.get(f.id)
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and \
            f.value.id in ("self", "cls"):
        return summaries.get(f.attr)
    return None


def _call_taint(node, tainted: dict, summaries: dict, lines, lineno):
    """When an expression contains a call to a summarised helper that returns
    one of its parameters (or request input), the flow its result carries.
    A sanitizer around the call stops it, as it stops a name."""
    if node is None:
        return None
    if isinstance(node, ast.Call) and _name(node.func) in _SANITIZERS:
        return None
    if not isinstance(node, ast.Call) or not _summary_of(node, summaries):
        for child in ast.iter_child_nodes(node):
            got = _call_taint(child, tainted, summaries, lines, lineno)
            if got:
                return got
        return None
    summ = _summary_of(node, summaries)
    if not summ:
        return None
    call_step = {"step": "call", "line": lineno, "text": _line(lines, lineno),
                 "what": f"{summ['name']}() returns it"}
    if summ["returns_source"]:
        return [{"step": "source", "line": summ["source_line"],
                 "text": _line(lines, summ["source_line"]),
                 "what": f"request input in {summ['name']}()"}, call_step]
    for i in summ["returns_params"]:
        arg = _arg_for(node, summ["params"], i, False)
        hit = _uses(arg, set(tainted))
        if hit:
            prior = tainted.get(hit) or [{"step": "source", "line": lineno,
                                          "text": _line(lines, lineno), "what": "request input"}]
            return (prior + [call_step])[-10:]
    return None


def _analyse(fn, lines, seeds: dict, summaries: dict):
    """The flows of one function from its seeds. Returns (sinks, returns):
    sinks as (kind, flow, sanitized); returns as the flows its return
    statements carry."""
    tainted: dict[str, list[dict]] = {k: list(v) for k, v in seeds.items()}
    sanitized: list[dict] = []
    sinks, returns = [], []
    body = sorted((n for n in _walk_own(fn)), key=lambda n: (getattr(n, "lineno", 0),
                                                             getattr(n, "col_offset", 0)))
    for node in body:
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [t.id for tgt in targets for t in ast.walk(tgt)
                     if isinstance(t, ast.Name)]
            if value is None or not names:
                continue
            if isinstance(value, ast.Call) and _name(value.func) in _SANITIZERS and \
                    _uses(ast.Tuple(elts=list(value.args), ctx=ast.Load()), set(tainted)):
                sanitized.append({"line": node.lineno, "text": _line(lines, node.lineno),
                                  "by": _name(value.func)})
                for n in names:
                    if not isinstance(node, ast.AugAssign):
                        tainted.pop(n, None)
                continue
            through = _call_taint(value, tainted, summaries, lines, node.lineno)
            if through:
                step = {"step": "assign", "line": node.lineno,
                        "text": _line(lines, node.lineno), "what": ", ".join(names)}
                for n in names:
                    tainted[n] = (through + [step])[-10:]
                continue
            hit = _uses(value, set(tainted), summaries)
            if hit:
                prior = tainted.get(hit, [{"step": "source", "line": node.lineno,
                                           "text": _line(lines, node.lineno),
                                           "what": "request input"}])
                step = {"step": "assign", "line": node.lineno,
                        "text": _line(lines, node.lineno), "what": ", ".join(names)}
                for n in names:
                    tainted[n] = (prior + [step])[-10:] if hit != "<request>" else \
                        [{"step": "source", "line": node.lineno,
                          "text": _line(lines, node.lineno), "what": "request input"}]
            elif not isinstance(node, ast.AugAssign):
                for n in names:
                    tainted.pop(n, None)
        elif isinstance(node, ast.Return) and node.value is not None:
            through = _call_taint(node.value, tainted, summaries, lines, node.lineno)
            if through:
                returns.append(through)
                continue
            hit = _uses(node.value, set(tainted), summaries)
            if hit:
                returns.append(list(tainted.get(hit) or [
                    {"step": "source", "line": node.lineno,
                     "text": _line(lines, node.lineno), "what": "request input"}]))
        elif isinstance(node, ast.Call):
            sink = _sink_of(node)
            if sink is not None and sink[1] is not None:
                kind, arg = sink
                hit = _uses(arg, set(tainted), summaries)
                if not hit:
                    through = _call_taint(arg, tainted, summaries, lines, node.lineno)
                    if through:
                        sinks.append((kind, through + [{"step": "sink", "line": node.lineno,
                                                        "text": _line(lines, node.lineno),
                                                        "what": _name(node.func)}],
                                      sanitized))
                    continue
                flow = list(tainted.get(hit) or [{"step": "source", "line": node.lineno,
                                                  "text": _line(lines, node.lineno),
                                                  "what": "request input"}])
                flow.append({"step": "sink", "line": node.lineno,
                             "text": _line(lines, node.lineno), "what": _name(node.func)})
                sinks.append((kind, flow, sanitized))
                continue
            # A call into a helper whose parameter reaches a sink inside it.
            summ = _summary_of(node, summaries)
            if not summ:
                continue
            for i, inner in summ["param_sinks"]:
                arg = _arg_for(node, summ["params"], i, False)
                hit = _uses(arg, set(tainted)) if arg is not None else None
                if not hit:
                    continue
                prior = tainted.get(hit) or [{"step": "source", "line": node.lineno,
                                              "text": _line(lines, node.lineno),
                                              "what": "request input"}]
                kind, inner_flow = inner
                call_step = {"step": "call", "line": node.lineno,
                             "text": _line(lines, node.lineno),
                             "what": f"{summ['name']}({summ['params'][i]})"}
                sinks.append((kind, (prior + [call_step] + inner_flow[1:])[-12:], sanitized))
    return sinks, returns


def _summaries(tree, lines) -> dict:
    """What each function of the file does with its parameters: which reach a
    sink, which are returned, and whether it returns request input. Built
    over a few rounds so a helper calling a helper is followed."""
    fns: dict[str, list] = {}
    for fn in ast.walk(tree):
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fns.setdefault(fn.name, []).append(fn)
    # Two functions sharing a name (methods of different classes): which one
    # a call reaches is not known statically, so neither is summarised.
    unique = {n: f[0] for n, f in fns.items() if len(f) == 1}
    summaries: dict = {}
    for _ in range(_SUMMARY_ROUNDS):
        new = {}
        for name, fn in unique.items():
            params = _params(fn)
            seeds = {p: [{"step": "source", "line": fn.lineno, "text": _line(lines, fn.lineno),
                          "what": f"parameter {p}", "param": p}] for p in params}
            sinks, returns = _analyse(fn, lines, seeds, summaries)
            param_sinks = [(params.index(flow[0]["param"]), (kind, flow))
                           for kind, flow, _ in sinks if flow[0].get("param") in params]
            returns_params = sorted({params.index(r[0]["param"]) for r in returns
                                     if r and r[0].get("param") in params})
            src = [r for r in returns if r and not r[0].get("param")]
            # Request input read inside the helper itself, without seeds.
            own_sinks, own_returns = _analyse(fn, lines, {}, summaries)
            src = src or own_returns
            new[name] = {"name": name, "params": params, "param_sinks": param_sinks[:10],
                         "returns_params": returns_params,
                         "returns_source": bool(src),
                         "source_line": src[0][0]["line"] if src else None}
        if new == summaries:
            break
        summaries = new
    return summaries


def _python(rel: str, text: str) -> list[dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    lines = text.splitlines()
    summaries = _summaries(tree, lines)
    out, seen = [], set()
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        seeds = {p: [{"step": "source", "line": fn.lineno, "text": _line(lines, fn.lineno),
                      "what": f"route parameter {p}"}] for p in _route_params(fn)}
        sinks, _ = _analyse(fn, lines, seeds, summaries)
        for kind, flow, sanitized in sinks:
            key = (kind, flow[0]["line"], flow[-1]["line"])
            if key in seen:
                continue
            seen.add(key)
            out.append(_make(rel, kind, flow, sanitized, "python",
                             "medium" if not any(s["step"] == "call" for s in flow) else "low"))
    return out


def _walk_own(fn):
    """Every node of a function, but not those of functions nested in it."""
    stack = list(ast.iter_child_nodes(fn))
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda,
                             ast.ClassDef)):
            continue
        yield node
        stack.extend(ast.iter_child_nodes(node))


# ---------------------------------------------------------------------------
# JavaScript / TypeScript, by pattern
# ---------------------------------------------------------------------------

_JS_SOURCE = re.compile(r"\b(req|request|ctx\.request|event)\.(query|body|params|headers|"
                        r"cookies|url|search)\b|\blocation\.(search|hash)\b|"
                        r"\bURLSearchParams\(")
_JS_ASSIGN = re.compile(r"\b(?:const|let|var)\s+(\{[^}]{1,300}\}|\[[^\]]{1,200}\]|[A-Za-z_$][\w$]*)"
                        r"\s*(?::\s*[\w<>\[\]|, ]+)?=\s*(.+)$")
_JS_SANITIZER = re.compile(r"\b(parseInt|parseFloat|Number|encodeURIComponent|escape\w*|"
                           r"sanitize\w*|validator\.\w+|DOMPurify\.sanitize|path\.basename|"
                           r"xss\(|Joi\.|z\.\w+\(|isValid\w*)\b")
_JS_SINKS = (
    ("command", re.compile(r"\b(exec|execSync|spawnSync|spawn|execFile)\s*\(")),
    ("code", re.compile(r"\b(eval|Function|setTimeout|setInterval|vm\.runIn\w+)\s*\(")),
    ("sql", re.compile(r"\.(query|raw|execute|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(")),
    ("path", re.compile(r"\b(fs\.\w+|readFile\w*|writeFile\w*|createReadStream|"
                        r"res\.sendFile|res\.download|unlink\w*)\s*\(")),
    ("ssrf", re.compile(r"\b(fetch|axios(\.\w+)?|got|http\.get|https\.get|request)\s*\(")),
    ("template", re.compile(r"(\.innerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|"
                            r"\.html\s*\()")),
    ("redirect", re.compile(r"\bres\.redirect\s*\(|\bwindow\.location\s*=")),
    ("response", re.compile(r"\bres\.(send|write|end)\s*\(")),
)


def _js_names(lhs: str) -> list[str]:
    if lhs.startswith(("{", "[")):
        inner = lhs.strip("{}[] ")
        names = []
        for part in inner.split(","):
            part = part.split("=")[0].strip()
            if ":" in part:
                part = part.split(":")[1].strip()
            part = part.lstrip(".")
            if re.fullmatch(r"[A-Za-z_$][\w$]*", part):
                names.append(part)
        return names
    return [lhs]


def _javascript(rel: str, text: str) -> list[dict]:
    lines = text.split("\n")
    tainted: dict[str, list[dict]] = {}
    out = []
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith(("//", "*", "/*")) or len(line) > 1000:
            continue
        uses = None
        if _JS_SOURCE.search(line):
            uses = "<request>"
        else:
            for name in tainted:
                if re.search(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", line):
                    uses = name
                    break
        m = _JS_ASSIGN.search(line)
        if m:
            names = _js_names(m.group(1).strip())
            if uses and not _JS_SANITIZER.search(m.group(2)):
                prior = tainted.get(uses) if uses != "<request>" else None
                step = {"step": "source" if prior is None else "assign", "line": n,
                        "text": _line(lines, n), "what": ", ".join(names)}
                for name in names:
                    tainted[name] = ((prior or []) + [step])[-8:]
            else:
                for name in names:
                    tainted.pop(name, None)
            continue
        if not uses:
            continue
        for kind, rx in _JS_SINKS:
            sm = rx.search(line)
            if not sm:
                continue
            after = line[sm.end() - 1:]
            if kind == "sql" and not re.search(r"`[^`]*\$\{|['\"]\s*\+|\+\s*['\"]", line):
                continue                        # parameters passed apart
            if kind == "command" and sm.group(1) in ("spawn", "spawnSync", "execFile") \
                    and "shell" not in line:
                continue
            if kind == "ssrf" and not re.search(r"(fetch|axios|got|get|request)\s*\(\s*"
                                                r"[`'\"]?[^,)]*" + (re.escape(uses)
                                                                    if uses != "<request>"
                                                                    else ""), line):
                continue
            if uses != "<request>" and not re.search(
                    rf"(?<![\w$.]){re.escape(uses)}(?![\w$])", after):
                continue
            flow = list(tainted.get(uses) or [{"step": "source", "line": n,
                                               "text": _line(lines, n),
                                               "what": "request input"}])
            flow.append({"step": "sink", "line": n, "text": _line(lines, n),
                         "what": sm.group(0).rstrip("( ")})
            out.append(_make(rel, kind, flow, [], "javascript", "low"))
            break
    return out


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _make(rel: str, kind: str, flow: list[dict], sanitized: list[dict], lang: str,
          confidence: str) -> dict:
    category, cwe, severity, en, es = SINKS[kind]
    sink = flow[-1]
    return {"kind": kind, "file": rel, "line": sink["line"], "category": category,
            "cwe": cwe, "severity": severity, "titles": (en, es), "flow": flow,
            "sanitizers_seen": sanitized[:5], "language": lang, "confidence": confidence,
            "snippet": sink["text"]}


def to_findings(raw: list[dict], language: str = "en") -> list[dict]:
    es = language == "es"
    out = []
    for r in raw[:MAX_FINDINGS]:
        en, sp = r["titles"]
        steps = " → ".join(f"{s['step']}@{s['line']}" for s in r["flow"])
        source = r["flow"][0]
        desc = (f"El valor entra por la línea {source['line']} ({source.get('what')}) y llega "
                f"sin saneado reconocido al sumidero de la línea {r['line']}. Flujo: {steps}."
                if es else
                f"The value enters at line {source['line']} ({source.get('what')}) and reaches "
                f"the sink at line {r['line']} with no recognised sanitizer. Flow: {steps}.")
        out.append({
            "category": r["category"], "file": r["file"], "line": r["line"],
            "severity": r["severity"], "title": (sp if es else en)[:255],
            "description": desc, "code_snippet": r["snippet"],
            "anchor": f"taint.{r['kind']}:{r['file']}:{r['line']}" + (
                f":{source['line']}" if any(st["step"] == "call" for st in r["flow"]) else ""),
            "verification_status": "verified" if r["snippet"] else "unverified",
            "verification_note": "",
            "rule_id": f"taint.{'py' if r['language'] == 'python' else 'js'}.{r['kind']}",
            "detail": {"scanner": f"taint/{TAINT_VERSION}", "cwe": r["cwe"],
                       "assessment": "potential", "confidence": r["confidence"],
                       "flow": r["flow"], "sanitizers_seen": r["sanitizers_seen"],
                       "language": r["language"], "limits": LIMITS["es" if es else "en"]},
        })
    return out


def analyze(texts: dict[str, str]) -> dict:
    raw, analysed, skipped = [], set(), set()
    for rel in sorted(texts):
        low = rel.lower()
        if re.search(r"(?i)(^|/)(tests?|spec|__tests__|node_modules|dist|build|vendor)/", rel):
            continue
        if low.endswith(".py"):
            analysed.add("python")
            raw += _python(rel, texts[rel])
        elif low.endswith((".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx")) and \
                not low.endswith(".min.js"):
            analysed.add("javascript")
            raw += _javascript(rel, texts[rel])
        elif low.endswith((".go", ".java", ".rb", ".php", ".cs", ".rs", ".kt")):
            skipped.add(low.rsplit(".", 1)[1])
        if len(raw) >= MAX_FINDINGS:
            break
    by_kind: dict[str, int] = {}
    for r in raw:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
    return {"version": TAINT_VERSION, "raw": raw[:MAX_FINDINGS], "by_kind": by_kind,
            "languages": sorted(analysed), "not_analysed": sorted(skipped),
            "truncated": len(raw) >= MAX_FINDINGS}
