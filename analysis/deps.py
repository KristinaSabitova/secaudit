"""Dependencies: what the repository declares and locks, and what that risks (B10, C23).

Read from manifests and lockfiles on the server's checkout, never by running
a package manager (no `pip`, no `npm install`: both run code from the
packages). Supported: requirements*.txt, pyproject.toml (PEP 621 and
Poetry), poetry.lock, uv.lock, package.json, package-lock.json (v1-v3) and
go.mod. A lockfile gives the transitive set with exact versions; a manifest
alone gives the direct dependencies with the range as declared.

From that inventory:

- a CycloneDX 1.5 SBOM (to_cyclonedx);
- dependency confusion signals: pip's --extra-index-url (the classic: the
  public index is consulted too, and the higher version wins), npm lockfiles
  resolving from more than one registry, dependencies fetched from a git or
  plain URL instead of a registry;
- ghost dependencies: declared and never mentioned anywhere else in the code.
  Plugins, entry points and dynamic imports exist, so these are "apparently
  unused", a list to look at, not findings;
- known vulnerabilities, from OSV.dev, only when SECAUDIT_OSV_CHECK=1: the
  package names and versions leave the server, nothing else. Only exact
  versions are asked: a range has no single answer. Every vulnerability
  carries its OSV id and aliases (CVE, GHSA) so it can be checked at its
  source; no severity is invented where the advisory gives none.

Abandoned packages would need each registry's release history; that is not
looked up, and the limits say so.
"""

import json
import os
import re
import tomllib
import urllib.parse
import urllib.request
from pathlib import PurePosixPath

DEPS_VERSION = "1"

PYPI, NPM, GO = "PyPI", "npm", "Go"
MAX_COMPONENTS = 5000

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*(.*)$")
_EXACT = re.compile(r"^==\s*([A-Za-z0-9.+!_\-]+)\s*$")
_REQ_FILE = re.compile(r"(^|/)requirements[^/]*\.(txt|in)$|(^|/)requirements/[^/]+\.(txt|in)$")


def pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def purl(ecosystem: str, name: str, version: str | None) -> str:
    if ecosystem == NPM:
        q = urllib.parse.quote(name, safe="/").replace("@", "%40", 1) \
            if name.startswith("@") else urllib.parse.quote(name)
        base = f"pkg:npm/{q}"
    elif ecosystem == PYPI:
        base = f"pkg:pypi/{pypi_name(name)}"
    else:
        base = f"pkg:golang/{name}"
    return f"{base}@{urllib.parse.quote(version)}" if version and _is_exact(version) else base


def _is_exact(version: str) -> bool:
    return bool(re.match(r"^v?\d[\w.+\-]*$", version or ""))


def _component(ecosystem, name, version, direct, manifest, scope="runtime",
               line=None, resolved=None) -> dict:
    return {"ecosystem": ecosystem, "name": name, "version": version or None,
            "direct": direct, "scope": scope, "manifest": manifest, "line": line,
            "resolved": resolved, "purl": purl(ecosystem, name, version)}


def _signal(rule: str, file: str, line: int | None, text: str, **detail) -> dict:
    return {"rule": rule, "file": file, "line": line, "text": text[:300], **detail}


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

def parse_requirements(rel: str, text: str) -> tuple[list[dict], list[dict]]:
    comps, signals = [], []
    scope = "dev" if re.search(r"(?i)dev|test|lint|doc", PurePosixPath(rel).name) else "runtime"
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("--extra-index-url", "--index-url", "-i ", "--find-links", "-f ")):
            if line.startswith("--extra-index-url"):
                signals.append(_signal("dep.extra_index_url", rel, n, line))
            elif line.startswith(("--index-url", "-i ")):
                signals.append(_signal("dep.custom_index", rel, n, line))
            continue
        if line.startswith(("-r", "-c", "--requirement", "--constraint")):
            continue
        if line.startswith(("-e", "git+", "http://", "https://")) or " @ " in line:
            signals.append(_signal("dep.url_source", rel, n, line))
            m = re.search(r"#egg=([A-Za-z0-9._\-]+)", line) or \
                re.match(r"^([A-Za-z0-9._\-]+)\s*@", line)
            if m:
                comps.append(_component(PYPI, m.group(1), None, True, rel, scope, n))
            continue
        m = _REQ_LINE.match(line.split(";")[0])
        if not m:
            continue
        spec = m.group(3).strip()
        exact = _EXACT.match(spec)
        comps.append(_component(PYPI, m.group(1), exact.group(1) if exact else spec or None,
                                True, rel, scope, n))
    return comps, signals


def _pep508(rel: str, text: str, items, scope: str) -> list[dict]:
    out = []
    for item in items or []:
        if not isinstance(item, str):
            continue
        m = _REQ_LINE.match(item.split(";")[0])
        if not m:
            continue
        spec = m.group(3).strip()
        exact = _EXACT.match(spec)
        out.append(_component(PYPI, m.group(1), exact.group(1) if exact else spec or None,
                              True, rel, scope, _line_of(text, m.group(1))))
    return out


def _line_of(text: str, needle: str) -> int | None:
    for n, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return n
    return None


def parse_pyproject(rel: str, text: str) -> tuple[list[dict], list[dict]]:
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return [], []
    comps, signals = [], []
    project = data.get("project") or {}
    comps += _pep508(rel, text, project.get("dependencies"), "runtime")
    for group in (project.get("optional-dependencies") or {}).values():
        comps += _pep508(rel, text, group, "optional")
    for group in (data.get("dependency-groups") or {}).values():
        comps += _pep508(rel, text, [g for g in group if isinstance(g, str)], "dev")
    poetry = (data.get("tool") or {}).get("poetry") or {}
    sections = [("runtime", poetry.get("dependencies")),
                ("dev", poetry.get("dev-dependencies"))]
    for group in (poetry.get("group") or {}).values():
        sections.append(("dev", (group or {}).get("dependencies")))
    for scope, deps in sections:
        for name, spec in (deps or {}).items():
            if name.lower() == "python":
                continue
            version = spec if isinstance(spec, str) else (spec or {}).get("version") \
                if isinstance(spec, dict) else None
            if isinstance(spec, dict) and (spec.get("git") or spec.get("url")):
                signals.append(_signal("dep.url_source", rel, _line_of(text, name),
                                       f"{name} = {spec}"))
            comps.append(_component(PYPI, name, version, True, rel, scope,
                                    _line_of(text, name)))
    for source in poetry.get("source") or []:
        if isinstance(source, dict) and source.get("priority") in (None, "supplemental",
                                                                    "secondary", "default"):
            if source.get("url") and "pypi.org" not in source["url"]:
                signals.append(_signal("dep.extra_index_url", rel,
                                       _line_of(text, source["url"]), str(source["url"]),
                                       note="poetry source consulted beside PyPI"))
    return comps, signals


def parse_toml_lock(rel: str, text: str) -> list[dict]:
    """poetry.lock and uv.lock: [[package]] name/version, all transitive."""
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, RecursionError):
        return []
    out = []
    for p in data.get("package") or []:
        if isinstance(p, dict) and p.get("name"):
            scope = "dev" if p.get("category") == "dev" else "runtime"
            src = p.get("source") if isinstance(p.get("source"), dict) else {}
            out.append(_component(PYPI, p["name"], str(p.get("version") or "") or None,
                                  False, rel, scope, None,
                                  src.get("url") or src.get("registry") or src.get("git")))
    return out


# ---------------------------------------------------------------------------
# npm
# ---------------------------------------------------------------------------

def parse_package_json(rel: str, text: str) -> tuple[list[dict], list[dict]]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return [], []
    if not isinstance(data, dict):
        return [], []
    comps, signals = [], []
    for key, scope in (("dependencies", "runtime"), ("devDependencies", "dev"),
                       ("optionalDependencies", "optional"), ("peerDependencies", "runtime")):
        for name, spec in (data.get(key) or {}).items():
            spec = str(spec)
            line = _line_of(text, f'"{name}"')
            if re.match(r"^(git(\+\w+)?:|https?:|github:|[\w.\-]+/[\w.\-]+(#.*)?$)", spec):
                signals.append(_signal("dep.url_source", rel, line, f'"{name}": "{spec}"'))
            exact = spec if _is_exact(spec) else None
            comps.append(_component(NPM, name, exact or spec, True, rel, scope, line))
    return comps, signals


def parse_package_lock(rel: str, text: str) -> tuple[list[dict], list[dict]]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        return [], []
    if not isinstance(data, dict):
        return [], []
    comps, hosts = [], {}
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, p in packages.items():
            if not path or not isinstance(p, dict) or "node_modules/" not in path:
                continue
            name = p.get("name") or path.rsplit("node_modules/", 1)[1]
            comps.append(_component(NPM, name, p.get("version"), False, rel,
                                    "dev" if p.get("dev") else
                                    "optional" if p.get("optional") else "runtime",
                                    None, p.get("resolved")))
    else:
        def walk(deps):
            for name, p in (deps or {}).items():
                if isinstance(p, dict):
                    comps.append(_component(NPM, name, p.get("version"), False, rel,
                                            "dev" if p.get("dev") else "runtime",
                                            None, p.get("resolved")))
                    walk(p.get("dependencies"))
        walk(data.get("dependencies"))
    for c in comps:
        r = c.get("resolved")
        if isinstance(r, str) and r.startswith(("http://", "https://")):
            hosts.setdefault(urllib.parse.urlsplit(r).hostname or "?", []).append(c["name"])
    signals = []
    if len(hosts) > 1:
        others = {h: n for h, n in hosts.items() if h != "registry.npmjs.org"}
        signals.append(_signal(
            "dep.mixed_registries", rel, None,
            "packages resolved from: " + ", ".join(sorted(hosts)),
            hosts={h: sorted(set(n))[:20] for h, n in others.items()}))
    for c in comps:
        r = c.get("resolved") or ""
        if r.startswith("http://"):
            signals.append(_signal("dep.insecure_resolved", rel, _line_of(text, r),
                                   f"{c['name']}: {r}"))
    return comps, signals


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

def parse_go_mod(rel: str, text: str) -> list[dict]:
    out, block = [], False
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("require ("):
            block = True
            continue
        if block and line == ")":
            block = False
            continue
        m = re.match(r"^(?:require\s+)?([\w.\-~/]+\.[\w.\-~/]+)\s+(v[\w.+\-]+)(\s*//\s*indirect)?",
                     line) if (block or line.startswith("require ")) else None
        if m:
            out.append(_component(GO, m.group(1), m.group(2), not m.group(3), rel,
                                  "runtime", n))
    return out


# ---------------------------------------------------------------------------
# All of it
# ---------------------------------------------------------------------------

def inventory(texts: dict[str, str]) -> dict:
    """Every component and every supply-chain signal in the checkout's manifests."""
    comps, signals, manifests = [], [], []
    for rel in sorted(texts):
        name = PurePosixPath(rel).name.lower()
        text = texts[rel]
        got, sig = [], []
        if _REQ_FILE.search(rel.lower()):
            got, sig = parse_requirements(rel, text)
        elif name == "pyproject.toml":
            got, sig = parse_pyproject(rel, text)
        elif name in ("poetry.lock", "uv.lock"):
            got = parse_toml_lock(rel, text)
        elif name == "package.json":
            got, sig = parse_package_json(rel, text)
        elif name in ("package-lock.json", "npm-shrinkwrap.json"):
            got, sig = parse_package_lock(rel, text)
        elif name == "go.mod":
            got = parse_go_mod(rel, text)
        else:
            continue
        manifests.append(rel)
        comps += got
        signals += sig
    # A locked component that a manifest declares is direct.
    declared = {(c["ecosystem"], _key(c)) for c in comps if c["direct"]}
    for c in comps:
        if not c["direct"] and (c["ecosystem"], _key(c)) in declared:
            c["direct"] = True
    # One row per ecosystem, name and version; the first manifest names it.
    unique, seen = [], set()
    for c in comps:
        k = (c["ecosystem"], _key(c), c["version"])
        if k not in seen:
            seen.add(k)
            unique.append(c)
    return {"components": unique[:MAX_COMPONENTS], "signals": signals[:200],
            "manifests": manifests, "truncated": len(unique) > MAX_COMPONENTS}


def _key(c: dict) -> str:
    return pypi_name(c["name"]) if c["ecosystem"] == PYPI else c["name"]


# Distributions whose import name is not their own.
IMPORT_NAMES = {
    "pyyaml": "yaml", "beautifulsoup4": "bs4", "pillow": "PIL",
    "python-dateutil": "dateutil", "scikit-learn": "sklearn",
    "psycopg2-binary": "psycopg2", "psycopg-binary": "psycopg", "psycopg": "psycopg",
    "opencv-python": "cv2", "python-dotenv": "dotenv", "pyjwt": "jwt",
    "python-multipart": "multipart", "attrs": "attr", "protobuf": "google.protobuf",
    "pymysql": "pymysql", "mysqlclient": "MySQLdb", "typing-extensions": "typing_extensions",
    "uvicorn": "uvicorn", "gunicorn": "gunicorn", "pycryptodome": "Crypto",
    "google-cloud-storage": "google.cloud", "msgpack-python": "msgpack",
}

# Packages that are tools, not imports: never reported as ghosts.
_TOOLS = re.compile(r"(?i)^(@types/|eslint|prettier|typescript$|ts-node|jest|mocha|vitest|"
                    r"nodemon|husky|lint-staged|webpack|vite|rollup|babel|@babel/|postcss|"
                    r"autoprefixer|tailwindcss|pytest|black|ruff|flake8|mypy|isort|pylint|"
                    r"coverage|tox|nox|pre-commit|setuptools|wheel|pip|build|twine|hatch|"
                    r"gunicorn|uvicorn|alembic)")


def ghost_dependencies(components: list[dict], texts: dict[str, str],
                       manifests: list[str]) -> list[dict]:
    """Direct dependencies nothing outside the manifests mentions.

    Generous on purpose: any mention of the package or its import name in any
    other file counts as use (configs name plugins; Dockerfiles run servers),
    so what is left is worth a look. Dynamic imports, entry points and plugin
    loaders can still use something listed here.
    """
    skip = set(manifests) | {r for r in texts if re.search(
        r"(?i)(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|uv\.lock|"
        r"go\.sum|requirements[^/]*\.(txt|in)|pyproject\.toml|setup\.cfg|"
        r"README[^/]*|CHANGELOG[^/]*)$", r)}
    corpus = "\n".join(t for r, t in texts.items() if r not in skip)
    out = []
    for c in components:
        if not c["direct"] or _TOOLS.search(c["name"]):
            continue
        if c["ecosystem"] == PYPI:
            mod = IMPORT_NAMES.get(pypi_name(c["name"]),
                                   pypi_name(c["name"]).replace("-", "_"))
            names = {mod.split(".")[0], c["name"], pypi_name(c["name"])}
        elif c["ecosystem"] == NPM:
            names = {c["name"]}
        else:
            names = {c["name"]}
        if not any(re.search(rf"(?<![\w\-/@.]){re.escape(n)}(?![\w\-])", corpus)
                   for n in names if n):
            out.append({"ecosystem": c["ecosystem"], "name": c["name"],
                        "manifest": c["manifest"], "line": c.get("line"),
                        "scope": c["scope"]})
    return out[:200]


# ---------------------------------------------------------------------------
# OSV.dev
# ---------------------------------------------------------------------------

OSV_API = "https://api.osv.dev/v1"
OSV_TIMEOUT = 20
MAX_OSV_QUERIES = 1000
MAX_OSV_DETAILS = 60


def osv_enabled() -> bool:
    return os.environ.get("SECAUDIT_OSV_CHECK", "0").strip().lower() in ("1", "true", "yes", "on")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _http(method: str, url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "secaudit"})
    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(req, timeout=OSV_TIMEOUT) as resp:
        return json.loads(resp.read(10_000_000))


def _severity(vuln: dict) -> str | None:
    """The advisory's own severity word, when it gives one. Never computed."""
    for holder in [vuln.get("database_specific") or {}] + \
            [a.get("database_specific") or {} for a in vuln.get("affected") or []]:
        word = str(holder.get("severity") or "").lower()
        if word in ("critical", "high", "medium", "low"):
            return word
        if word == "moderate":
            return "medium"
    return None


def query_osv(components: list[dict], http=_http) -> dict:
    """Ask OSV.dev about every component with an exact version.

    Returns {"queried", "asked", "vulnerable", "error"} and sets c["vulns"]
    on each component asked: a list of {id, aliases, summary, severity, url}.
    """
    asked = [c for c in components
             if c["version"] and _is_exact(c["version"])][:MAX_OSV_QUERIES]
    result = {"queried": False, "asked": len(asked), "vulnerable": 0, "error": None}
    if not asked:
        result["queried"] = True
        return result
    queries = [{"package": {"name": _key(c) if c["ecosystem"] == PYPI else c["name"],
                            "ecosystem": c["ecosystem"]},
                "version": c["version"].lstrip("v") if c["ecosystem"] != GO else c["version"]}
               for c in asked]
    try:
        ids_per = []
        for i in range(0, len(queries), 500):
            body = http("POST", f"{OSV_API}/querybatch", {"queries": queries[i:i + 500]})
            ids_per += [[v.get("id") for v in (r or {}).get("vulns") or [] if v.get("id")]
                        for r in body.get("results") or []]
        details: dict[str, dict] = {}
        for vid in sorted({v for ids in ids_per for v in ids})[:MAX_OSV_DETAILS]:
            try:
                details[vid] = http("GET", f"{OSV_API}/vulns/{urllib.parse.quote(vid)}")
            except Exception:
                details[vid] = {}
        for c, ids in zip(asked, ids_per):
            c["vulns"] = [{"id": vid,
                           "aliases": (details.get(vid) or {}).get("aliases") or [],
                           "summary": str((details.get(vid) or {}).get("summary") or "")[:300],
                           "severity": _severity(details.get(vid) or {}),
                           "url": f"https://osv.dev/vulnerability/{vid}"} for vid in ids]
            result["vulnerable"] += bool(ids)
        for c in components:
            c.setdefault("vulns", None)
        result["queried"] = True
    except Exception as e:      # no network, refused: said, not guessed
        result["error"] = str(e)[:200]
    return result


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

_SIGNAL_TEXT = {
    "dep.extra_index_url": (
        "medium", "CWE-427",
        ("Possible dependency confusion: extra package index",
         "Posible confusión de dependencias: índice de paquetes adicional"),
        ("pip consults this index and PyPI together and installs the highest version "
         "found in either. Anyone who publishes an internal package name on PyPI with "
         "a higher version gets their code installed. Use --index-url with a proxy "
         "that mirrors PyPI, or pin hashes (--require-hashes).",
         "pip consulta este índice y PyPI a la vez e instala la versión más alta de "
         "cualquiera de los dos. Quien publique en PyPI un nombre interno con una versión "
         "mayor consigue que se instale su código. Usa --index-url con un proxy que "
         "replique PyPI, o fija hashes (--require-hashes).")),
    "dep.custom_index": (
        "info", "CWE-829",
        ("Packages come from a custom index", "Los paquetes vienen de un índice propio"),
        ("Everything is installed from this index instead of PyPI: its integrity is "
         "the supply chain's.",
         "Todo se instala desde este índice en vez de PyPI: su integridad es la de la "
         "cadena de suministro.")),
    "dep.mixed_registries": (
        "medium", "CWE-427",
        ("Lockfile resolves from more than one registry",
         "El lockfile resuelve desde más de un registro"),
        ("Packages come from several registries; a scoped or internal name that the "
         "public registry also serves can be swapped. Pin each scope to one registry "
         "in .npmrc.",
         "Los paquetes vienen de varios registros; un nombre interno que el registro "
         "público también sirva puede suplantarse. Fija cada scope a un registro en .npmrc.")),
    "dep.url_source": (
        "low", "CWE-829",
        ("Dependency fetched from a URL or git", "Dependencia descargada de una URL o de git"),
        ("It bypasses the registry: no published version, and whatever the URL serves "
         "at install time is what runs. Pin it to a commit or a hash.",
         "Se salta el registro: no hay versión publicada y se instala lo que sirva la URL "
         "en ese momento. Fíjala a un commit o a un hash.")),
    "dep.insecure_resolved": (
        "medium", "CWE-494",
        ("Dependency resolved over plain HTTP", "Dependencia resuelta por HTTP sin cifrar"),
        ("A package downloaded over http:// can be replaced in transit.",
         "Un paquete descargado por http:// puede sustituirse por el camino.")),
}


def signal_findings(signals: list[dict], language: str = "en") -> list[dict]:
    es = language == "es"
    out = []
    for s in signals:
        meta = _SIGNAL_TEXT.get(s["rule"])
        if not meta or not s.get("file"):
            continue
        severity, cwe, titles, texts = meta
        out.append({
            "category": "dependencies", "file": s["file"],
            "anchor": f"{s['rule']}:{s['text'][:80]}", "severity": severity,
            "title": titles[1] if es else titles[0],
            "description": texts[1] if es else texts[0],
            "code_snippet": s["text"] if s.get("line") else "",
            "line": s.get("line"),
            "verification_status": "verified" if s.get("line") else "unverified",
            "verification_note": "" if s.get("line") else (
                "señal calculada sobre todo el lockfile" if es
                else "signal computed over the whole lockfile"),
            "rule_id": s["rule"],
            "detail": {"cwe": cwe, "scanner": f"deps/{DEPS_VERSION}",
                       "assessment": "potential", "confidence": "medium",
                       "prerequisites": [("que alguien publique un paquete con ese nombre"
                                          if es else "someone publishing a package under that name")]
                       if "registr" in s["rule"] or "index" in s["rule"] else [],
                       "hosts": s.get("hosts")},
        })
    return out


def vulnerability_findings(components: list[dict], language: str = "en") -> list[dict]:
    """One finding per component that OSV.dev says is affected at that version."""
    es = language == "es"
    out = []
    for c in components:
        if not c.get("vulns"):
            continue
        ids = [v["id"] for v in c["vulns"]]
        aliases = sorted({a for v in c["vulns"] for a in v.get("aliases") or []})
        severities = [v["severity"] for v in c["vulns"] if v.get("severity")]
        order = ["critical", "high", "medium", "low"]
        severity = min(severities, key=order.index) if severities else "medium"
        line = c.get("line")
        out.append({
            "category": "dependencies", "file": c["manifest"],
            "anchor": f"osv:{c['ecosystem']}:{_key(c)}@{c['version']}",
            "severity": severity,
            "title": (f"{c['name']} {c['version']}: vulnerabilidad conocida "
                      f"({', '.join(ids[:3])})" if es else
                      f"{c['name']} {c['version']}: known vulnerability "
                      f"({', '.join(ids[:3])})")[:255],
            "description": (
                ("OSV.dev registra esta versión como afectada. Que el código use la parte "
                 "vulnerable no está comprobado. " if es else
                 "OSV.dev lists this version as affected. Whether the code uses the "
                 "vulnerable part is not established. ")
                + "; ".join(f"{v['id']}: {v['summary']}" for v in c["vulns"][:5])
                + (f" — " + (", ".join(aliases[:8])) if aliases else "")),
            "code_snippet": "", "line": line,
            "verification_status": "verified",
            "verification_note": "",
            "rule_id": "dep.known_vulnerability",
            "detail": {"cwe": "CWE-1395", "scanner": f"deps/{DEPS_VERSION}",
                       "assessment": "potential",
                       "confidence": "high",
                       "component": {k: c[k] for k in ("ecosystem", "name", "version",
                                                         "direct", "purl")},
                       "references": [v["url"] for v in c["vulns"]],
                       "aliases": aliases,
                       "severity_source": "advisory" if severities else
                       ("ninguna: el aviso no da gravedad" if es else
                        "none: the advisory gives no severity"),
                       "limits": ("no se comprueba si el código alcanza la función "
                                  "vulnerable" if es else
                                  "whether the code reaches the vulnerable function "
                                  "is not checked")},
        })
    return out


def to_cyclonedx(components: list[dict], repo_url: str, commit: str | None,
                 tool_version: str) -> dict:
    """A CycloneDX 1.5 JSON SBOM of the inventory."""
    import uuid
    from datetime import datetime, timezone
    comps = []
    for c in components:
        entry = {"type": "library", "name": c["name"],
                 "bom-ref": f"{c['purl']}#{c['manifest']}",
                 "purl": c["purl"], "scope": "optional" if c["scope"] in ("dev", "optional")
                 else "required",
                 "properties": [{"name": "secaudit:direct", "value": str(bool(c["direct"])).lower()},
                                {"name": "secaudit:manifest", "value": c["manifest"]},
                                {"name": "secaudit:scope", "value": c["scope"] or ""}]}
        if c.get("version"):
            entry["version"] = c["version"]
        comps.append(entry)
    vulns = []
    for c in components:
        for v in c.get("vulns") or []:
            vulns.append({"id": v["id"], "source": {"name": "OSV", "url": v["url"]},
                          "references": [{"id": a, "source": {"name": "alias"}}
                                         for a in v.get("aliases") or []],
                          "description": v.get("summary") or None,
                          "affects": [{"ref": f"{c['purl']}#{c['manifest']}"}]})
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": {"components": [{"type": "application", "name": "secaudit",
                                      "version": tool_version}]},
            "component": {"type": "application", "name": repo_url,
                          "version": commit or "unknown",
                          "bom-ref": "root"},
        },
        "components": comps,
    }
    if vulns:
        bom["vulnerabilities"] = vulns
    return bom
