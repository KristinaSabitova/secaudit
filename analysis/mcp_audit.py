"""MCP Security Auditor: the Model Context Protocol surface of a repository.

Finds MCP servers and clients in the code, the tools, resources and prompts
they expose, and the MCP configurations an agent would load (.mcp.json,
.vscode/mcp.json, .cursor/mcp.json, Claude Desktop and Claude Code settings,
any JSON with "mcpServers"). Then checks them against the OWASP MCP Top 10.

Static only. Nothing is started, installed or connected to: a server that
would ask for a token at runtime looks, from here, like a server that does
not, so every finding says what was seen and what would confirm it. A rule
marks a finding "confirmed" only when the code or the configuration states
the fact by itself (a literal token in a config, an auto-approve flag, an
unpinned `npx -y`); everything inferred stays "potential".

Taxonomy: OWASP MCP Top 10, 2025 edition, Beta (Phase 3 of its road map),
as published at https://owasp.org/www-project-mcp-top-10/ and checked on
2026-11-02. The names below are the official ones; MCP04 is "Software
Supply Chain Attacks & Dependency Tampering".

Run it alone over a directory, nothing written anywhere:

    python3 -m analysis.mcp_audit path/to/checkout
"""

import ast
import json
import re
import sys
from pathlib import Path, PurePosixPath

from .parallax import _INSTRUCTION, _load_json, invisible_runs  # noqa: F401
from .secrets_scan import mask, redact_line, scan_line

MCP_AUDIT_VERSION = "1"
OWASP_MCP_VERSION = "OWASP MCP Top 10 2025 (Beta, Phase 3)"
OWASP_MCP_URL = "https://owasp.org/www-project-mcp-top-10/"
OWASP_MCP_CHECKED = "2026-11-02"

# ---------------------------------------------------------------------------
# The catalogue: per category, what is inspected, what can be seen statically,
# what confirms it, the usual false positives, the mitigation and the limits.
# ---------------------------------------------------------------------------

CATALOG = {
    "MCP01": {
        "name": "Token Mismanagement & Secret Exposure",
        "cwe": "CWE-798",
        "inspects": {"en": "MCP configs (env, headers, args, url), tool code returning the environment",
                     "es": "configuraciones MCP (env, headers, args, url), código de herramientas que devuelve el entorno"},
        "static": {"en": "literal tokens in env/headers, tokens in URL query strings, tools returning os.environ / process.env",
                   "es": "tokens literales en env/headers, tokens en la query de una URL, herramientas que devuelven os.environ / process.env"},
        "confirm": {"en": "a value with a known token format, or a high-entropy literal under a secret-named key, written in the config",
                    "es": "un valor con formato de token conocido, o un literal de alta entropía bajo una clave con nombre de secreto, escrito en la configuración"},
        "false_positives": {"en": "placeholders and example configs; ${VAR} references are never flagged",
                            "es": "marcadores y configuraciones de ejemplo; las referencias ${VAR} nunca se marcan"},
        "mitigation": {"en": "reference the environment (${VAR}) or a secret manager; revoke and rotate what was committed",
                       "es": "referenciar el entorno (${VAR}) o un gestor de secretos; revocar y rotar lo publicado"},
        "limits": {"en": "whether a token is live, and its scopes, are not checked; token passthrough at runtime is not visible",
                   "es": "no se comprueba si el token está activo ni sus permisos; el reenvío de tokens en ejecución no es visible"},
    },
    "MCP02": {
        "name": "Privilege Escalation via Scope Creep",
        "cwe": "CWE-269",
        "inspects": {"en": "agent settings (enableAllProjectMcpServers, permissions.allow), autoApprove/alwaysAllow lists, server arguments",
                     "es": "ajustes del agente (enableAllProjectMcpServers, permissions.allow), listas autoApprove/alwaysAllow, argumentos del servidor"},
        "static": {"en": "every project server enabled, wildcard tool permissions, auto-approved tools, filesystem servers rooted at / or ~, dangerous flags",
                   "es": "todos los servidores del proyecto activados, permisos comodín, herramientas autoaprobadas, servidores de ficheros con raíz en / o ~, flags peligrosos"},
        "confirm": {"en": "the setting itself grants it",
                    "es": "el propio ajuste lo concede"},
        "false_positives": {"en": "a sandbox or container around the agent narrows what the grant reaches",
                            "es": "un sandbox o contenedor alrededor del agente limita lo que alcanza el permiso"},
        "mitigation": {"en": "approve servers and tools one by one; root filesystem servers at the project; least privilege tokens",
                       "es": "aprobar servidores y herramientas uno a uno; raíz del servidor de ficheros en el proyecto; tokens de mínimo privilegio"},
        "limits": {"en": "the scopes of OAuth/API tokens are not visible statically",
                   "es": "los permisos de los tokens OAuth/API no son visibles estáticamente"},
    },
    "MCP03": {
        "name": "Tool Poisoning",
        "cwe": "CWE-1427",
        "inspects": {"en": "names and descriptions of tools, resources and prompts (docstrings, description fields)",
                     "es": "nombres y descripciones de herramientas, recursos y prompts (docstrings, campos description)"},
        "static": {"en": "instructions aimed at the model, invisible Unicode, descriptions built at runtime, very long descriptions",
                   "es": "instrucciones dirigidas al modelo, Unicode invisible, descripciones construidas en ejecución, descripciones muy largas"},
        "confirm": {"en": "invisible characters in the metadata (always deliberate); instruction-like text stays potential",
                    "es": "caracteres invisibles en los metadatos (siempre deliberados); el texto con forma de instrucción queda como potencial"},
        "false_positives": {"en": "legitimate usage notes (\"call list_files first\")",
                            "es": "notas de uso legítimas (\"llama antes a list_files\")"},
        "mitigation": {"en": "short, factual descriptions; pin and review tool metadata; show it to the user before approval",
                       "es": "descripciones breves y factuales; fijar y revisar los metadatos; mostrarlos al usuario antes de aprobar"},
        "limits": {"en": "a server can change its descriptions after approval (rug pull): only what is in the repository is read",
                   "es": "un servidor puede cambiar sus descripciones tras aprobarse (rug pull): solo se lee lo que hay en el repositorio"},
    },
    "MCP04": {
        "name": "Software Supply Chain Attacks & Dependency Tampering",
        "cwe": "CWE-494",
        "inspects": {"en": "how configs launch servers (npx, uvx, docker, remote URLs), install pipes",
                     "es": "cómo lanzan las configuraciones los servidores (npx, uvx, docker, URLs remotas), tuberías de instalación"},
        "static": {"en": "unpinned or @latest packages fetched at launch, images without tag or digest, http:// servers, curl | sh",
                   "es": "paquetes sin fijar o @latest descargados al arrancar, imágenes sin tag ni digest, servidores http://, curl | sh"},
        "confirm": {"en": "the launch command itself is unpinned",
                    "es": "el propio comando de arranque no fija versión"},
        "false_positives": {"en": "a lockfile or private registry may pin what the command does not show",
                            "es": "un lockfile o registro privado puede fijar lo que el comando no muestra"},
        "mitigation": {"en": "pin versions (pkg@1.2.3, ==1.2.3, image@sha256), prefer reviewed local builds, https only",
                       "es": "fijar versiones (pkg@1.2.3, ==1.2.3, imagen@sha256), preferir builds locales revisados, solo https"},
        "limits": {"en": "the package's own content is not audited here (see the dependencies module)",
                   "es": "el contenido del paquete no se audita aquí (ver el módulo de dependencias)"},
    },
    "MCP05": {
        "name": "Command Injection & Execution",
        "cwe": "CWE-78",
        "inspects": {"en": "the body of every tool handler",
                     "es": "el cuerpo de cada manejador de herramienta"},
        "static": {"en": "shell=True, os.system, os.popen, eval/exec, child_process.exec, new Function, with tool parameters in the call",
                   "es": "shell=True, os.system, os.popen, eval/exec, child_process.exec, new Function, con parámetros de la herramienta en la llamada"},
        "confirm": {"en": "a parameter of the tool reaches a shell or eval call in the same function (Python, by ast)",
                    "es": "un parámetro de la herramienta llega a una llamada de shell o eval en la misma función (Python, por ast)"},
        "false_positives": {"en": "parameters validated against an allowlist before the call",
                            "es": "parámetros validados contra una lista permitida antes de la llamada"},
        "mitigation": {"en": "no shell; argument lists; allowlists of commands; run tools in a sandbox",
                       "es": "sin shell; listas de argumentos; listas permitidas de comandos; ejecutar herramientas en sandbox"},
        "limits": {"en": "flow is followed only inside the handler; JavaScript is matched by text",
                   "es": "el flujo solo se sigue dentro del manejador; JavaScript se reconoce por texto"},
    },
    "MCP06": {
        "name": "Prompt Injection via Contextual Payloads",
        "cwe": "CWE-1427",
        "inspects": {"en": "tools and resources that return content fetched from outside (HTTP, files, issues, mail)",
                     "es": "herramientas y recursos que devuelven contenido traído de fuera (HTTP, ficheros, issues, correo)"},
        "static": {"en": "fetch/read calls whose result is returned to the model with no marking or sanitising",
                   "es": "llamadas que traen o leen contenido y lo devuelven al modelo sin marcarlo ni sanearlo"},
        "confirm": {"en": "never statically: whether a payload steers the model needs a dynamic test",
                    "es": "nunca estáticamente: si una carga dirige al modelo requiere prueba dinámica"},
        "false_positives": {"en": "content the server itself produced",
                            "es": "contenido que produce el propio servidor"},
        "mitigation": {"en": "mark external content as data, strip instructions and invisible characters, require confirmation for actions that follow",
                       "es": "marcar el contenido externo como datos, quitar instrucciones y caracteres invisibles, pedir confirmación para las acciones posteriores"},
        "limits": {"en": "the content itself is not available until runtime",
                   "es": "el contenido en sí no existe hasta la ejecución"},
    },
    "MCP07": {
        "name": "Insufficient Authentication & Authorization",
        "cwe": "CWE-306",
        "inspects": {"en": "servers served over HTTP/SSE and the files that start them; remote servers in configs",
                     "es": "servidores servidos por HTTP/SSE y los ficheros que los arrancan; servidores remotos en configuraciones"},
        "static": {"en": "network transports with no auth marker in the file, binding to 0.0.0.0; remote servers configured with no credentials",
                   "es": "transportes de red sin rastro de autenticación en el fichero, escucha en 0.0.0.0; servidores remotos configurados sin credenciales"},
        "confirm": {"en": "never statically: auth may sit in a proxy or another module",
                    "es": "nunca estáticamente: la autenticación puede estar en un proxy u otro módulo"},
        "false_positives": {"en": "auth in middleware defined elsewhere, a gateway in front, loopback-only binding",
                            "es": "autenticación en un middleware de otro fichero, una pasarela delante, escucha solo en loopback"},
        "mitigation": {"en": "OAuth 2.1 as the MCP authorization spec describes, or bearer tokens validated per request; bind to loopback for local use",
                       "es": "OAuth 2.1 como describe la especificación de autorización de MCP, o tokens validados en cada petición; escuchar en loopback para uso local"},
        "limits": {"en": "stdio servers inherit the client's trust and are not flagged",
                   "es": "los servidores stdio heredan la confianza del cliente y no se marcan"},
    },
    "MCP08": {
        "name": "Lack of Audit and Telemetry",
        "cwe": "CWE-778",
        "inspects": {"en": "files that define MCP servers",
                     "es": "ficheros que definen servidores MCP"},
        "static": {"en": "no logging call or logger in a file that defines tools",
                   "es": "ningún logger ni llamada de log en un fichero que define herramientas"},
        "confirm": {"en": "never statically: logging may be configured by the host",
                    "es": "nunca estáticamente: el registro puede configurarlo el anfitrión"},
        "false_positives": {"en": "logging in a shared module or through the SDK's context",
                            "es": "registro en un módulo común o a través del contexto del SDK"},
        "mitigation": {"en": "log every tool call: caller, tool, arguments (redacted), result status",
                       "es": "registrar cada llamada: quién, qué herramienta, argumentos (redactados), resultado"},
        "limits": {"en": "whether logs are kept, read or alerted on is outside the repository",
                   "es": "si los logs se guardan, se leen o generan alertas queda fuera del repositorio"},
    },
    "MCP09": {
        "name": "Shadow MCP Servers",
        "cwe": "CWE-1059",
        "inspects": {"en": "server implementations against configs and docs; configs in unusual places; tunnel and raw-IP endpoints",
                     "es": "implementaciones de servidor frente a configuraciones y documentación; configuraciones en sitios inusuales; túneles e IPs"},
        "static": {"en": "servers no config or README mentions, nested agent configs, ngrok/tunnel/raw-IP URLs",
                   "es": "servidores que no menciona ninguna configuración ni README, configuraciones anidadas, URLs de túnel o IP"},
        "confirm": {"en": "never statically: an inventory outside the repository may list it",
                    "es": "nunca estáticamente: un inventario fuera del repositorio puede incluirlo"},
        "false_positives": {"en": "examples and test servers",
                            "es": "ejemplos y servidores de prueba"},
        "mitigation": {"en": "keep an inventory of approved servers; document each one; block unknown endpoints",
                       "es": "mantener un inventario de servidores aprobados; documentar cada uno; bloquear endpoints desconocidos"},
        "limits": {"en": "servers deployed outside the repository are not visible",
                   "es": "los servidores desplegados fuera del repositorio no son visibles"},
    },
    "MCP10": {
        "name": "Context Injection & Over-Sharing",
        "cwe": "CWE-200",
        "inspects": {"en": "tools and resources that read files, directories, databases or the environment",
                     "es": "herramientas y recursos que leen ficheros, directorios, bases de datos o el entorno"},
        "static": {"en": "paths taken from parameters with no confinement, file:// resource templates, recursive globs, SELECT *",
                   "es": "rutas tomadas de parámetros sin confinar, plantillas de recurso file://, globs recursivos, SELECT *"},
        "confirm": {"en": "a tool parameter reaches open()/read_text() with no resolve/relative_to check in the function (Python, by ast)",
                    "es": "un parámetro llega a open()/read_text() sin comprobación resolve/relative_to en la función (Python, por ast)"},
        "false_positives": {"en": "confinement done in a helper the handler calls",
                            "es": "confinamiento hecho en una función auxiliar a la que llama el manejador"},
        "mitigation": {"en": "confine paths to a root, return only the fields needed, never the environment",
                       "es": "confinar las rutas a una raíz, devolver solo los campos necesarios, nunca el entorno"},
        "limits": {"en": "what a session ends up sharing depends on the conversation, not visible here",
                   "es": "lo que una sesión acaba compartiendo depende de la conversación, no visible aquí"},
    },
}


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

CONFIG_NAMES = {".mcp.json", "mcp.json", "mcp_config.json", "mcp_settings.json",
                "claude_desktop_config.json", "cline_mcp_settings.json"}
STANDARD_CONFIG_DIRS = {"", ".vscode", ".cursor", ".claude", ".gemini", ".windsurf",
                        ".roo", ".kiro/settings", ".amazonq", ".codeium/windsurf"}
SETTINGS_FILES = re.compile(r"(^|/)\.(claude|gemini)/settings(\.local)?\.json$")

_PY_SERVER = re.compile(r"(?m)^\s*(from\s+(mcp\.server|fastmcp|mcp)\b[^\n]*import\s+[^\n]*"
                        r"(FastMCP|Server|MCPServer)|import\s+fastmcp\b)")
_PY_CLIENT = re.compile(r"(?m)^\s*from\s+mcp(\.client[\w.]*)?\s+import\s+[^\n]*"
                        r"(ClientSession|stdio_client|sse_client|streamablehttp_client)")
_JS_SERVER = re.compile(r"""@modelcontextprotocol/sdk/server|\bnew\s+McpServer\s*\(""")
_JS_CLIENT = re.compile(r"""@modelcontextprotocol/sdk/client""")
_JS_SUFFIXES = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")

_SECRET_KEY = re.compile(r"(?i)(token|secret|password|passwd|api[_\-]?key|apikey|auth|"
                         r"credential|private[_\-]?key|access[_\-]?key|cookie|session)")
_ENV_REF = re.compile(r"^\s*(\$\{[^}]*\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_]+%|\{\{[^}]*\}\}|<[^>]*>|)\s*$")
_URL_TOKEN = re.compile(r"(?i)[?&](token|key|api_?key|access_token|auth|secret)=([^&\s\"']{6,})")
_TUNNEL = re.compile(r"(?i)\b(ngrok(-free)?\.(io|app|dev)|trycloudflare\.com|loca\.lt|"
                     r"localtunnel\.me|serveo\.net|pinggy\.(io|link)|bore\.pub)\b")
_RAW_IP = re.compile(r"^https?://(\d{1,3}\.){3}\d{1,3}(:\d+)?(/|$)")
_LOCAL = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:\d+)?(/|$)")

# Instructions aimed at a model, as they show up in poisoned tool metadata.
# Narrower than the parallax regex: a tool description legitimately says
# "token", "file" or "agent".
_POISON = re.compile(
    r"(?i)(<\s*(important|system|secret|instructions?)\s*>|ignore (all |any |the )?"
    r"(previous|prior|above|other) (instructions|tools)|disregard (previous|prior|the)|"
    r"do not (tell|mention|inform|reveal|show)[^.]{0,30}(user|human)|"
    r"(without|don'?t|never) (telling|asking|informing|notifying) (the )?(user|human)|"
    r"before (using|calling) (this|any) tool,? (you )?(must|should|first)|"
    r"(read|send|include|pass|upload|post)[^.]{0,40}(~/\.ssh|id_rsa|\.env\b|mcp\.json|"
    r"credentials|\.aws/|private key)|exfiltrat|system prompt|"
    r"you (must|are required to) (always|first|also)|secretly|"
    r"ignora (las )?instrucciones|no (le )?(digas|informes) al usuario)")

MAX_DESCRIPTION = 1500


def _is_config(rel: str, text: str) -> bool:
    name = PurePosixPath(rel).name.lower()
    if name in CONFIG_NAMES or SETTINGS_FILES.search(rel):
        return True
    return name.endswith(".json") and '"mcpServers"' in text


def _lines(text: str) -> list[str]:
    return text.splitlines()


def _line_of(text: str, needle: str, start: int = 1) -> int | None:
    if not needle:
        return None
    for n, line in enumerate(_lines(text), 1):
        if n >= start and needle in line:
            return n
    return None


def _redact(line: str) -> str:
    """redact_line, plus tokens carried in a URL's query string."""
    line = _URL_TOKEN.sub(lambda m: m.group(0).replace(m.group(2), mask(m.group(2))), line)
    return redact_line(line)


def _snippet(text: str, line: int | None, span: int = 1) -> str:
    if not line:
        return ""
    lines = _lines(text)
    out = [_redact(l) for l in lines[line - 1:line - 1 + span]]
    return "\n".join(out).strip()


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def _finding(cat: str, rule: str, rel: str, text: str, line: int | None,
             severity: str, title: tuple[str, str], description: tuple[str, str],
             language: str, assessment: str = "potential", confidence: str = "medium",
             prerequisites: tuple[list, list] = ([], []), impact: tuple[str, str] = ("", ""),
             span: int = 1, artifact: str = "code", **extra) -> dict:
    es = language == "es"
    k = "es" if es else "en"
    meta = CATALOG[cat]
    snippet = _snippet(text, line, span)
    return {
        "category": "mcp",
        "file": rel,
        "anchor": f"{rule}:{extra.get('subject') or line or ''}",
        "severity": severity,
        "title": f"{cat}: {title[1] if es else title[0]}"[:255],
        "description": description[1] if es else description[0],
        "code_snippet": snippet,
        "line": line,
        "verification_status": "verified" if snippet else "unverified",
        "verification_note": "" if snippet else (
            "sin línea concreta que citar" if es else "no single line to quote"),
        "rule_id": rule,
        "detail": {
            "owasp_mcp": cat,
            "owasp_mcp_name": meta["name"],
            "owasp_version": OWASP_MCP_VERSION,
            "cwe": meta["cwe"],
            "scanner": f"mcp/{MCP_AUDIT_VERSION}",
            "artifact": artifact,
            "assessment": assessment,
            "confidence": confidence,
            "prerequisites": prerequisites[1] if es else prerequisites[0],
            "impact": impact[1] if es else impact[0],
            "mitigation": meta["mitigation"][k],
            "limits": meta["limits"][k],
            **{key: v for key, v in extra.items() if key != "subject"},
        },
    }


# ---------------------------------------------------------------------------
# Configurations
# ---------------------------------------------------------------------------

def _servers_of(data) -> dict:
    if not isinstance(data, dict):
        return {}
    servers = data.get("mcpServers") or data.get("servers")
    if not servers and isinstance(data.get("mcp"), dict):
        servers = data["mcp"].get("servers")
    return servers if isinstance(servers, dict) else {}


def _command_line(server: dict) -> str:
    cmd = server.get("command")
    args = server.get("args") if isinstance(server.get("args"), list) else []
    return " ".join(str(x) for x in ([cmd] if cmd else []) + args)


def _check_config(rel: str, text: str, language: str, inventory: dict) -> list[dict]:
    out = []
    data = _load_json(text)
    if data is None:
        return out
    parent = str(PurePosixPath(rel).parent)
    parent = "" if parent == "." else parent
    entry = {"file": rel, "servers": []}
    inventory["configs"].append(entry)

    # Agent settings: what gets enabled and approved without asking.
    if isinstance(data, dict) and data.get("enableAllProjectMcpServers") is True:
        line = _line_of(text, "enableAllProjectMcpServers")
        out.append(_finding(
            "MCP02", "mcp02.enable_all_project_servers", rel, text, line, "high",
            ("every MCP server of the project is enabled without asking",
             "todos los servidores MCP del proyecto se activan sin preguntar"),
            ("enableAllProjectMcpServers starts every server in .mcp.json, including one a "
             "contributor adds later, with no approval prompt.",
             "enableAllProjectMcpServers arranca todos los servidores de .mcp.json, también "
             "los que añada después un colaborador, sin pedir aprobación."),
            language, "confirmed", "high",
            (["someone adds or changes a server in .mcp.json"],
             ["que alguien añada o cambie un servidor en .mcp.json"]),
            ("code of their choice runs on every developer machine that opens the repo",
             "código elegido por ellos se ejecuta en cada máquina que abra el repositorio"),
            artifact="config"))
    perms = (data.get("permissions") or {}) if isinstance(data, dict) else {}
    for item in perms.get("allow") or [] if isinstance(perms, dict) else []:
        s = str(item)
        # mcp__* (every server), mcp__name or mcp__name__* (a whole server).
        if re.match(r"^mcp__(\*|[A-Za-z0-9\-]+(__\*)?)$", s):
            line = _line_of(text, s)
            out.append(_finding(
                "MCP02", "mcp02.wildcard_tool_permission", rel, text, line, "medium",
                (f"every tool of an MCP server is allowed without asking ({s})",
                 f"todas las herramientas de un servidor MCP permitidas sin preguntar ({s})"),
                ("A whole server, or every server, is allowed instead of named tools: a tool "
                 "added later is approved too.",
                 "Se permite un servidor entero, o todos, en vez de herramientas concretas: "
                 "una herramienta añadida después también queda aprobada."),
                language, "confirmed", "high", artifact="config", subject=s))

    for name, server in _servers_of(data).items():
        if not isinstance(server, dict):
            continue
        cmdline = _command_line(server)
        url = str(server.get("url") or server.get("serverUrl") or "")
        kind = "remote" if url else "stdio"
        entry["servers"].append({"name": str(name)[:100], "type": kind,
                                 "command": _redact(cmdline)[:200] if cmdline else None,
                                 "url": _redact(url)[:200] if url else None})
        inventory["config_servers"].add(str(name))
        nline = _line_of(text, f'"{name}"') or 1

        # MCP01: literal secrets in env, headers and the URL.
        for field in ("env", "headers"):
            values = server.get(field)
            if not isinstance(values, dict):
                continue
            for key, value in values.items():
                value = str(value)
                if _ENV_REF.match(value) or "${" in value or value.startswith("$"):
                    continue
                hits = scan_line(f'{key}="{value}"')
                looks_secret = _SECRET_KEY.search(str(key)) and len(value) >= 8 \
                    and not re.search(r"(?i)example|your|changeme|xxx|placeholder|<", value)
                if not hits and not looks_secret:
                    continue
                specific = any(h[3] for h in hits)
                line = _line_of(text, value, nline) or _line_of(text, value)
                # The snippet is masked; the value itself is never stored.
                f = _finding(
                    "MCP01", "mcp01.literal_secret_in_config", rel, text, line,
                    "high" if specific else "medium",
                    (f'credential written in the config of MCP server "{name}" ({field}.{key})',
                     f'credencial escrita en la configuración del servidor MCP "{name}" ({field}.{key})'),
                    ("A token is committed in the MCP configuration instead of referenced from "
                     "the environment. Revoke and rotate it.",
                     "Un token está publicado en la configuración MCP en vez de referenciado "
                     "desde el entorno. Revócalo y rótalo."),
                    language, "confirmed" if specific else "potential",
                    "high" if specific else "medium",
                    (["read access to the repository"], ["acceso de lectura al repositorio"]),
                    ("the server's credential, with whatever scopes it has",
                     "la credencial del servidor, con los permisos que tenga"),
                    artifact="config", subject=f"{name}.{field}.{key}", server=str(name))
                if line and value in _lines(text)[line - 1]:
                    f["code_snippet"] = _lines(text)[line - 1].replace(value, mask(value)).strip()
                out.append(f)
        for source in [url] + [str(a) for a in server.get("args") or []
                               if isinstance(server.get("args"), list)]:
            m = _URL_TOKEN.search(source)
            if m and not _ENV_REF.match(m.group(2)) and "${" not in m.group(2):
                line = _line_of(text, m.group(2))
                f = _finding(
                    "MCP01", "mcp01.token_in_url", rel, text, line, "high",
                    (f'token in the URL of MCP server "{name}"',
                     f'token en la URL del servidor MCP "{name}"'),
                    ("A token in a query string ends up in proxy logs, history and referrers.",
                     "Un token en la query acaba en logs de proxies, historiales y referrers."),
                    language, "confirmed", "high", artifact="config",
                    subject=f"{name}.url", server=str(name))
                if line:
                    f["code_snippet"] = _lines(text)[line - 1].replace(
                        m.group(2), mask(m.group(2))).strip()
                out.append(f)

        # MCP02: auto-approved tools, broad filesystem roots, dangerous flags.
        auto = server.get("autoApprove") or server.get("alwaysAllow")
        if isinstance(auto, list) and auto:
            risky = [str(t) for t in auto if re.search(
                r"(?i)write|exec|run|shell|command|delete|remove|push|deploy|create|edit|"
                r"update|send|post|\*", str(t))]
            line = _line_of(text, "autoApprove", nline) or _line_of(text, "alwaysAllow", nline)
            out.append(_finding(
                "MCP02", "mcp02.auto_approved_tools", rel, text, line,
                "high" if risky else "medium",
                (f'tools of MCP server "{name}" run without approval',
                 f'herramientas del servidor MCP "{name}" se ejecutan sin aprobación'),
                (f"Approved in advance: {', '.join(str(t) for t in auto[:10])}.",
                 f"Aprobadas de antemano: {', '.join(str(t) for t in auto[:10])}."),
                language, "confirmed", "high", artifact="config",
                subject=f"{name}.autoApprove", server=str(name), tools=[str(t) for t in auto[:20]]))
        if re.search(r"server-filesystem|mcp-server-filesystem|filesystem", cmdline):
            for arg in server.get("args") or []:
                if str(arg).strip() in ("/", "~", "~/", "$HOME", "${HOME}", "C:\\", "C:/", "/home",
                                        "/Users", "/root"):
                    line = _line_of(text, f'"{arg}"', nline)
                    out.append(_finding(
                        "MCP02", "mcp02.broad_filesystem_root", rel, text, line, "high",
                        (f'filesystem MCP server "{name}" can reach {arg}',
                         f'el servidor MCP de ficheros "{name}" alcanza {arg}'),
                        ("Rooted at the whole disk or the home directory: SSH keys, cloud "
                         "credentials and other projects are within reach of the model.",
                         "Con raíz en todo el disco o en el home: claves SSH, credenciales de "
                         "nube y otros proyectos quedan al alcance del modelo."),
                        language, "confirmed", "high", artifact="config",
                        subject=f"{name}.root", server=str(name)))
        flag = re.search(r"(?i)(--allow-all\b|--unsafe\b|--dangerously[\w-]*|--no-sandbox\b|"
                         r"--allow-write=?/\s|--disable-auth\b|--no-auth\b)", cmdline)
        if flag:
            line = _line_of(text, flag.group(1), nline)
            out.append(_finding(
                "MCP02", "mcp02.dangerous_flag", rel, text, line, "medium",
                (f'MCP server "{name}" started with {flag.group(1)}',
                 f'servidor MCP "{name}" arrancado con {flag.group(1)}'),
                ("A flag that widens what the server may do.",
                 "Un flag que amplía lo que el servidor puede hacer."),
                language, "confirmed", "medium", artifact="config",
                subject=f"{name}.flag", server=str(name)))

        # MCP04: how the server is fetched and launched.
        cmd = str(server.get("command") or "").rsplit("/", 1)[-1]
        args = [str(a) for a in server.get("args") or []] if isinstance(server.get("args"), list) else []
        pkg = None
        if cmd in ("npx", "bunx", "pnpx") or (cmd in ("pnpm", "yarn") and "dlx" in args):
            pkg = next((a for a in args if not a.startswith("-") and a not in ("dlx", "exec")), None)
            pinned = bool(pkg and re.search(r"[^@/]@\d", pkg)) and "@latest" not in (pkg or "")
        elif cmd in ("uvx", "pipx"):
            rest = [a for a in args if a not in ("run",)]
            pkg = next((a for a in rest if not a.startswith("-")), None)
            pinned = bool(pkg and "==" in pkg) or any(a.startswith("--from") and "==" in a
                                                      for a in rest)
        if pkg and not pinned:
            line = _line_of(text, pkg, nline)
            out.append(_finding(
                "MCP04", "mcp04.unpinned_package", rel, text, line, "medium",
                (f'MCP server "{name}" runs whatever version of {pkg} is current',
                 f'el servidor MCP "{name}" ejecuta la versión actual de {pkg}, sea cual sea'),
                (f"{cmd} downloads and runs the package at every launch; a compromised or "
                 f"hijacked release runs on the developer's machine with their access.",
                 f"{cmd} descarga y ejecuta el paquete en cada arranque; una versión "
                 f"comprometida se ejecuta en la máquina del desarrollador con su acceso."),
                language, "confirmed", "high",
                (["a malicious release of the package"], ["una versión maliciosa del paquete"]),
                ("code execution on every machine that starts the server",
                 "ejecución de código en cada máquina que arranque el servidor"),
                artifact="config", subject=f"{name}.package", server=str(name), package=pkg))
        if cmd == "docker" and "run" in args:
            image = next((a for a in args[args.index("run") + 1:]
                          if not a.startswith("-") and ("/" in a or ":" in a or "." in a
                                                        or a.isidentifier())), None)
            if image and "@sha256:" not in image and (":" not in image.rsplit("/", 1)[-1]
                                                     or image.endswith(":latest")):
                line = _line_of(text, image, nline)
                out.append(_finding(
                    "MCP04", "mcp04.unpinned_image", rel, text, line, "medium",
                    (f'MCP server "{name}" runs an unpinned image ({image})',
                     f'el servidor MCP "{name}" ejecuta una imagen sin fijar ({image})'),
                    ("Without a tag or digest, the image that runs can change at any time.",
                     "Sin tag ni digest, la imagen que se ejecuta puede cambiar en cualquier momento."),
                    language, "confirmed", "high", artifact="config",
                    subject=f"{name}.image", server=str(name)))
        if re.search(r"(curl|wget)[^|]*\|\s*(ba|z)?sh\b", cmdline):
            line = _line_of(text, "curl", nline) or _line_of(text, "wget", nline)
            out.append(_finding(
                "MCP04", "mcp04.pipe_to_shell", rel, text, line, "high",
                (f'MCP server "{name}" pipes a download into a shell',
                 f'el servidor MCP "{name}" pasa una descarga a una shell'),
                ("Whatever the URL serves at launch time runs.",
                 "Se ejecuta lo que sirva la URL al arrancar."),
                language, "confirmed", "high", artifact="config",
                subject=f"{name}.pipe", server=str(name)))
        if url.startswith("http://") and not _LOCAL.match(url):
            line = _line_of(text, url)
            out.append(_finding(
                "MCP04", "mcp04.plain_http_remote", rel, text, line, "high",
                (f'remote MCP server "{name}" over plain HTTP',
                 f'servidor MCP remoto "{name}" por HTTP sin cifrar'),
                ("Tool descriptions and results can be rewritten in transit.",
                 "Las descripciones y resultados de las herramientas pueden reescribirse por el camino."),
                language, "confirmed", "high", artifact="config",
                subject=f"{name}.http", server=str(name)))

        # MCP07: a remote server called with no credentials at all.
        if url and not _LOCAL.match(url) and not server.get("headers") \
                and not server.get("oauth") and not server.get("auth") \
                and not _URL_TOKEN.search(url):
            line = _line_of(text, url)
            out.append(_finding(
                "MCP07", "mcp07.remote_without_credentials", rel, text, line, "low",
                (f'remote MCP server "{name}" configured with no credentials',
                 f'servidor MCP remoto "{name}" configurado sin credenciales'),
                ("Either it is public, or it authenticates through an OAuth flow the client "
                 "starts. If neither, anyone can call it.",
                 "O es público, o se autentica con un flujo OAuth que inicia el cliente. "
                 "Si no es ninguna de las dos, cualquiera puede llamarlo."),
                language, "potential", "low", artifact="config",
                subject=f"{name}.auth", server=str(name)))

        # MCP09: endpoints nobody can account for.
        if url and (_TUNNEL.search(url) or _RAW_IP.match(url)) and not _LOCAL.match(url):
            line = _line_of(text, url)
            out.append(_finding(
                "MCP09", "mcp09.tunnel_or_raw_ip", rel, text, line, "medium",
                (f'MCP server "{name}" behind a tunnel or a raw IP',
                 f'servidor MCP "{name}" detrás de un túnel o una IP'),
                ("Temporary tunnels and bare IPs are what a server outside any inventory looks "
                 "like; whoever controls the endpoint controls the tools.",
                 "Los túneles temporales y las IPs sueltas son el aspecto de un servidor fuera "
                 "de todo inventario; quien controla el endpoint controla las herramientas."),
                language, "potential", "medium", artifact="config",
                subject=f"{name}.endpoint", server=str(name)))

    if _servers_of(data) and parent not in STANDARD_CONFIG_DIRS:
        out.append(_finding(
            "MCP09", "mcp09.nested_config", rel, text, 1, "low",
            ("MCP configuration in an unusual place",
             "configuración MCP en un sitio inusual"),
            ("An agent opened in this directory loads these servers, and nobody reviewing "
             "the root configuration sees them.",
             "Un agente abierto en este directorio carga estos servidores, y quien revise la "
             "configuración de la raíz no los ve."),
            language, "potential", "medium", artifact="config"))
    return out


# ---------------------------------------------------------------------------
# Python servers, by ast
# ---------------------------------------------------------------------------

_KIND_ATTRS = {"tool": "tool", "resource": "resource", "prompt": "prompt",
               "call_tool": "dispatcher", "read_resource": "dispatcher",
               "get_prompt": "dispatcher"}
_EXEC_CALLS = {"system", "popen", "eval", "exec", "execfile", "spawn", "getoutput",
               "getstatusoutput"}
_SUBPROCESS = {"run", "call", "check_call", "check_output", "Popen"}
_FETCH = re.compile(r"\b(requests|httpx|aiohttp|urllib\.request|urlopen|session)\.?"
                    r"(get|post|request|urlopen|fetch)?\b")
_CONFINE = re.compile(r"\b(resolve|relative_to|is_relative_to|commonpath|realpath|"
                      r"abspath|startswith|safe_join|secure_filename)\b")
_SANITIZE = re.compile(r"(?i)untrusted|sanitiz|escape|strip_instructions|<data>|"
                       r"quote_as_data|bleach")
_LOGGING_PY = re.compile(r"\b(logging\.|logger\.|log\.(info|warning|error|debug)|"
                         r"structlog|ctx\.(info|debug|warning|error|log)|"
                         r"loguru|print\(.*file=sys\.stderr)")


def _const_str(node) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _decorator_kind(dec) -> tuple[str | None, ast.Call | None]:
    call = dec if isinstance(dec, ast.Call) else None
    target = dec.func if call else dec
    if isinstance(target, ast.Attribute) and target.attr in _KIND_ATTRS:
        return _KIND_ATTRS[target.attr], call
    return None, None


def _names_in(node) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def python_tools(rel: str, text: str) -> list[dict]:
    """Every tool, resource, prompt or dispatcher a Python MCP server defines."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return []
    tools = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                kind, call = _decorator_kind(dec)
                if not kind:
                    continue
                desc, dynamic, name = None, False, node.name
                for kw in (call.keywords if call else []):
                    if kw.arg == "description":
                        desc = _const_str(kw.value)
                        dynamic = desc is None
                    elif kw.arg == "name" and _const_str(kw.value):
                        name = _const_str(kw.value)
                if call and call.args and kind == "resource":
                    uri = _const_str(call.args[0])
                    if uri:
                        name = uri
                if desc is None and not dynamic:
                    desc = ast.get_docstring(node, clean=False)
                params = [a.arg for a in node.args.args + node.args.kwonlyargs
                          if a.arg not in ("self", "ctx", "context")]
                tools.append({"file": rel, "name": name, "kind": kind, "line": node.lineno,
                              "end": getattr(node, "end_lineno", node.lineno),
                              "description": desc or "", "dynamic_description": dynamic,
                              "params": params, "node": node, "language": "python"})
        elif isinstance(node, ast.Call):
            func = node.func
            fname = func.attr if isinstance(func, ast.Attribute) else \
                func.id if isinstance(func, ast.Name) else None
            if fname in ("Tool", "Resource", "Prompt"):
                kw = {k.arg: k.value for k in node.keywords}
                name = _const_str(kw.get("name")) or _const_str(kw.get("uri"))
                if name is None:
                    continue
                desc = _const_str(kw.get("description"))
                tools.append({"file": rel, "name": name, "kind": fname.lower(),
                              "line": node.lineno, "end": node.lineno,
                              "description": desc or "",
                              "dynamic_description": "description" in kw and desc is None,
                              "params": [], "node": None, "language": "python"})
    return tools


def _python_body_checks(t: dict, rel: str, text: str, language: str) -> list[dict]:
    node = t["node"]
    if node is None:
        return []
    out = []
    params = set(t["params"])
    body_src = "\n".join(_lines(text)[t["line"] - 1:t["end"]])
    for call in [n for n in ast.walk(node) if isinstance(n, ast.Call)]:
        func = call.func
        attr = func.attr if isinstance(func, ast.Attribute) else \
            func.id if isinstance(func, ast.Name) else ""
        owner = func.value.id if isinstance(func, ast.Attribute) and \
            isinstance(func.value, ast.Name) else ""
        arg_names = set()
        for a in list(call.args) + [k.value for k in call.keywords]:
            arg_names |= _names_in(a)
        tainted = bool(params & arg_names)
        shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant)
                    and k.value.value is True for k in call.keywords)
        is_exec = (attr in _EXEC_CALLS and owner in ("os", "", "builtins", "commands",
                                                     "subprocess")) \
            or (owner == "subprocess" and attr in _SUBPROCESS and shell) \
            or (attr in ("eval", "exec") and owner == "")
        if is_exec:
            out.append(_finding(
                "MCP05", "mcp05.exec_in_tool", rel, text, call.lineno,
                "critical" if tainted else "high",
                (f'tool "{t["name"]}" runs a shell or evaluates code'
                 + (" with its parameters" if tainted else ""),
                 f'la herramienta "{t["name"]}" ejecuta una shell o evalúa código'
                 + (" con sus parámetros" if tainted else "")),
                ("Arguments the model chooses — and so whoever steers the model — reach "
                 f"{owner + '.' if owner else ''}{attr}().",
                 "Argumentos que elige el modelo — y por tanto quien lo dirija — llegan a "
                 f"{owner + '.' if owner else ''}{attr}()."),
                language, "confirmed" if tainted else "potential",
                "high" if tainted else "medium",
                (["the model calls the tool with chosen arguments (prompt injection suffices)"],
                 ["que el modelo llame a la herramienta con argumentos elegidos (basta una inyección de prompt)"]),
                ("command execution with the server's privileges",
                 "ejecución de comandos con los privilegios del servidor"),
                subject=f"{t['name']}.{attr}", tool=t["name"], tainted=tainted))
        if attr in ("open", "read_text", "read_bytes", "send_file", "FileResponse") and tainted \
                and not _CONFINE.search(body_src):
            out.append(_finding(
                "MCP10", "mcp10.unconfined_path", rel, text, call.lineno, "high",
                (f'tool "{t["name"]}" reads a path it is given, with no confinement',
                 f'la herramienta "{t["name"]}" lee la ruta que recibe, sin confinarla'),
                ("Any file the server can read — keys, .env, other projects — can be pulled "
                 "into the conversation.",
                 "Cualquier fichero que pueda leer el servidor — claves, .env, otros proyectos — "
                 "puede acabar en la conversación."),
                language, "confirmed", "high",
                (["the model calls the tool with a chosen path"],
                 ["que el modelo llame a la herramienta con una ruta elegida"]),
                ("disclosure of files outside the intended root",
                 "revelación de ficheros fuera de la raíz prevista"),
                subject=f"{t['name']}.path", tool=t["name"], cwe_override="CWE-22"))
    if re.search(r"\b(dict\(os\.environ\)|os\.environ\.copy\(\)|return\s+os\.environ\b|"
                 r"json\.dumps\(\s*(dict\()?os\.environ)", body_src):
        line = t["line"] + next((i for i, l in enumerate(body_src.splitlines())
                                 if "os.environ" in l), 0)
        out.append(_finding(
            "MCP01", "mcp01.environment_exposed", rel, text, line, "high",
            (f'tool "{t["name"]}" hands the whole environment to the model',
             f'la herramienta "{t["name"]}" entrega todo el entorno al modelo'),
            ("Every credential in the server's environment reaches the conversation and "
             "whatever the model does next.",
             "Todas las credenciales del entorno del servidor llegan a la conversación y a lo "
             "que haga el modelo después."),
            language, "confirmed", "high", subject=f"{t['name']}.environ", tool=t["name"]))
    if _FETCH.search(body_src) and re.search(r"\.(get|post|request|urlopen)\(|urlopen\(", body_src) \
            and not _SANITIZE.search(body_src):
        line = t["line"] + next((i for i, l in enumerate(body_src.splitlines())
                                 if re.search(r"\.(get|post|request)\(|urlopen\(", l)), 0)
        out.append(_finding(
            "MCP06", "mcp06.external_content_unmarked", rel, text, line, "medium",
            (f'tool "{t["name"]}" returns fetched content to the model as is',
             f'la herramienta "{t["name"]}" devuelve al modelo contenido descargado tal cual'),
            ("Whoever writes that content can write instructions into the model's context.",
             "Quien escriba ese contenido puede meter instrucciones en el contexto del modelo."),
            language, "unverifiable", "low",
            (["an attacker controls the fetched content"],
             ["que un atacante controle el contenido descargado"]),
            ("the model follows instructions from the content",
             "el modelo sigue instrucciones del contenido"),
            subject=f"{t['name']}.fetch", tool=t["name"], needs_dynamic_test=True))
    if re.search(r"(?i)select\s+\*\s+from", body_src):
        line = t["line"] + next((i for i, l in enumerate(body_src.splitlines())
                                 if re.search(r"(?i)select\s+\*", l)), 0)
        out.append(_finding(
            "MCP10", "mcp10.select_star", rel, text, line, "low",
            (f'tool "{t["name"]}" returns whole rows (SELECT *)',
             f'la herramienta "{t["name"]}" devuelve filas enteras (SELECT *)'),
            ("Every column, including ones the task does not need, reaches the model.",
             "Todas las columnas, también las que la tarea no necesita, llegan al modelo."),
            language, "potential", "low", subject=f"{t['name']}.select", tool=t["name"]))
    if re.search(r"""(glob\(\s*["'][^"']*\*\*|os\.walk\(\s*["'](/|~)|rglob\()""", body_src):
        line = t["line"] + next((i for i, l in enumerate(body_src.splitlines())
                                 if re.search(r"glob\(|os\.walk\(", l)), 0)
        out.append(_finding(
            "MCP10", "mcp10.recursive_listing", rel, text, line, "medium",
            (f'tool "{t["name"]}" lists files recursively',
             f'la herramienta "{t["name"]}" lista ficheros de forma recursiva'),
            ("Recursive listings pull far more of the disk into the context than a task needs.",
             "Los listados recursivos meten en el contexto mucho más disco del que necesita una tarea."),
            language, "potential", "medium", subject=f"{t['name']}.glob", tool=t["name"]))
    return out


# ---------------------------------------------------------------------------
# JavaScript / TypeScript servers, by text
# ---------------------------------------------------------------------------

_JS_TOOL = re.compile(
    r"""\.(tool|registerTool|resource|registerResource|prompt|registerPrompt)\(\s*"""
    r"""(["'`])([^"'`]{1,200})\2\s*,\s*(?:(["'`])((?:(?!\4).){0,4000})\4|\{[^}]*?description\s*:\s*(["'`])((?:(?!\6).){0,4000})\6)?""",
    re.S)
_JS_TOOL_OBJ = re.compile(
    r"""\{\s*name\s*:\s*(["'`])([\w\-.]{1,100})\1\s*,\s*description\s*:\s*(["'`])((?:(?!\3).){0,4000})\3""",
    re.S)
_JS_EXEC = re.compile(r"""\b(exec|execSync|spawn|spawnSync|execFile)\s*\(|\beval\s*\(|new\s+Function\s*\(""")
_LOGGING_JS = re.compile(r"\b(console\.(error|log|warn|info)|logger\.|pino|winston|bunyan|"
                         r"sendLoggingMessage|log\()")


def js_tools(rel: str, text: str) -> list[dict]:
    out = []
    for m in _JS_TOOL.finditer(text):
        kind = m.group(1).replace("register", "").lower()
        line = text.count("\n", 0, m.start()) + 1
        out.append({"file": rel, "name": m.group(3), "kind": kind, "line": line, "end": line,
                    "description": m.group(5) or m.group(7) or "",
                    "dynamic_description": False, "params": [], "node": None,
                    "language": "javascript", "offset": m.start()})
    for m in _JS_TOOL_OBJ.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        if any(t["line"] == line for t in out):
            continue
        out.append({"file": rel, "name": m.group(2), "kind": "tool", "line": line, "end": line,
                    "description": m.group(4), "dynamic_description": False, "params": [],
                    "node": None, "language": "javascript", "offset": m.start()})
    return out


def _js_checks(rel: str, text: str, tools: list[dict], language: str) -> list[dict]:
    out = []
    starts = sorted(t["offset"] for t in tools)
    for t in tools:
        nxt = next((s for s in starts if s > t["offset"]), len(text))
        body = text[t["offset"]:nxt]
        for m in _JS_EXEC.finditer(body):
            stmt = body[m.start():m.start() + 300].split(";")[0]
            interpolated = "${" in stmt or "+" in stmt
            line = text.count("\n", 0, t["offset"] + m.start()) + 1
            out.append(_finding(
                "MCP05", "mcp05.exec_in_tool", rel, text, line,
                "high" if interpolated else "medium",
                (f'tool "{t["name"]}" runs a command or evaluates code',
                 f'la herramienta "{t["name"]}" ejecuta un comando o evalúa código'),
                ("A child process or eval inside a tool handler"
                 + (", built from interpolated values." if interpolated else "."),
                 "Un proceso hijo o un eval dentro del manejador de una herramienta"
                 + (", construido con valores interpolados." if interpolated else ".")),
                language, "potential", "medium" if interpolated else "low",
                (["the model calls the tool with chosen arguments"],
                 ["que el modelo llame a la herramienta con argumentos elegidos"]),
                ("command execution with the server's privileges",
                 "ejecución de comandos con los privilegios del servidor"),
                subject=f"{t['name']}.{m.group(0)[:12]}", tool=t["name"]))
        if re.search(r"JSON\.stringify\(\s*process\.env\s*\)|return\s+process\.env\b|"
                     r"text:\s*JSON\.stringify\(process\.env", body):
            line = text.count("\n", 0, t["offset"] + body.find("process.env")) + 1
            out.append(_finding(
                "MCP01", "mcp01.environment_exposed", rel, text, line, "high",
                (f'tool "{t["name"]}" hands the whole environment to the model',
                 f'la herramienta "{t["name"]}" entrega todo el entorno al modelo'),
                ("Every credential in the server's environment reaches the conversation.",
                 "Todas las credenciales del entorno del servidor llegan a la conversación."),
                language, "confirmed", "high", subject=f"{t['name']}.environ", tool=t["name"]))
        if re.search(r"\b(readFile|readFileSync|createReadStream)\s*\(", body) \
                and not _CONFINE.search(body) and re.search(r"\b(path|file|filename)\b", body):
            line = text.count("\n", 0, t["offset"] + re.search(
                r"\b(readFile|readFileSync|createReadStream)\s*\(", body).start()) + 1
            out.append(_finding(
                "MCP10", "mcp10.unconfined_path", rel, text, line, "medium",
                (f'tool "{t["name"]}" reads files with no visible confinement',
                 f'la herramienta "{t["name"]}" lee ficheros sin confinamiento visible'),
                ("No resolve/startsWith check appears before the read.",
                 "No aparece ninguna comprobación resolve/startsWith antes de la lectura."),
                language, "potential", "low", subject=f"{t['name']}.path", tool=t["name"],
                cwe_override="CWE-22"))
        if re.search(r"\bfetch\s*\(|axios\.|got\(|https?\.get\(", body) and not _SANITIZE.search(body):
            line = text.count("\n", 0, t["offset"] + re.search(
                r"\bfetch\s*\(|axios\.|got\(|https?\.get\(", body).start()) + 1
            out.append(_finding(
                "MCP06", "mcp06.external_content_unmarked", rel, text, line, "medium",
                (f'tool "{t["name"]}" returns fetched content to the model as is',
                 f'la herramienta "{t["name"]}" devuelve al modelo contenido descargado tal cual'),
                ("Whoever writes that content can write instructions into the model's context.",
                 "Quien escriba ese contenido puede meter instrucciones en el contexto del modelo."),
                language, "unverifiable", "low", subject=f"{t['name']}.fetch", tool=t["name"],
                needs_dynamic_test=True))
    return out


# ---------------------------------------------------------------------------
# Every tool: its metadata (MCP03)
# ---------------------------------------------------------------------------

def _metadata_checks(t: dict, text: str, language: str) -> list[dict]:
    out = []
    rel, desc = t["file"], t["description"] or ""
    hidden = invisible_runs(desc) + invisible_runs(t["name"] or "")
    if hidden:
        decoded = "".join(r["decoded"] or "" for r in hidden)[:200]
        out.append(_finding(
            "MCP03", "mcp03.invisible_characters", rel, text, t["line"], "high",
            (f'{t["kind"]} "{t["name"]}" hides invisible characters in its metadata',
             f'{t["kind"]} "{t["name"]}" esconde caracteres invisibles en sus metadatos'),
            ("The model reads characters the person approving the tool cannot see"
             + (f" — they spell: {decoded}" if decoded else "."),
             "El modelo lee caracteres que quien aprueba la herramienta no puede ver"
             + (f" — dicen: {decoded}" if decoded else ".")),
            language, "confirmed", "high",
            (["the server is installed and its tools listed to the model"],
             ["que se instale el servidor y se listen sus herramientas al modelo"]),
            ("the model follows hidden instructions", "el modelo sigue instrucciones ocultas"),
            artifact="tool_metadata", subject=f"{t['name']}.invisible", tool=t["name"]))
    m = _POISON.search(desc)
    if m:
        offset = text.find(m.group(0))
        line = text.count("\n", 0, offset) + 1 if offset >= 0 else t["line"]
        out.append(_finding(
            "MCP03", "mcp03.instructions_in_description", rel, text, line, "high",
            (f'{t["kind"]} "{t["name"]}" carries instructions for the model',
             f'{t["kind"]} "{t["name"]}" lleva instrucciones para el modelo'),
            (f'Its description says: "{m.group(0)[:120]}". Tool descriptions go straight into '
             "the model's context; this reads as an order, not a description.",
             f'Su descripción dice: "{m.group(0)[:120]}". Las descripciones entran directas en '
             "el contexto del modelo; esto se lee como una orden, no como una descripción."),
            language, "potential", "medium",
            (["the server is installed and its tools listed to the model"],
             ["que se instale el servidor y se listen sus herramientas al modelo"]),
            ("the model acts against the user: reads files, calls other tools, hides it",
             "el modelo actúa contra el usuario: lee ficheros, llama a otras herramientas, lo oculta"),
            artifact="tool_metadata", subject=f"{t['name']}.poison", tool=t["name"]))
    if len(desc) > MAX_DESCRIPTION:
        out.append(_finding(
            "MCP03", "mcp03.oversized_description", rel, text, t["line"], "low",
            (f'{t["kind"]} "{t["name"]}" has a {len(desc)}-character description',
             f'{t["kind"]} "{t["name"]}" tiene una descripción de {len(desc)} caracteres'),
            ("Long descriptions are where hidden instructions go unnoticed by a reviewer.",
             "Las descripciones largas son donde las instrucciones pasan desapercibidas."),
            language, "potential", "low", artifact="tool_metadata",
            subject=f"{t['name']}.length", tool=t["name"]))
    if t.get("dynamic_description"):
        out.append(_finding(
            "MCP03", "mcp03.dynamic_description", rel, text, t["line"], "low",
            (f'{t["kind"]} "{t["name"]}" builds its description at runtime',
             f'{t["kind"]} "{t["name"]}" construye su descripción en ejecución'),
            ("What the model is told can change after the tool was reviewed (rug pull).",
             "Lo que se le dice al modelo puede cambiar después de revisar la herramienta (rug pull)."),
            language, "potential", "low", artifact="tool_metadata",
            subject=f"{t['name']}.dynamic", tool=t["name"]))
    return out


# ---------------------------------------------------------------------------
# Server files: transport, auth, logging (MCP07, MCP08)
# ---------------------------------------------------------------------------

_NET_TRANSPORT = re.compile(
    r"""(transport\s*=\s*["'](sse|streamable-http|http)["']|\.run\(\s*["'](sse|streamable-http|http)["']|"""
    r"""sse_app\(|streamable_http_app\(|run_sse_async|SSEServerTransport|"""
    r"""StreamableHTTPServerTransport|http_app\()""")
_AUTH_MARK = re.compile(r"(?i)(auth|bearer|authorization|token_verifier|oauth|api[_-]?key|"
                        r"requireBearerAuth|verify_token|jwt|x-api-key|basicauth)")
_ALL_INTERFACES = re.compile(r"""(host\s*=\s*["']0\.0\.0\.0["']|listen\([^)]*["']0\.0\.0\.0["']|"""
                             r"""--host[= ]0\.0\.0\.0)""")


def _server_checks(rel: str, text: str, tools: list[dict], language: str) -> list[dict]:
    out = []
    m = _NET_TRANSPORT.search(text)
    if m and not _AUTH_MARK.search(text):
        line = text.count("\n", 0, m.start()) + 1
        exposed = bool(_ALL_INTERFACES.search(text))
        out.append(_finding(
            "MCP07", "mcp07.network_server_without_auth", rel, text, line,
            "high" if exposed else "medium",
            ("MCP server served over the network with no sign of authentication",
             "servidor MCP servido por red sin rastro de autenticación"),
            ("The file starts an HTTP/SSE transport and mentions no token, OAuth or auth "
             "check" + (", listening on every interface." if exposed else "."),
             "El fichero arranca un transporte HTTP/SSE y no menciona ningún token, OAuth ni "
             "comprobación de autenticación" + (", escuchando en todas las interfaces."
                                                if exposed else ".")),
            language, "potential", "medium" if exposed else "low",
            (["network access to the port"], ["acceso de red al puerto"]),
            ("anyone who reaches it can call every tool",
             "cualquiera que llegue puede llamar a todas las herramientas"),
            artifact="server", subject="transport", transport=m.group(0)[:60]))
    has_tools = any(t["kind"] in ("tool", "dispatcher") for t in tools)
    logging_re = _LOGGING_PY if rel.endswith(".py") else _LOGGING_JS
    if has_tools and not logging_re.search(text):
        out.append(_finding(
            "MCP08", "mcp08.no_logging", rel, text, tools[0]["line"], "low",
            ("tool calls are not logged in this server",
             "las llamadas a herramientas no se registran en este servidor"),
            ("No logger or log call in the file that defines the tools: a misuse leaves no "
             "trace to investigate.",
             "Ningún logger ni llamada de log en el fichero que define las herramientas: un "
             "mal uso no deja rastro que investigar."),
            language, "potential", "low", artifact="server", subject="logging"))
    return out


# ---------------------------------------------------------------------------
# All of it
# ---------------------------------------------------------------------------

def analyze(texts: dict[str, str], language: str = "en") -> dict:
    """The MCP inventory of a checkout and the findings against OWASP MCP Top 10."""
    inventory = {"servers": [], "clients": [], "configs": [], "tools": [],
                 "config_servers": set()}
    findings: list[dict] = []
    server_files = []
    for rel in sorted(texts):
        text = texts[rel]
        low = rel.lower()
        if low.endswith(".json") and _is_config(rel, text):
            findings += _check_config(rel, text, language, inventory)
            continue
        tools = []
        if low.endswith(".py") and ("mcp" in text or "fastmcp" in text):
            if _PY_SERVER.search(text) or re.search(r"@\w+\.tool\(", text):
                tools = python_tools(rel, text)
                if tools or _PY_SERVER.search(text):
                    server_files.append(rel)
                    inventory["servers"].append({"file": rel, "language": "python",
                                                 "tools": len(tools)})
            if _PY_CLIENT.search(text):
                inventory["clients"].append({"file": rel, "language": "python",
                                             "line": _line_of(text, "import")})
        elif low.endswith(_JS_SUFFIXES) and "modelcontextprotocol" in text or \
                (low.endswith(_JS_SUFFIXES) and "McpServer" in text):
            if _JS_SERVER.search(text):
                tools = js_tools(rel, text)
                server_files.append(rel)
                inventory["servers"].append({"file": rel, "language": "javascript",
                                             "tools": len(tools)})
            if _JS_CLIENT.search(text):
                inventory["clients"].append({"file": rel, "language": "javascript",
                                             "line": _line_of(text, "modelcontextprotocol")})
        if not tools and rel not in server_files:
            continue
        for t in tools:
            inventory["tools"].append({"file": rel, "name": t["name"], "kind": t["kind"],
                                       "line": t["line"], "language": t["language"],
                                       "description_chars": len(t["description"] or "")})
            findings += _metadata_checks(t, text, language)
            if t["language"] == "python":
                findings += _python_body_checks(t, rel, text, language)
            if t["kind"] == "resource" and re.match(r"^file://", t["name"] or "") \
                    and "{" in (t["name"] or ""):
                findings.append(_finding(
                    "MCP10", "mcp10.file_resource_template", rel, text, t["line"], "medium",
                    (f'resource template {t["name"]} serves any file',
                     f'la plantilla de recurso {t["name"]} sirve cualquier fichero'),
                    ("A file:// template with a free path is a read of whatever path is asked.",
                     "Una plantilla file:// con ruta libre es leer la ruta que se pida."),
                    language, "potential", "medium", subject=f"{t['name']}.template",
                    tool=t["name"]))
        if any(t["language"] == "javascript" for t in tools):
            findings += _js_checks(rel, text, tools, language)
        findings += _server_checks(rel, text, tools, language)

    # MCP09: servers in the code that no config and no README accounts for.
    docs = "\n".join(t for r, t in texts.items()
                     if re.search(r"(?i)(^|/)(readme|docs?/)[^/]*", r) or r.lower().endswith(".md"))
    configs = "\n".join(t for r, t in texts.items() if _is_config(r, t))
    for rel in server_files:
        stem = PurePosixPath(rel).stem
        module = rel[:-3].replace("/", ".") if rel.endswith(".py") else rel
        names = {rel, module, PurePosixPath(rel).name,
                 stem if stem not in ("server", "index", "main", "app", "mcp") else None}
        mentioned = any(re.search(rf"(?<![\w.-]){re.escape(x)}(?![\w-])", configs + docs)
                        for x in names if x)
        if not mentioned:
            findings.append(_finding(
                "MCP09", "mcp09.undeclared_server", rel, texts[rel], 1, "low",
                ("MCP server that no configuration or documentation mentions",
                 "servidor MCP que no menciona ninguna configuración ni documentación"),
                ("Nothing in the repository declares this server; it may be running where "
                 "nobody keeps track of it.",
                 "Nada en el repositorio declara este servidor; puede estar ejecutándose donde "
                 "nadie lo controla."),
                language, "potential", "low", artifact="server"))
    # Two tools with one name: the model cannot tell which it is calling.
    names: dict[str, list] = {}
    for t in inventory["tools"]:
        if t["kind"] == "tool":
            names.setdefault(t["name"], []).append(t)
    for name, same in names.items():
        if len({t["file"] for t in same}) > 1:
            t = same[1]
            findings.append(_finding(
                "MCP03", "mcp03.tool_name_collision", t["file"], texts[t["file"]], t["line"],
                "low", (f'tool name "{name}" is defined by more than one server',
                        f'el nombre de herramienta "{name}" lo definen varios servidores'),
                ("A server can shadow another's tool by reusing its name.",
                 "Un servidor puede suplantar la herramienta de otro reutilizando su nombre."),
                language, "potential", "low", subject=f"{name}.collision", tool=name,
                also_in=[x["file"] for x in same]))

    for f in findings:
        cwe = f["detail"].pop("cwe_override", None)
        if cwe:
            f["detail"]["cwe"] = cwe
    by_cat: dict[str, int] = {}
    for f in findings:
        c = f["detail"]["owasp_mcp"]
        by_cat[c] = by_cat.get(c, 0) + 1
    inventory["config_servers"] = sorted(inventory["config_servers"])
    detected = bool(inventory["servers"] or inventory["clients"] or inventory["configs"])
    return {"findings": findings[:300], "inventory": inventory, "by_category": by_cat,
            "detected": detected, "version": MCP_AUDIT_VERSION,
            "taxonomy": {"name": OWASP_MCP_VERSION, "url": OWASP_MCP_URL,
                         "checked": OWASP_MCP_CHECKED}}


def catalog(language: str = "en") -> list[dict]:
    """The rule catalogue, per category, in one language."""
    k = "es" if language == "es" else "en"
    return [{"id": cid, "name": c["name"], "cwe": c["cwe"],
             **{field: c[field][k] for field in ("inspects", "static", "confirm",
                                                 "false_positives", "mitigation", "limits")}}
            for cid, c in CATALOG.items()]


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: python3 -m analysis.mcp_audit <directory>", file=sys.stderr)
        return 2
    from .parallax import repository_texts
    result = analyze(repository_texts(Path(argv[0])))
    json.dump(result, sys.stdout, indent=2, ensure_ascii=False, default=str)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
