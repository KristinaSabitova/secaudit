#!/usr/bin/env python3
"""
domainaudit — auditoría defensiva de dominios y subdominios.

Herramienta de superficie de ataque para dominios que TÚ controlas. Detecta
configuraciones débiles y vulnerabilidades expuestas sin tocar el código:
enumera subdominios, revisa DNS, TLS/certificados, cabeceras HTTP, seguridad
de correo (SPF/DKIM/DMARC), riesgo de secuestro de subdominio y puertos.

Sin dependencias externas: solo la librería estándar de Python 3.9+.
Las consultas DNS usan DNS-over-HTTPS (Google / Cloudflare), así que funciona
en cualquier máquina con salida HTTPS, sin resolver local ni dnspython.

Uso básico:
    domainaudit ejemplo.com
    domainaudit ejemplo.com --subdomains            # enumera y audita subdominios (CT logs)
    domainaudit ejemplo.com --subdomains --brute    # + fuerza bruta con diccionario interno
    domainaudit ejemplo.com --full                  # todo, incluye escaneo de puertos
    domainaudit ejemplo.com --json -o informe.json
    domainaudit ejemplo.com --md   -o informe.md

Autorización:
    Solo audita dominios que poseas o tengas permiso explícito para probar.
    El escaneo de puertos y la fuerza bruta son activos: se piden confirmación
    salvo que pases --yes.
"""

import argparse
import concurrent.futures
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Modelo de hallazgos
# ---------------------------------------------------------------------------

SEVERITIES = ["critical", "high", "medium", "low", "info"]
_SEV_ORDER = {s: i for i, s in enumerate(SEVERITIES)}

# Peso para la puntuación de riesgo agregada.
_SEV_WEIGHT = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}


@dataclass
class Finding:
    severity: str          # critical/high/medium/low/info
    category: str          # dns/tls/headers/email/takeover/ports/exposure
    target: str            # host o dominio afectado
    title: str
    detail: str
    fix: str = ""


@dataclass
class HostReport:
    host: str
    resolved: bool = False
    addresses: list = field(default_factory=list)
    findings: list = field(default_factory=list)

    def add(self, sev, cat, title, detail, fix=""):
        self.findings.append(Finding(sev, cat, self.host, title, detail, fix))


# ---------------------------------------------------------------------------
# Salida en color (solo si es TTY)
# ---------------------------------------------------------------------------

class C:
    RED = "\033[31m"; YEL = "\033[33m"; BLU = "\033[34m"
    GRN = "\033[32m"; DIM = "\033[2m"; BOLD = "\033[1m"; OFF = "\033[0m"

    @classmethod
    def disable(cls):
        for k in ("RED", "YEL", "BLU", "GRN", "DIM", "BOLD", "OFF"):
            setattr(cls, k, "")


_SEV_COLOR = {
    "critical": lambda s: f"{C.BOLD}{C.RED}{s}{C.OFF}",
    "high":     lambda s: f"{C.RED}{s}{C.OFF}",
    "medium":   lambda s: f"{C.YEL}{s}{C.OFF}",
    "low":      lambda s: f"{C.BLU}{s}{C.OFF}",
    "info":     lambda s: f"{C.DIM}{s}{C.OFF}",
}


def _color_sev(sev: str) -> str:
    return _SEV_COLOR.get(sev, lambda s: s)(sev.upper().ljust(8))


def log(msg: str) -> None:
    print(f"{C.DIM}[*]{C.OFF} {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# DNS sobre HTTPS (sin dependencias)
# ---------------------------------------------------------------------------

_DOH_ENDPOINTS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
]

_USER_AGENT = "domainaudit/1.0 (+defensive-self-audit)"


def _http_json(url: str, headers: dict = None, timeout: float = 8.0):
    req = urllib.request.Request(url, headers=headers or {})
    req.add_header("User-Agent", _USER_AGENT)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", "replace"))


def doh_query(name: str, rtype: str, timeout: float = 8.0) -> dict:
    """Resuelve un registro DNS vía DoH. Devuelve el JSON estilo Google/RFC8484.

    Prueba varios endpoints; devuelve {} si todos fallan.
    """
    name = name.rstrip(".")
    params = urllib.parse.urlencode({"name": name, "type": rtype})
    for base in _DOH_ENDPOINTS:
        try:
            return _http_json(
                f"{base}?{params}",
                headers={"Accept": "application/dns-json"},
                timeout=timeout,
            )
        except (urllib.error.URLError, urllib.error.HTTPError,
                socket.timeout, json.JSONDecodeError, TimeoutError):
            continue
    return {}


def dns_records(name: str, rtype: str) -> list:
    """Lista de valores (strings) de un tipo de registro."""
    data = doh_query(name, rtype)
    out = []
    for ans in data.get("Answer", []):
        # DoH usa códigos numéricos; filtramos por el tipo solicitado cuando aplica.
        val = ans.get("data", "")
        if val:
            out.append(val.strip('"'))
    return out


def dns_status(name: str, rtype: str) -> tuple:
    """Devuelve (status_code, dnssec_validated, answers)."""
    data = doh_query(name, rtype)
    status = data.get("Status", -1)     # 0 = NOERROR, 3 = NXDOMAIN
    ad = bool(data.get("AD", False))    # Authenticated Data => DNSSEC validado
    answers = [a.get("data", "").strip('"') for a in data.get("Answer", [])]
    return status, ad, answers


# ---------------------------------------------------------------------------
# Enumeración de subdominios
# ---------------------------------------------------------------------------

_CRT_SH = "https://crt.sh/?q={}&output=json"

# Diccionario compacto de subdominios comunes para fuerza bruta opcional.
_BRUTE_WORDS = [
    "www", "mail", "webmail", "smtp", "imap", "pop", "ftp", "sftp", "ns1", "ns2",
    "vpn", "remote", "portal", "admin", "administrator", "dashboard", "panel",
    "api", "api-dev", "dev", "staging", "stage", "test", "testing", "qa", "uat",
    "beta", "demo", "sandbox", "preprod", "prod", "app", "apps", "web", "cdn",
    "static", "assets", "media", "img", "images", "files", "download", "docs",
    "blog", "shop", "store", "cart", "checkout", "pay", "payment", "billing",
    "auth", "login", "sso", "id", "accounts", "account", "secure", "my",
    "support", "help", "helpdesk", "status", "monitor", "metrics", "grafana",
    "kibana", "jenkins", "gitlab", "git", "jira", "confluence", "wiki",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo", "backup",
    "internal", "intranet", "corp", "office", "mx", "email", "newsletter",
    "cpanel", "whm", "plesk", "phpmyadmin", "adminer", "gateway", "proxy",
    "old", "new", "legacy", "v1", "v2", "mobile", "m", "share", "cloud",
]

# Firmas de secuestro de subdominio (dangling CNAME hacia servicio no reclamado).
_TAKEOVER_FINGERPRINTS = [
    ("github.io", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "No such app"),
    ("herokudns.com", "No such app"),
    ("amazonaws.com", "NoSuchBucket"),
    ("s3.amazonaws.com", "The specified bucket does not exist"),
    ("cloudfront.net", "Bad request"),
    ("azurewebsites.net", "404 Web Site not found"),
    ("cloudapp.net", "404 Web Site not found"),
    ("trafficmanager.net", "404 Web Site not found"),
    ("blob.core.windows.net", "The specified container does not exist"),
    ("ghost.io", "The thing you were looking for is no longer here"),
    ("wpengine.com", "The site you were looking for couldn't be found"),
    ("pantheonsite.io", "The gods are wise"),
    ("surge.sh", "project not found"),
    ("bitbucket.io", "Repository not found"),
    ("fastly.net", "Fastly error: unknown domain"),
    ("readthedocs.io", "unknown to Read the Docs"),
    ("netlify.app", "Not Found"),
    ("netlify.com", "Not Found"),
    ("zendesk.com", "Help Center Closed"),
    ("statuspage.io", "You are being redirected"),
    ("uservoice.com", "This UserVoice subdomain is currently available"),
    ("helpscoutdocs.com", "No settings were found for this company"),
    ("wordpress.com", "Do you want to register"),
]


def enum_crtsh(domain: str, timeout: float = 20.0) -> set:
    """Subdominios desde Certificate Transparency logs (crt.sh)."""
    found = set()
    try:
        data = _http_json(_CRT_SH.format(urllib.parse.quote(f"%.{domain}")),
                          timeout=timeout)
    except (urllib.error.URLError, urllib.error.HTTPError,
            socket.timeout, json.JSONDecodeError, TimeoutError) as e:
        log(f"crt.sh no disponible ({e}); se omite CT logs.")
        return found
    for row in data:
        name_value = row.get("name_value", "")
        for name in name_value.splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and "@" not in name:
                found.add(name)
    return found


def resolve_host(host: str, timeout: float = 5.0) -> list:
    """Devuelve las IPs de un host vía DoH (A + AAAA). Lista vacía si no resuelve."""
    addrs = []
    for rtype in ("A", "AAAA"):
        _, _, answers = dns_status(host, rtype)
        for a in answers:
            # Ignora respuestas CNAME intermedias (no son IPs).
            if re.match(r"^[0-9a-fA-F:.]+$", a) and (":" in a or a.count(".") == 3):
                addrs.append(a)
    return sorted(set(addrs))


def brute_subdomains(domain: str, words: list, workers: int = 40) -> set:
    """Prueba host candidatos y devuelve los que resuelven."""
    found = set()
    candidates = [f"{w}.{domain}" for w in words]

    def _check(host):
        return host if resolve_host(host) else None

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(_check, candidates):
            if res:
                found.add(res)
    return found


# ---------------------------------------------------------------------------
# TLS / certificados
# ---------------------------------------------------------------------------

def _parse_cert_time(value: str) -> datetime:
    # Formato OpenSSL: 'Jun  1 12:00:00 2025 GMT'
    return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)


def inspect_tls(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Recupera info del certificado y protocolo. {} si no hay TLS."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # getpeercert() sin verificación puede venir vacío; forzamos binario.
                if not cert:
                    der = ssock.getpeercert(binary_form=True)
                    cert = _decode_der_subject(der) if der else {}
                return {
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher(),
                    "cert": cert,
                }
    except (socket.timeout, ssl.SSLError, OSError, TimeoutError):
        return {}


def _decode_der_subject(der: bytes) -> dict:
    """Best-effort: usa el contexto verificador para leer fechas si es posible."""
    try:
        return ssl._ssl._test_decode_cert  # type: ignore  # pragma: no cover
    except Exception:
        return {}


def verified_tls(host: str, port: int = 443, timeout: float = 8.0) -> tuple:
    """Devuelve (ok_verificado, mensaje_error)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, ""
    except ssl.SSLCertVerificationError as e:
        return False, str(e.verify_message or e)
    except (socket.timeout, ssl.SSLError, OSError, TimeoutError) as e:
        return False, str(e)


def supports_legacy_protocol(host: str, port: int, proto) -> bool:
    """True si el host acepta un protocolo TLS obsoleto concreto."""
    try:
        ctx = ssl.SSLContext(proto)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def audit_tls(rep: HostReport, port: int = 443) -> None:
    info = inspect_tls(rep.host, port)
    if not info:
        rep.add("info", "tls", "Sin servicio TLS en 443",
                f"{rep.host} no respondió con TLS en el puerto {port}.",
                "Si debe servir HTTPS, revisa que el certificado y el listener estén activos.")
        return

    proto = info.get("protocol", "?")
    cert = info.get("cert") or {}

    # Verificación de cadena/hostname
    ok, err = verified_tls(rep.host, port)
    if not ok:
        rep.add("high", "tls", "Certificado no válido o no confiable",
                f"La verificación TLS falló: {err}",
                "Instala un certificado válido para el hostname, emitido por una CA de confianza "
                "y con la cadena intermedia completa.")

    # Expiración
    not_after = cert.get("notAfter")
    if not_after:
        try:
            exp = _parse_cert_time(not_after)
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                rep.add("critical", "tls", "Certificado caducado",
                        f"Caducó hace {abs(days)} día(s) ({not_after}).",
                        "Renueva el certificado de inmediato; automatiza con ACME/Let's Encrypt.")
            elif days < 15:
                rep.add("high", "tls", "Certificado por caducar",
                        f"Caduca en {days} día(s) ({not_after}).",
                        "Renueva ya y configura renovación automática.")
            elif days < 30:
                rep.add("medium", "tls", "Certificado caduca pronto",
                        f"Caduca en {days} día(s).",
                        "Programa la renovación automática.")
        except ValueError:
            pass

    # Protocolo negociado
    if proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        rep.add("high", "tls", f"Protocolo TLS obsoleto negociado ({proto})",
                f"El servidor negoció {proto}, considerado inseguro.",
                "Desactiva TLS < 1.2 y prioriza TLS 1.3.")

    # Soporte de protocolos obsoletos (aunque no sean el default)
    for name, const in (("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None)),
                        ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None))):
        if const and supports_legacy_protocol(rep.host, port, const):
            rep.add("medium", "tls", f"Soporta {name} (obsoleto)",
                    f"El servidor aún acepta handshakes {name}.",
                    f"Deshabilita {name} en la configuración del servidor/CDN.")


# ---------------------------------------------------------------------------
# Cabeceras HTTP de seguridad
# ---------------------------------------------------------------------------

_SEC_HEADERS = {
    "strict-transport-security": ("high",
        "Sin HSTS: el navegador puede degradar a HTTP y permitir ataques SSL-strip.",
        "Añade 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."),
    "content-security-policy": ("medium",
        "Sin Content-Security-Policy: mayor superficie para XSS e inyección de contenido.",
        "Define una CSP restrictiva (default-src 'self'; ...)."),
    "x-frame-options": ("medium",
        "Sin X-Frame-Options/frame-ancestors: riesgo de clickjacking.",
        "Usa 'X-Frame-Options: DENY' o 'frame-ancestors' en la CSP."),
    "x-content-type-options": ("low",
        "Sin X-Content-Type-Options: el navegador puede hacer MIME-sniffing.",
        "Añade 'X-Content-Type-Options: nosniff'."),
    "referrer-policy": ("low",
        "Sin Referrer-Policy: puede filtrar URLs internas en el header Referer.",
        "Añade 'Referrer-Policy: strict-origin-when-cross-origin'."),
    "permissions-policy": ("low",
        "Sin Permissions-Policy: no se restringen APIs del navegador (cámara, geo...).",
        "Añade una 'Permissions-Policy' que limite las funciones no usadas."),
}

# Cabeceras que revelan tecnología/versión.
_LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version",
                  "x-aspnetmvc-version", "x-generator"]


def fetch_http(host: str, scheme: str, timeout: float = 8.0) -> dict:
    """Hace una petición y devuelve {status, headers, url, redirect}."""
    url = f"{scheme}://{host}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT}, method="GET")
    try:
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            _NoRedirect(),
        )
        with opener.open(req, timeout=timeout) as resp:
            return {"status": resp.status,
                    "headers": {k.lower(): v for k, v in resp.getheaders()},
                    "url": resp.url, "redirect": None}
    except urllib.error.HTTPError as e:
        # 3xx capturado por el handler no-redirect
        return {"status": e.code,
                "headers": {k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
                "url": url,
                "redirect": e.headers.get("Location") if e.headers else None}
    except (urllib.error.URLError, socket.timeout, OSError, TimeoutError):
        return {}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # convierte 3xx en HTTPError para inspeccionarlo


def audit_headers(rep: HostReport) -> None:
    https = fetch_http(rep.host, "https")
    http = fetch_http(rep.host, "http")

    if not https and not http:
        rep.add("info", "headers", "Sin servicio HTTP/HTTPS",
                f"{rep.host} no respondió en HTTP ni HTTPS.", "")
        return

    # ¿HTTP redirige a HTTPS?
    if http:
        loc = (http.get("redirect") or "")
        status = http.get("status", 0)
        redirects_to_https = loc.lower().startswith("https://")
        if not (300 <= status < 400 and redirects_to_https):
            # Si además sirve contenido por HTTP plano
            if status and status < 400:
                rep.add("medium", "headers", "HTTP no redirige a HTTPS",
                        f"http://{rep.host}/ respondió {status} sin redirigir a HTTPS.",
                        "Fuerza la redirección 301 de todo el tráfico HTTP a HTTPS.")

    resp = https or http
    headers = resp.get("headers", {})

    for name, (sev, detail, fix) in _SEC_HEADERS.items():
        if name not in headers:
            # HSTS solo aplica realmente si hay HTTPS.
            if name == "strict-transport-security" and not https:
                continue
            rep.add(sev, "headers", f"Falta cabecera: {name}", detail, fix)

    # Fugas de información
    for name in _LEAKY_HEADERS:
        if name in headers and headers[name].strip():
            rep.add("low", "exposure", f"Cabecera revela tecnología: {name}",
                    f"{name}: {headers[name]}",
                    f"Elimina u ofusca la cabecera '{name}' para no revelar versiones explotables.")

    # Cookies sin flags de seguridad
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        low = set_cookie.lower()
        missing = [f for f in ("httponly", "secure") if f not in low]
        if missing:
            rep.add("medium", "headers", "Cookie sin flags de seguridad",
                    f"Set-Cookie sin: {', '.join(missing)}.",
                    "Marca las cookies de sesión como HttpOnly, Secure y SameSite.")


# ---------------------------------------------------------------------------
# Seguridad de correo (SPF / DKIM / DMARC / MX)
# ---------------------------------------------------------------------------

def audit_email(rep: HostReport, domain: str) -> None:
    txt = dns_records(domain, "TXT")
    mx = dns_records(domain, "MX")

    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        sev = "medium" if mx else "low"
        rep.add(sev, "email", "Sin registro SPF",
                "No se encontró 'v=spf1' en los TXT del dominio.",
                "Publica un SPF, p.ej. 'v=spf1 include:_spf.tu-proveedor.com -all'.")
    else:
        val = spf[0].lower()
        if val.rstrip().endswith("+all") or " +all" in val:
            rep.add("high", "email", "SPF permisivo (+all)",
                    f"El SPF autoriza cualquier emisor: {spf[0]}",
                    "Cambia '+all' por '-all' (fail) para bloquear suplantación.")
        elif "~all" in val:
            rep.add("low", "email", "SPF en softfail (~all)",
                    "El SPF usa '~all' (softfail) en vez de '-all'.",
                    "Considera endurecer a '-all' cuando confirmes todos tus emisores.")
        elif "-all" not in val and "redirect=" not in val:
            rep.add("low", "email", "SPF sin política de rechazo",
                    f"El SPF no termina en '-all': {spf[0]}",
                    "Añade '-all' al final para rechazar emisores no listados.")

    # DMARC
    dmarc_txt = dns_records(f"_dmarc.{domain}", "TXT")
    dmarc = [t for t in dmarc_txt if t.lower().startswith("v=dmarc1")]
    if not dmarc:
        sev = "medium" if mx else "low"
        rep.add(sev, "email", "Sin registro DMARC",
                "No existe _dmarc con 'v=DMARC1'.",
                "Publica DMARC: '_dmarc IN TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@tu-dominio\"'.")
    else:
        val = dmarc[0].lower()
        if "p=none" in val:
            rep.add("low", "email", "DMARC en modo monitor (p=none)",
                    "La política DMARC es 'p=none' (no bloquea nada).",
                    "Sube a 'p=quarantine' y luego 'p=reject' tras revisar los informes.")

    # DKIM: probamos selectores comunes (best-effort).
    dkim_found = False
    for sel in ("default", "google", "selector1", "selector2", "k1", "dkim", "mail", "s1"):
        recs = dns_records(f"{sel}._domainkey.{domain}", "TXT")
        if any("v=dkim1" in r.lower() or "p=" in r.lower() for r in recs):
            dkim_found = True
            break
    if mx and not dkim_found:
        rep.add("low", "email", "DKIM no detectado",
                "No se encontró DKIM en selectores comunes (puede usar un selector propio).",
                "Verifica que tu proveedor de correo firme con DKIM y publica la clave pública.")


# ---------------------------------------------------------------------------
# DNS: DNSSEC, CAA, wildcard, transferencia de zona
# ---------------------------------------------------------------------------

def audit_dns(rep: HostReport, domain: str) -> None:
    # DNSSEC
    status, ad, _ = dns_status(domain, "A")
    ds = dns_records(domain, "DS")
    if not ad and not ds:
        rep.add("low", "dns", "DNSSEC no habilitado",
                "El dominio no está firmado con DNSSEC (sin flag AD ni registros DS).",
                "Habilita DNSSEC en tu registrador para prevenir envenenamiento de caché.")

    # CAA
    caa = dns_records(domain, "CAA")
    if not caa:
        rep.add("low", "dns", "Sin registro CAA",
                "No hay CAA que limite qué CAs pueden emitir certificados para el dominio.",
                "Publica un CAA, p.ej. '0 issue \"letsencrypt.org\"'.")

    # NS
    ns = dns_records(domain, "NS")
    if not ns:
        rep.add("medium", "dns", "Sin registros NS visibles",
                "No se resolvieron servidores de nombres para el dominio.", "")


# ---------------------------------------------------------------------------
# Secuestro de subdominio (dangling CNAME)
# ---------------------------------------------------------------------------

def audit_takeover(rep: HostReport, host: str) -> None:
    cnames = dns_records(host, "CNAME")
    if not cnames:
        return
    target = cnames[-1].rstrip(".").lower()

    matched_service = None
    for service, _fp in _TAKEOVER_FINGERPRINTS:
        if target.endswith(service) or service in target:
            matched_service = service
            break
    if not matched_service:
        return

    # ¿El destino del CNAME resuelve? Si no resuelve, hay riesgo alto de takeover.
    resolves = bool(resolve_host(target))
    if not resolves:
        rep.add("high", "takeover", "Posible secuestro de subdominio (CNAME colgante)",
                f"{host} apunta (CNAME) a '{target}' de {matched_service}, que no resuelve. "
                "Un atacante podría reclamar ese recurso y servir contenido en tu subdominio.",
                f"Elimina el registro CNAME o reclama/recrea el recurso en {matched_service}.")
        return

    # Resuelve: comprobamos la firma en el cuerpo HTTP.
    body = ""
    for scheme in ("https", "http"):
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(f"{scheme}://{host}/",
                                        headers={"User-Agent": _USER_AGENT})
            opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
            with opener.open(req, timeout=6.0) as resp:
                body = resp.read(4096).decode("utf-8", "replace")
            break
        except urllib.error.HTTPError as e:
            try:
                body = e.read(4096).decode("utf-8", "replace")
            except Exception:
                body = ""
            break
        except Exception:
            continue

    fp_text = dict(_TAKEOVER_FINGERPRINTS).get(matched_service, "")
    if fp_text and fp_text.lower() in body.lower():
        rep.add("high", "takeover", "Secuestro de subdominio muy probable",
                f"{host} → {matched_service} devuelve la firma de 'recurso no reclamado': "
                f"\"{fp_text}\".",
                f"Reclama el recurso en {matched_service} o elimina el CNAME de {host}.")


# ---------------------------------------------------------------------------
# Escaneo de puertos (activo)
# ---------------------------------------------------------------------------

# Puertos que normalmente NO deberían estar expuestos a Internet.
_RISKY_PORTS = {
    21: ("high", "FTP", "Transferencia sin cifrar; usa SFTP/FTPS."),
    23: ("critical", "Telnet", "Protocolo sin cifrar; deshabilítalo, usa SSH."),
    25: ("info", "SMTP", "Normal en servidores de correo; verifica que no sea open relay."),
    135: ("high", "MSRPC", "No exponer a Internet."),
    139: ("high", "NetBIOS", "No exponer a Internet."),
    445: ("critical", "SMB", "Nunca exponer SMB a Internet (ransomware/EternalBlue)."),
    1433: ("high", "MSSQL", "Base de datos expuesta; restringe por firewall/VPN."),
    3306: ("high", "MySQL", "Base de datos expuesta; restringe por firewall/VPN."),
    3389: ("high", "RDP", "Escritorio remoto expuesto; usa VPN + MFA."),
    5432: ("high", "PostgreSQL", "Base de datos expuesta; restringe por firewall/VPN."),
    5900: ("high", "VNC", "Acceso remoto expuesto; usa VPN."),
    6379: ("critical", "Redis", "Redis sin auth por defecto; nunca exponer."),
    9200: ("high", "Elasticsearch", "A menudo sin auth; nunca exponer."),
    11211: ("high", "Memcached", "Sin auth; usado en amplificación DDoS."),
    27017: ("critical", "MongoDB", "A menudo sin auth; nunca exponer."),
}
_COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 465,
                 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8000,
                 8080, 8443, 9200, 11211, 27017]


def scan_port(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, OSError, TimeoutError):
        return False


def audit_ports(rep: HostReport, workers: int = 30) -> None:
    if not rep.addresses:
        return
    ip = rep.addresses[0]

    def _check(port):
        return port if scan_port(ip, port) else None

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(_check, _COMMON_PORTS):
            if res:
                open_ports.append(res)

    for port in sorted(open_ports):
        if port in _RISKY_PORTS:
            sev, svc, fix = _RISKY_PORTS[port]
            rep.add(sev, "ports", f"Puerto {port}/{svc} abierto",
                    f"{ip}:{port} ({svc}) responde a conexiones desde fuera.",
                    fix)
        elif port not in (80, 443):
            rep.add("info", "ports", f"Puerto {port} abierto",
                    f"{ip}:{port} acepta conexiones.",
                    "Verifica que esta exposición sea intencional.")


# ---------------------------------------------------------------------------
# Orquestación por host
# ---------------------------------------------------------------------------

def audit_host(host: str, is_apex: bool, do_ports: bool) -> HostReport:
    rep = HostReport(host=host)
    rep.addresses = resolve_host(host)
    rep.resolved = bool(rep.addresses)

    if not rep.resolved:
        # Podría existir vía CNAME colgante: revisamos takeover igual.
        audit_takeover(rep, host)
        if not rep.findings:
            rep.add("info", "dns", "No resuelve", f"{host} no resolvió a ninguna IP.", "")
        return rep

    audit_takeover(rep, host)
    audit_tls(rep)
    audit_headers(rep)
    if is_apex:
        audit_dns(rep, host)
        audit_email(rep, host)
    if do_ports:
        audit_ports(rep)
    return rep


def audit_domain(domain: str, opts) -> list:
    domain = domain.strip().lower().rstrip(".")
    hosts = {domain}

    if opts.subdomains:
        log(f"Enumerando subdominios de {domain} vía Certificate Transparency...")
        ct = enum_crtsh(domain)
        log(f"  {len(ct)} subdominio(s) en CT logs.")
        hosts |= ct
        if opts.brute:
            log(f"Fuerza bruta con {len(_BRUTE_WORDS)} nombres comunes...")
            bf = brute_subdomains(domain, _BRUTE_WORDS)
            log(f"  {len(bf)} resuelto(s) por fuerza bruta.")
            hosts |= bf

    hosts = sorted(hosts)
    log(f"Auditando {len(hosts)} host(s)...")

    reports = []
    # Concurrencia a nivel de host, pero limitada para ser buen ciudadano.
    with concurrent.futures.ThreadPoolExecutor(max_workers=opts.workers) as ex:
        futs = {
            ex.submit(audit_host, h, h == domain, opts.ports): h
            for h in hosts
        }
        for fut in concurrent.futures.as_completed(futs):
            try:
                reports.append(fut.result())
            except Exception as e:  # nunca abortar el lote por un host
                h = futs[fut]
                r = HostReport(host=h)
                r.add("info", "error", "Error auditando host", str(e), "")
                reports.append(r)

    reports.sort(key=lambda r: r.host)
    return reports


# ---------------------------------------------------------------------------
# Puntuación y reportes
# ---------------------------------------------------------------------------

def risk_score(reports: list) -> int:
    """Puntuación 0-100 (100 = peor). Saturada."""
    total = sum(_SEV_WEIGHT[f.severity]
                for r in reports for f in r.findings)
    return min(100, total)


def _all_findings(reports: list) -> list:
    out = [f for r in reports for f in r.findings]
    out.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.category, f.target))
    return out


def print_console(domain: str, reports: list) -> None:
    findings = _all_findings(reports)
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1

    resolved = sum(1 for r in reports if r.resolved)
    print()
    print(f"{C.BOLD}══ Auditoría de dominio: {domain} ══{C.OFF}")
    print(f"   Hosts analizados : {len(reports)} ({resolved} resuelven)")
    print(f"   Hallazgos        : {len(findings)}")
    score = risk_score(reports)
    band = (C.GRN if score < 20 else C.YEL if score < 50 else C.RED)
    print(f"   Riesgo agregado  : {band}{score}/100{C.OFF}")
    print()

    if not findings:
        print(f"{C.GRN}[+] Sin hallazgos. Buen trabajo.{C.OFF}")
        return

    # Agrupado por host, solo hosts con hallazgos accionables.
    for rep in reports:
        actionable = [f for f in rep.findings if f.severity != "info"]
        if not actionable:
            continue
        addr = f" {C.DIM}({', '.join(rep.addresses)}){C.OFF}" if rep.addresses else ""
        print(f"{C.BOLD}▸ {rep.host}{C.OFF}{addr}")
        for f in sorted(rep.findings, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
            if f.severity == "info":
                continue
            print(f"   [{_color_sev(f.severity)}] {C.BOLD}{f.title}{C.OFF}  {C.DIM}({f.category}){C.OFF}")
            print(f"        {f.detail}")
            if f.fix:
                print(f"        {C.GRN}fix:{C.OFF} {f.fix}")
        print()

    print(f"{C.BOLD}── Resumen ──{C.OFF}")
    for s in SEVERITIES:
        if counts[s]:
            print(f"   {_color_sev(s)} {counts[s]}")


def to_dict(domain: str, reports: list) -> dict:
    return {
        "domain": domain,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "risk_score": risk_score(reports),
        "hosts": [
            {
                "host": r.host,
                "resolved": r.resolved,
                "addresses": r.addresses,
                "findings": [asdict(f) for f in r.findings],
            }
            for r in reports
        ],
    }


def to_markdown(domain: str, reports: list) -> str:
    findings = _all_findings(reports)
    counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITIES}
    lines = [
        f"# Informe de auditoría de dominio: {domain}",
        "",
        f"- Generado: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- Hosts analizados: {len(reports)}",
        f"- Riesgo agregado: **{risk_score(reports)}/100**",
        "",
        "| Severidad | Nº |",
        "|-----------|----|",
    ]
    for s in SEVERITIES:
        lines.append(f"| {s} | {counts[s]} |")
    lines.append("")

    for rep in reports:
        actionable = [f for f in rep.findings if f.severity != "info"]
        if not actionable:
            continue
        addr = f" ({', '.join(rep.addresses)})" if rep.addresses else ""
        lines.append(f"## {rep.host}{addr}")
        lines.append("")
        for f in sorted(rep.findings, key=lambda x: _SEV_ORDER.get(x.severity, 9)):
            if f.severity == "info":
                continue
            lines.append(f"### [{f.severity.upper()}] {f.title}  _( {f.category} )_")
            lines.append("")
            lines.append(f"{f.detail}")
            if f.fix:
                lines.append("")
                lines.append(f"**Solución:** {f.fix}")
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


def valid_domain(d: str) -> bool:
    return bool(_DOMAIN_RE.match(d.strip().rstrip(".")))


def _confirm(prompt: str) -> bool:
    if not sys.stdin.isatty():
        return False
    try:
        return input(prompt).strip().lower() in ("y", "yes", "s", "si", "sí")
    except (EOFError, KeyboardInterrupt):
        print()
        return False


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="domainaudit",
        description="Auditoría defensiva de vulnerabilidades de dominios y subdominios.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("domain", nargs="+",
                   help="uno o más dominios raíz que POSEES (ej: miempresa.com)")
    p.add_argument("--subdomains", "-s", action="store_true",
                   help="enumerar y auditar subdominios (Certificate Transparency)")
    p.add_argument("--brute", action="store_true",
                   help="además, fuerza bruta con diccionario interno (activo)")
    p.add_argument("--ports", action="store_true",
                   help="escanear puertos comunes (activo)")
    p.add_argument("--full", action="store_true",
                   help="equivale a --subdomains --brute --ports")
    p.add_argument("--workers", type=int, default=12,
                   help="hosts auditados en paralelo (def: 12)")
    p.add_argument("--json", action="store_true", help="salida JSON")
    p.add_argument("--md", action="store_true", help="salida Markdown")
    p.add_argument("-o", "--output", help="escribir el informe a un archivo")
    p.add_argument("--yes", "-y", action="store_true",
                   help="confirmar automáticamente escaneos activos (soy el dueño)")
    p.add_argument("--no-color", action="store_true", help="desactivar color")

    args = p.parse_args(argv)

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    if args.full:
        args.subdomains = args.brute = args.ports = True

    # Validación de dominios
    for d in args.domain:
        if not valid_domain(d):
            print(f"error: '{d}' no parece un dominio válido.", file=sys.stderr)
            return 2

    # Confirmación para escaneos activos
    active = args.brute or args.ports
    if active and not args.yes:
        print("Vas a ejecutar comprobaciones ACTIVAS (escaneo de puertos / fuerza bruta).")
        print("Confirma que eres el dueño de estos dominios o tienes permiso explícito:")
        for d in args.domain:
            print(f"   - {d}")
        if not _confirm("¿Continuar? [y/N] "):
            print("Cancelado. Usa --yes para omitir esta confirmación.", file=sys.stderr)
            return 1

    all_reports = {}
    exit_code = 0
    for d in args.domain:
        reports = audit_domain(d, args)
        all_reports[d] = reports
        # Código de salida distinto de 0 si hay hallazgos críticos/altos.
        if any(f.severity in ("critical", "high")
               for r in reports for f in r.findings):
            exit_code = 3

    # Salida
    if args.json:
        payload = ({"domains": [to_dict(d, r) for d, r in all_reports.items()]}
                   if len(all_reports) > 1
                   else to_dict(next(iter(all_reports)), next(iter(all_reports.values()))))
        text = json.dumps(payload, indent=2, ensure_ascii=False)
        _emit(text, args.output)
    elif args.md:
        text = "\n\n---\n\n".join(to_markdown(d, r) for d, r in all_reports.items())
        _emit(text, args.output)
    else:
        for d, reports in all_reports.items():
            print_console(d, reports)
        if args.output:
            # Aun en modo consola, si piden -o guardamos markdown.
            text = "\n\n---\n\n".join(to_markdown(d, r) for d, r in all_reports.items())
            _write_file(text, args.output)

    return exit_code


def _emit(text: str, output: str | None) -> None:
    if output:
        _write_file(text, output)
    else:
        print(text)


def _write_file(text: str, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    log(f"Informe escrito en {path}")


if __name__ == "__main__":
    sys.exit(main())
