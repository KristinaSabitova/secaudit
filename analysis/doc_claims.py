"""What the documentation says about security, against what the code shows (A4).

A README can promise what the code does not do: "passwords are hashed with
bcrypt", "every endpoint requires authentication", "rate limited". A
reviewer who reads the promise may skip the check. This reads the security
claims in README, SECURITY and docs files (English and Spanish), and looks
for the code that would back each one.

- backed: the code mentions what the claim names (a hashing library, a rate
  limiter, a CSRF middleware...). Mentioned is not proven: it is where the
  check would live.
- unbacked: no file other than documentation mentions it. The claim may be
  kept by infrastructure outside the repository (a gateway, a proxy), so it
  is a place to look, not a finding by itself.
- contradicted: the code states the opposite of the claim (TLS verification
  turned off, debug on, a hash known to be weak).

Unbacked and contradicted claims lower the confidence one can place in the
documentation, and the audit says so.
"""

import re
from pathlib import PurePosixPath

CLAIMS_VERSION = "1"
MAX_ITEMS = 100

_DOC = re.compile(r"(?i)(^|/)(readme|security|security_policy|architecture|"
                  r"docs?/[^/]+)(\.[a-z]+)?$|\.(md|rst|adoc)$")

# kind -> (claim pattern, evidence in code, contradiction in code or None)
CLAIMS = {
    "password_hashing": (
        r"(?i)(passwords? (are|is) (securely )?(hashed|salted)|bcrypt|argon2|scrypt|"
        r"contrase(ñ|n)as? (se )?(guardan |almacenan )?(cifradas|hasheadas|con hash)|"
        r"hash(eadas?)? (de|las) contrase)",
        r"(?i)(bcrypt|argon2|scrypt|pbkdf2|hashpw|generate_password_hash|passlib|"
        r"make_password|password_hash\(|crypto\.scrypt|hashSync|PasswordHasher)",
        r"(?i)(hashlib\.(md5|sha1)\([^)]*pass|md5\([^)]*pass|sha1\([^)]*pass)"),
    "authentication": (
        r"(?i)((all|every) (api )?(endpoints?|routes?|requests?) (are |is )?"
        r"(authenticated|require[sd]? auth)|requires? authentication|"
        r"(todos los|todas las) (endpoints?|rutas|peticiones) requieren autenticaci|"
        r"requiere autenticaci)",
        r"(?i)(login_required|jwt_required|@auth|Depends\(\s*(get_current|auth|verify|require)|"
        r"passport\.|authenticate\(|requireAuth|isAuthenticated|OAuth2PasswordBearer|"
        r"HTTPBearer|before_request|getServerSession|clerkMiddleware)", None),
    "rate_limiting": (
        r"(?i)(rate[- ]limit(ed|ing)?|throttl(ed|ing)|limitaci(ó|o)n de (peticiones|"
        r"intentos|tasa)|l(í|i)mite de peticiones)",
        r"(?i)(limiter|ratelimit|rate_limit|slowapi|flask_limiter|express-rate-limit|"
        r"rateLimit|throttle|Throttle|django_ratelimit|bottleneck)", None),
    "csrf": (
        r"(?i)(csrf (protection|tokens?)|protecci(ó|o)n (contra )?csrf|protected against csrf)",
        r"(?i)(csrf|CSRFProtect|csurf|csrf_token|CsrfViewMiddleware|SameSite)",
        r"(?i)(csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False|csrf\s*:\s*false)"),
    "encryption_at_rest": (
        r"(?i)(encrypted at rest|encryption at rest|data is encrypted|cifrad[oa]s? en reposo|"
        r"(los )?datos (se guardan |est(á|a)n )?cifrados|AES-?256)",
        r"(?i)(Fernet|AES|AESGCM|cryptography\.|pgcrypto|encrypt\(|createCipheriv|KMS|"
        r"nacl\.|libsodium|crypto\.subtle)", None),
    "input_validation": (
        r"(?i)((all )?(user )?input (is |are )?(validated|sanitized)|"
        r"validaci(ó|o)n de (la )?entrada|(se )?valida(n)? (toda )?la entrada|"
        r"entradas? (validadas|saneadas))",
        r"(?i)(pydantic|BaseModel|marshmallow|Joi\.|zod|z\.object|validator|validate\(|"
        r"express-validator|cerberus|jsonschema|wtforms|serializers?\.)", None),
    "tls": (
        r"(?i)(https only|only over https|enforces? https|tls (1\.[23]|everywhere)|"
        r"solo (por|sobre) https|(cifrado|conexiones?) tls|HSTS)",
        r"(?i)(https|ssl|tls|Strict-Transport-Security|HSTS|SECURE_SSL_REDIRECT|"
        r"force_https|helmet)",
        r"(?i)(verify\s*=\s*False|rejectUnauthorized\s*:\s*false|"
        r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|InsecureSkipVerify\s*:\s*true|CERT_NONE)"),
    "mfa": (
        r"(?i)(two[- ]factor|2fa|mfa|multi[- ]factor|doble factor|autenticaci(ó|o)n en dos pasos)",
        r"(?i)(totp|pyotp|speakeasy|otplib|webauthn|fido2|two_factor|2fa|mfa|otp)", None),
    "audit_logging": (
        r"(?i)(audit (log|trail)|(all )?actions are logged|registro de auditor(í|i)a|"
        r"(se )?registran todas las (acciones|operaciones))",
        r"(?i)(audit|AuditLog|logger\.|logging\.|winston|pino|structlog)", None),
    "no_debug_in_production": (
        r"(?i)(debug (mode )?(is )?(disabled|off) in production|"
        r"(modo )?depuraci(ó|o)n desactivad[oa] en producci)",
        r"(?i)(DEBUG\s*=\s*(False|os\.environ|env)|debug\s*=\s*False|NODE_ENV)",
        r"(?i)(\bDEBUG\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True)"),
}

LABELS = {
    "password_hashing": ("passwords are hashed", "las contraseñas se guardan con hash"),
    "authentication": ("endpoints require authentication",
                       "los endpoints requieren autenticación"),
    "rate_limiting": ("requests are rate limited", "hay limitación de peticiones"),
    "csrf": ("CSRF protection", "protección CSRF"),
    "encryption_at_rest": ("data is encrypted at rest", "los datos se cifran en reposo"),
    "input_validation": ("input is validated", "la entrada se valida"),
    "tls": ("traffic is protected with TLS/HTTPS", "el tráfico va por TLS/HTTPS"),
    "mfa": ("multi-factor authentication", "autenticación de varios factores"),
    "audit_logging": ("actions are audit-logged", "las acciones quedan registradas"),
    "no_debug_in_production": ("debug is off in production",
                               "la depuración está desactivada en producción"),
}

_CODE_EXT = (".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php",
             ".java", ".kt", ".cs", ".rs", ".yml", ".yaml", ".toml", ".json", ".ini",
             ".cfg", ".conf", ".env.example", "dockerfile")


def _is_doc(rel: str) -> bool:
    return bool(_DOC.search(rel))


def _is_code(rel: str) -> bool:
    low = rel.lower()
    if re.search(r"(?i)(^|/)(tests?|spec|__tests__|node_modules|vendor|dist|build)/", rel):
        return False
    return low.endswith(_CODE_EXT) or PurePosixPath(low).name == "dockerfile"


def _first(rx: re.Pattern, texts: dict[str, str], files: list[str]) -> dict | None:
    for rel in files:
        m = rx.search(texts[rel])
        if m:
            line = texts[rel].count("\n", 0, m.start()) + 1
            return {"file": rel, "line": line, "match": m.group(0)[:80]}
    return None


def analyze(texts: dict[str, str], language: str = "en") -> dict:
    es = language == "es"
    docs = sorted(r for r in texts if _is_doc(r) and not _is_code(r))
    code = sorted(r for r in texts if _is_code(r) and not _is_doc(r))
    items = []
    for kind, (claim, evidence, contra) in CLAIMS.items():
        crx = re.compile(claim)
        said = None
        for rel in docs:
            for n, line in enumerate(texts[rel].split("\n"), 1):
                if len(line) < 2000 and crx.search(line):
                    said = {"file": rel, "line": n, "text": line.strip()[:240]}
                    break
            if said:
                break
        if said is None:
            continue
        backing = _first(re.compile(evidence), texts, code)
        against = _first(re.compile(contra), texts, code) if contra else None
        status = "contradicted" if against else "backed" if backing else "unbacked"
        items.append({"kind": kind, "status": status,
                      "label": LABELS[kind][1 if es else 0], "claim": said,
                      "evidence": backing, "contradiction": against})
    items = items[:MAX_ITEMS]
    counts = {s: sum(1 for i in items if i["status"] == s)
              for s in ("backed", "unbacked", "contradicted")}
    return {"version": CLAIMS_VERSION, "items": items, "counts": counts,
            "documents": len(docs), "code_files": len(code),
            "lowers_confidence": bool(counts["unbacked"] or counts["contradicted"]),
            "note": ("Que el código mencione un control no prueba que funcione; que no lo "
                     "mencione puede deberse a infraestructura fuera del repositorio."
                     if es else
                     "Code that mentions a control does not prove it works; code that does "
                     "not may rely on infrastructure outside the repository.")}
