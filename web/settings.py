"""Backend configuration entered from the dashboard.

The API key is encrypted at rest with a master key that lives only in the
environment, so a database dump on its own does not disclose it.
"""

import base64
import hashlib
import ipaddress
import os
import socket
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from .auth import SINGLE_USER_ENV
from .models import Settings

SECRET_ENV = "SECAUDIT_SECRET_KEY"

# Hosts this instance may be pointed at for Ollama. Set it and only those are
# accepted; leave it unset and the policy below decides.
ALLOWED_OLLAMA_HOSTS_ENV = "SECAUDIT_ALLOWED_OLLAMA_HOSTS"

# Which environment variable each backend reads its credential from. The engine
# takes credentials from the environment, so a stored key has to land there.
CREDENTIAL_ENV = {
    "anthropic-api": "ANTHROPIC_API_KEY",
    "openai-api": "OPENAI_API_KEY",
}

# Enough to tell the two apart: Anthropic keys are also "sk-" prefixed, so the
# longer prefix has to be tested first.
_KEY_PREFIXES = (("sk-ant-", "anthropic-api"), ("sk-", "openai-api"))


class SecretsUnavailable(Exception):
    """Credentials cannot be stored or read with the current master key."""


class InvalidOllamaURL(ValueError):
    """The Ollama address is not one this instance may be asked to reach."""


def _resolved_addresses(host: str) -> list[ipaddress._BaseAddress]:
    """Every address the host resolves to, or [] if it resolves to none."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []
    return [ipaddress.ip_address(info[4][0]) for info in infos]


def _is_internal(address: ipaddress._BaseAddress) -> bool:
    return (address.is_private or address.is_loopback or address.is_link_local
            or address.is_multicast or address.is_reserved
            or address.is_unspecified)


def validate_ollama_url(url: str) -> str:
    """Check an Ollama address before the server can be made to request it.

    The server fetches this URL and hands the caller what came back, so an
    unchecked value is a port scanner pointed at whatever the container can
    reach. The obvious remedy — ban private and loopback addresses — cannot be
    the whole rule here: a real Ollama lives at http://localhost:11434 or at a
    container name on the compose network, so banning those outright would
    remove the one backend that costs nothing to run, which this tool is
    required to keep working.

    So the shape is always enforced, and who may be reached depends on what
    kind of instance this is:

      * an explicit host allowlist wins wherever it is set;
      * a personal instance (SINGLE_USER_ENV) may reach anything, because its
        operator and its only user are the same person and there is no one to
        pivot away from;
      * a hosted instance, where a stranger can sign in and type this, is held
        to public addresses.
    """
    url = (url or "").strip()
    if not url:
        return url

    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise InvalidOllamaURL(
            f"the Ollama URL must be http or https, not '{parts.scheme or url}'")
    if parts.username or parts.password:
        raise InvalidOllamaURL("the Ollama URL must not carry credentials")
    if parts.query or parts.fragment:
        raise InvalidOllamaURL("the Ollama URL must not carry a query or fragment")
    if parts.path not in ("", "/"):
        raise InvalidOllamaURL(
            "the Ollama URL must be a bare address, without a path")
    try:
        port = parts.port
    except ValueError as e:                      # a non-numeric port
        raise InvalidOllamaURL("the Ollama URL has an invalid port") from e
    if port is not None and not 1 <= port <= 65535:
        raise InvalidOllamaURL("the Ollama URL has an invalid port")
    host = (parts.hostname or "").strip()
    if not host:
        raise InvalidOllamaURL("the Ollama URL has no host")

    allowed_hosts = {h.strip().lower()
                     for h in os.environ.get(ALLOWED_OLLAMA_HOSTS_ENV, "").split(",")
                     if h.strip()}
    if allowed_hosts:
        if host.lower() not in allowed_hosts:
            raise InvalidOllamaURL(
                f"'{host}' is not one of the Ollama hosts this instance allows")
        return url.rstrip("/")

    if os.environ.get(SINGLE_USER_ENV, "").strip():
        return url.rstrip("/")

    addresses = _resolved_addresses(host)
    if not addresses:
        raise InvalidOllamaURL(
            f"'{host}' does not resolve, so it cannot be checked. Name it in "
            f"{ALLOWED_OLLAMA_HOSTS_ENV} if this instance should reach it.")
    if any(_is_internal(address) for address in addresses):
        raise InvalidOllamaURL(
            f"'{host}' resolves inside this network. A hosted instance will "
            f"not be pointed at it; name it in {ALLOWED_OLLAMA_HOSTS_ENV} if "
            "that is what the operator wants.")
    return url.rstrip("/")


def _fernet() -> Fernet:
    secret = os.environ.get(SECRET_ENV)
    if not secret:
        raise SecretsUnavailable(
            f"{SECRET_ENV} is not set, so API keys cannot be stored. "
            "Generate one with: openssl rand -hex 32"
        )
    # Any passphrase is accepted; Fernet itself needs 32 url-safe base64 bytes.
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest()))


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(token: str) -> str:
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as e:
        raise SecretsUnavailable(
            f"the stored API key cannot be decrypted; {SECRET_ENV} has changed"
        ) from e


def detect_backend(api_key: str) -> str | None:
    """Infer the backend an API key belongs to, or None if the shape is unknown."""
    for prefix, backend in _KEY_PREFIXES:
        if api_key.startswith(prefix):
            return backend
    return None


def load(session: Session, user_id: int | None = None) -> Settings | None:
    """The row for a user, or the instance-wide default when user_id is None."""
    return session.scalar(select(Settings).where(Settings.user_id == user_id))


def save(session: Session, user_id: int | None = None, *,
         backend: str | None = None, model: str | None = None,
         ollama_url: str | None = None, api_key: str | None = None,
         clear_api_key: bool = False) -> Settings:
    """Store the settings, encrypting the key. Fields left as None are unchanged."""
    settings = load(session, user_id) or Settings(user_id=user_id)
    if backend is not None:
        settings.backend = backend or None
    if model is not None:
        settings.model = model or None
    if ollama_url is not None:
        settings.ollama_url = validate_ollama_url(ollama_url) or None
    if clear_api_key:
        settings.api_key_encrypted = None
    elif api_key:
        settings.api_key_encrypted = encrypt(api_key)
    session.add(settings)
    session.commit()
    return settings


def config_overrides(session: Session, user_id: int | None = None) -> dict:
    """The engine config the dashboard settings ask for."""
    settings = load(session, user_id)
    if settings is None:
        return {}
    stored = {"backend": settings.backend, "model": settings.model,
              "ollama_url": settings.ollama_url}
    return {k: v for k, v in stored.items() if v}


def credentials(session: Session, user_id: int | None = None) -> dict[str, str]:
    """The environment variables this user's audits should run with.

    Returned rather than exported: the audit runs in its own process, so one
    user's key never becomes visible to another user's concurrent audit.
    """
    settings = load(session, user_id)
    if settings is None or not settings.api_key_encrypted:
        return {}
    env_name = CREDENTIAL_ENV.get(settings.backend or "")
    if env_name is None:
        return {}
    return {env_name: decrypt(settings.api_key_encrypted)}


def to_dict(settings: Settings | None) -> dict:
    """Serialise for the API — never includes the key itself."""
    if settings is None:
        return {"backend": None, "model": None, "ollama_url": None,
                "api_key_set": False, "updated_at": None}
    from .models import isoformat_utc
    return {
        "backend": settings.backend,
        "model": settings.model,
        "ollama_url": settings.ollama_url,
        "api_key_set": bool(settings.api_key_encrypted),
        "updated_at": isoformat_utc(settings.updated_at),
    }
