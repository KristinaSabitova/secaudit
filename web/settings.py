"""Backend configuration entered from the dashboard.

The API key is encrypted at rest with a master key that lives only in the
environment, so a database dump on its own does not disclose it.
"""

import base64
import hashlib
import os

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import Settings

SECRET_ENV = "SECAUDIT_SECRET_KEY"

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
        settings.ollama_url = ollama_url or None
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
