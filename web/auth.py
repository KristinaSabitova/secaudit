"""Sign-in with GitHub, and the session cookie that follows from it.

GitHub rather than passwords: the tool already revolves around GitHub
repositories, and it means no password hashes, no reset emails, and no mail
server to run.
"""

import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import User, UserSession

CLIENT_ID_ENV = "GITHUB_OAUTH_CLIENT_ID"
CLIENT_SECRET_ENV = "GITHUB_OAUTH_CLIENT_SECRET"
ADMIN_LOGIN_ENV = "SECAUDIT_ADMIN_GITHUB_LOGIN"

COOKIE_NAME = "secaudit_session"
SESSION_DAYS = 30
HTTP_TIMEOUT = 15

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
USER_URL = "https://api.github.com/user"


class AuthError(Exception):
    """Sign-in could not be completed."""


class AuthUnavailable(AuthError):
    """No OAuth application is configured, so nobody can sign in."""


def _credentials() -> tuple[str, str]:
    client_id = os.environ.get(CLIENT_ID_ENV)
    client_secret = os.environ.get(CLIENT_SECRET_ENV)
    if not client_id or not client_secret:
        raise AuthUnavailable(
            f"{CLIENT_ID_ENV} and {CLIENT_SECRET_ENV} are not set, so sign-in "
            "is disabled. Register a GitHub OAuth App and set both."
        )
    return client_id, client_secret


def is_configured() -> bool:
    try:
        _credentials()
        return True
    except AuthUnavailable:
        return False


def authorize_url(state: str, redirect_uri: str) -> str:
    client_id, _ = _credentials()
    query = urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        # No scopes: only the public profile is needed to identify the account.
        "scope": "",
        "allow_signup": "true",
    })
    return f"{AUTHORIZE_URL}?{query}"


def _post_json(url: str, data: dict, headers: dict) -> dict:
    request = urllib.request.Request(
        url, data=urllib.parse.urlencode(data).encode(),
        headers={"Accept": "application/json", **headers}, method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return json.loads(response.read())
    except urllib.error.URLError as e:
        raise AuthError(f"could not reach GitHub: {e}") from e


def _get_json(url: str, token: str) -> dict:
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": "secaudit",
    })
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            return json.loads(response.read())
    except urllib.error.URLError as e:
        raise AuthError(f"could not reach GitHub: {e}") from e


def exchange_code(code: str, redirect_uri: str) -> dict:
    """Trade an authorization code for the GitHub account that signed in."""
    client_id, client_secret = _credentials()
    token_response = _post_json(TOKEN_URL, {
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }, headers={})
    token = token_response.get("access_token")
    if not token:
        raise AuthError(token_response.get("error_description")
                        or "GitHub did not return an access token")

    profile = _get_json(USER_URL, token)
    if not profile.get("id"):
        raise AuthError("GitHub did not return an account id")
    return profile


def upsert_user(session: Session, profile: dict) -> User:
    """Create or refresh the local record for a GitHub account."""
    github_id = str(profile["id"])
    user = session.scalar(select(User).where(User.github_id == github_id))
    if user is None:
        user = User(github_id=github_id)
        session.add(user)
    user.login = str(profile.get("login") or "")[:100]
    user.name = str(profile.get("name") or "")[:200] or None
    user.avatar_url = str(profile.get("avatar_url") or "")[:512] or None

    # The account named in the environment administers the instance; so does
    # the very first account to sign in, so a fresh install is never locked out.
    admin_login = os.environ.get(ADMIN_LOGIN_ENV, "").strip().lower()
    if admin_login:
        user.is_admin = user.login.lower() == admin_login
    elif session.scalar(select(User).where(User.is_admin.is_(True))) is None:
        user.is_admin = True

    session.commit()
    return user


def start_session(session: Session, user: User) -> UserSession:
    record = UserSession(
        token=secrets.token_urlsafe(32),
        user_id=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS),
    )
    session.add(record)
    session.commit()
    return record


def user_for_token(session: Session, token: str | None) -> User | None:
    if not token:
        return None
    record = session.get(UserSession, token)
    if record is None:
        return None
    expires_at = record.expires_at
    if expires_at.tzinfo is None:          # SQLite drops the offset
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= datetime.now(timezone.utc):
        session.delete(record)
        session.commit()
        return None
    return session.get(User, record.user_id)


def end_session(session: Session, token: str | None) -> None:
    if not token:
        return
    record = session.get(UserSession, token)
    if record is not None:
        session.delete(record)
        session.commit()


def user_to_dict(user: User | None) -> dict | None:
    if user is None:
        return None
    return {
        "login": user.login,
        "name": user.name,
        "avatar_url": user.avatar_url,
        "is_admin": user.is_admin,
    }
