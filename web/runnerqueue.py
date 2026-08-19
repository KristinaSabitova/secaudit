"""Handing audits to a runner on someone else's machine.

The `claude-code` backend authenticates a person on a machine rather than a
server on their behalf, so the hosted instance cannot run it. When a user picks
it, their audits are left queued here instead and their own runner claims them,
audits locally, and posts the findings back.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import Audit, User

# A claim older than this is assumed abandoned — the runner was interrupted or
# went offline — and the audit becomes claimable again.
CLAIM_TIMEOUT = timedelta(minutes=45)

RUNNER_BACKEND = "claude-code"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def issue_token(session: Session, user: User) -> str:
    """Replace this account's runner token and return it. Shown once."""
    token = secrets.token_urlsafe(32)
    user.runner_token_hash = hash_token(token)
    session.commit()
    return token


def revoke_token(session: Session, user: User) -> None:
    user.runner_token_hash = None
    session.commit()


def user_for_token(session: Session, token: str | None) -> User | None:
    if not token:
        return None
    return session.scalar(
        select(User).where(User.runner_token_hash == hash_token(token))
    )


def _aware(moment: datetime | None) -> datetime | None:
    if moment is not None and moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)   # SQLite drops the offset
    return moment


def claim_next(session: Session, user: User) -> Audit | None:
    """Take the next audit this user's runner should execute, if there is one.

    A runner sees its owner's audits; an admin's runner also sees the ones a
    webhook queued, which belong to nobody.
    """
    owned = [Audit.user_id == user.id]
    if user.is_admin:
        owned.append(Audit.user_id.is_(None))

    stale = datetime.now(timezone.utc) - CLAIM_TIMEOUT
    candidates = session.scalars(
        select(Audit)
        .where(or_(*owned), Audit.status.in_(("pending", "running")))
        .order_by(Audit.created_at)
    ).all()

    for audit in candidates:
        claimed_at = _aware(audit.runner_claimed_at)
        if audit.status == "pending" and claimed_at is None:
            pass                                  # never claimed
        elif claimed_at is not None and claimed_at < stale:
            pass                                  # the previous runner vanished
        else:
            continue
        audit.status = "running"
        audit.runner_claimed_at = datetime.now(timezone.utc)
        session.commit()
        return audit
    return None


def to_dict(audit: Audit) -> dict:
    return {"id": audit.id, "repo_url": audit.repo_url, "branch": audit.branch,
            "language": audit.language}
