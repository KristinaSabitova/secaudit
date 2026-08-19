"""ORM models for audits and findings, plus dict serialisation helpers."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, ForeignKey, Integer, String,
                        Text)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Findings are only presented as confirmed when they carry evidence from the
# audited repository; see verification_status on Finding.
VERIFIED = "verified"
UNVERIFIED = "unverified"

# Languages an audit can be written in. The engine is asked for one of these
# directly, so there is no translation step after the fact.
LANGUAGES = ("en", "es")
DEFAULT_LANGUAGE = "en"


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_utc(dt: datetime | None) -> str | None:
    """Serialise a timestamp as UTC with an explicit offset.

    Timestamps are stored in UTC, but SQLite hands them back without tzinfo,
    and browsers read an offset-less ISO string as local time.
    """
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


def empty_summary() -> dict:
    return {s: 0 for s in SEVERITIES}


def summarize(findings: list[dict]) -> dict:
    summary = empty_summary()
    for f in findings:
        sev = f.get("severity")
        summary[sev if sev in summary else "info"] += 1
    return summary


class Audit(Base):
    __tablename__ = "audits"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_new_id)
    repo_url: Mapped[str] = mapped_column(String(255), nullable=False)
    # NULL means the audit came from a webhook, not from a signed-in user.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True,
    )
    # NULL means "whatever the repository's default branch is".
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    trigger: Mapped[str] = mapped_column(String(16), default="manual")   # manual | webhook
    # The language the backend was asked to write this audit's findings in.
    language: Mapped[str] = mapped_column(String(8), default=DEFAULT_LANGUAGE,
                                          nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending")   # pending | running | done | error
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=empty_summary)
    # When a runner took this audit, so an abandoned one can be reclaimed.
    runner_claimed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="audit", cascade="all, delete-orphan", order_by="Finding.id",
    )


class User(Base):
    """A GitHub account that has signed in."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    github_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    login: Mapped[str] = mapped_column(String(100), nullable=False)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    # Admins see webhook-triggered audits and everyone else's; see web/auth.py.
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # SHA-256 of this account's runner token; the token itself is shown once.
    runner_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow,
    )


class UserSession(Base):
    """A signed-in browser session, keyed by the value of the session cookie."""

    __tablename__ = "user_sessions"

    token: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow,
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )


class Settings(Base):
    """Backend configuration entered in the dashboard, one row per user.

    The row with no user is the instance-wide default. API keys are stored
    encrypted; see web/settings.py.
    """

    __tablename__ = "settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # NULL is the instance-wide default, used by webhook-triggered audits.
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, unique=True,
    )
    backend: Mapped[str | None] = mapped_column(String(32), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ollama_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    api_key_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow,
    )


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    category: Mapped[str] = mapped_column(String(64), default="other")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    file: Mapped[str] = mapped_column(String(512), default="")
    # Findings are anchored by function or class, which survives a refactor;
    # the line is a convenience on top and stays NULL when the backend could
    # not point at one.
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    anchor: Mapped[str] = mapped_column(String(255), default="")
    fingerprint: Mapped[str] = mapped_column(String(16), default="")
    # The code that shows the flaw, copied from the audited repository. Empty
    # whenever the engine could not point at any.
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    verification_status: Mapped[str] = mapped_column(
        String(16), default=UNVERIFIED, nullable=False, index=True,
    )
    # Why an unverified finding could not be anchored to code.
    verification_note: Mapped[str | None] = mapped_column(String(255), nullable=True)

    audit: Mapped[Audit] = relationship(back_populates="findings")


def _line_number(value) -> int | None:
    """A positive line number, or None for anything else a backend sends."""
    try:
        line = int(value)
    except (TypeError, ValueError):
        return None
    return line if line > 0 else None


def finding_from_dict(audit_id: str, f: dict) -> Finding:
    sev = f.get("severity")
    snippet = str(f.get("code_snippet") or "").strip()
    status = str(f.get("verification_status") or "").strip().lower()
    note = str(f.get("verification_note") or "")[:255]
    file = str(f.get("file") or "")[:512]
    # The engine applies this same rule, but a finding also reaches here from a
    # runner on someone else's machine, so it is enforced again before storage:
    # nothing is recorded as confirmed without the evidence to back it up.
    if status != VERIFIED:
        status = UNVERIFIED
        note = note or "not reported as verified by the audit backend"
    elif not file or not snippet:
        status = UNVERIFIED
        missing = "a file" if not file else "code evidence"
        note = f"degraded to unverified: reported as verified without {missing}"
    return Finding(
        audit_id=audit_id,
        severity=sev if sev in SEVERITIES else "info",
        category=str(f.get("category") or "other")[:64],
        title=str(f.get("title") or "")[:255],
        description=str(f.get("description") or ""),
        file=file,
        # The engine used to anchor findings by function or class only. With
        # the excerpt line-numbered, a backend can point at a line as well.
        line=_line_number(f.get("line")),
        anchor=str(f.get("anchor") or "")[:255],
        fingerprint=str(f.get("fingerprint") or "")[:16],
        code_snippet=snippet or None,
        verification_status=status,
        verification_note=note or None,
    )


def finding_to_dict(f: Finding) -> dict:
    d = {
        "id": f.id,
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "file": f.file,
        "line": f.line,
        "anchor": f.anchor,
        "fingerprint": f.fingerprint,
        "verification_status": f.verification_status,
    }
    if f.code_snippet:
        d["code_snippet"] = f.code_snippet
    if f.verification_note:
        d["verification_note"] = f.verification_note
    return d


def audit_to_dict(audit: Audit, include_findings: bool = False,
                  verified_only: bool = False) -> dict:
    d = {
        "id": audit.id,
        "repo_url": audit.repo_url,
        "branch": audit.branch,
        "commit_sha": audit.commit_sha,
        "trigger": audit.trigger,
        "status": audit.status,
        "language": audit.language or DEFAULT_LANGUAGE,
        "created_at": isoformat_utc(audit.created_at),
        "error": audit.error,
        "summary": audit.summary or empty_summary(),
    }
    if include_findings:
        findings = audit.findings
        # Counted before filtering, so the detail view can say "12 findings,
        # 9 of them backed by evidence" even when only those 9 are listed.
        d["verified_count"] = sum(1 for f in findings
                                  if f.verification_status == VERIFIED)
        if verified_only:
            findings = [f for f in findings if f.verification_status == VERIFIED]
        d["findings"] = [finding_to_dict(f) for f in findings]
    return d
