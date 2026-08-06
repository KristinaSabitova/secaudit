"""ORM models for audits and findings, plus dict serialisation helpers."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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
    # NULL means "whatever the repository's default branch is".
    branch: Mapped[str | None] = mapped_column(String(255), nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    trigger: Mapped[str] = mapped_column(String(16), default="manual")   # manual | webhook
    status: Mapped[str] = mapped_column(String(16), default="pending")   # pending | running | done | error
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[dict] = mapped_column(JSON, default=empty_summary)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="audit", cascade="all, delete-orphan", order_by="Finding.id",
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
    # The engine anchors findings to functions/classes, not line numbers,
    # so line stays NULL for engine-produced findings.
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    anchor: Mapped[str] = mapped_column(String(255), default="")
    fingerprint: Mapped[str] = mapped_column(String(16), default="")

    audit: Mapped[Audit] = relationship(back_populates="findings")


def finding_from_dict(audit_id: str, f: dict) -> Finding:
    sev = f.get("severity")
    return Finding(
        audit_id=audit_id,
        severity=sev if sev in SEVERITIES else "info",
        category=str(f.get("category") or "other")[:64],
        title=str(f.get("title") or "")[:255],
        description=str(f.get("description") or ""),
        file=str(f.get("file") or "")[:512],
        line=None,
        anchor=str(f.get("anchor") or "")[:255],
        fingerprint=str(f.get("fingerprint") or "")[:16],
    )


def finding_to_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "severity": f.severity,
        "category": f.category,
        "title": f.title,
        "description": f.description,
        "file": f.file,
        "line": f.line,
        "anchor": f.anchor,
        "fingerprint": f.fingerprint,
    }


def audit_to_dict(audit: Audit, include_findings: bool = False) -> dict:
    d = {
        "id": audit.id,
        "repo_url": audit.repo_url,
        "branch": audit.branch,
        "commit_sha": audit.commit_sha,
        "trigger": audit.trigger,
        "status": audit.status,
        "created_at": audit.created_at.isoformat() if audit.created_at else None,
        "error": audit.error,
        "summary": audit.summary or empty_summary(),
    }
    if include_findings:
        d["findings"] = [finding_to_dict(f) for f in audit.findings]
    return d
