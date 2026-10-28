"""ORM models for audits and findings, plus dict serialisation helpers."""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (JSON, Boolean, DateTime, Float, ForeignKey, Integer,
                        String, Text, UniqueConstraint)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base

SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Findings are only presented as confirmed when they carry evidence from the
# audited repository; see verification_status on Finding.
VERIFIED = "verified"
UNVERIFIED = "unverified"

# How far a finding has been shown to hold (module 2). NULL means nothing has
# been shown: the finding has no evidence, or predates the evidence check.
EXISTS = "exists"
EPISTEMIC_STATUSES = (EXISTS, "reachable", "corroborated", "refuted", "inconclusive")
REFUTATION_METHODS = ("callgraph", "sanitizer", "reachability", "devil_advocate")
REFUTATION_RESULTS = ("refuted", "survived", "inconclusive")

# Views of a repository and how two of them can disagree (module 1).
VIEWS = ("human", "bytes", "machine", "llm", "published")
DIVERGENCE_KINDS = ("hidden_content", "unexpected_execution", "audit_blind_spot",
                    "release_mismatch")

CONFIDENCE = ("high", "medium", "low")

# Who might attack, and from where (module 5).
PERSONAS = ("anonymous", "authenticated_user", "malicious_contributor",
            "compromised_dependency", "manipulated_agent")
JEWEL_KINDS = ("secrets", "user_data", "deployment", "administration", "other")
DECLARED_BY = ("user", "suggested")

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
    # Counts over the coverage rows; NULL for audits from before they existed.
    coverage_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    project_id: Mapped[int | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True,
    )

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="audit", cascade="all, delete-orphan", order_by="Finding.id",
    )
    coverage: Mapped[list["Coverage"]] = relationship(
        cascade="all, delete-orphan", order_by="Coverage.id",
    )
    module_runs: Mapped[list["ModuleRun"]] = relationship(
        cascade="all, delete-orphan", order_by="ModuleRun.id",
    )
    project: Mapped["Project | None"] = relationship()


class Project(Base):
    """A repository as one owner audits it. NULL owner: the instance's own."""

    __tablename__ = "projects"
    __table_args__ = (UniqueConstraint("user_id", "repo_url",
                                       name="uq_projects_user_repo"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True,
    )
    repo_url: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False,
    )


class ModuleRun(Base):
    """One stage of an audit: what it did, what it cost, whether it worked."""

    __tablename__ = "module_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    module: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    backend: Mapped[str | None] = mapped_column(String(32), nullable=True)
    model: Mapped[str | None] = mapped_column(String(128), nullable=True)
    tokens_in: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    tokens_out: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False,
    )


class Coverage(Base):
    """One file of an audited checkout: whether the auditor was shown it."""

    __tablename__ = "coverage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    # A trailing slash marks a directory skipped as a whole (node_modules/).
    file: Mapped[str] = mapped_column(String(512), nullable=False)
    audited: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(String(255), nullable=False)
    # 1 runs automatically ... 6 tests, docs and data; see analysis/chunking.
    risk_tier: Mapped[int] = mapped_column(Integer, nullable=False)
    signals: Mapped[list | None] = mapped_column(JSON, nullable=True)


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
    # Findings are anchored by function or class, which survives a refactor.
    # line and line_end are where the snippet was found in the audited file
    # (analysis/evidence.py), and stay NULL when it could not be located.
    line: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
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
    # Module 2: how far the finding has been shown to hold.
    epistemic_status: Mapped[str | None] = mapped_column(
        String(16), nullable=True, index=True,
    )
    # Module 3: where it probably came from, and where it went.
    origin_commit: Mapped[str | None] = mapped_column(String(40), nullable=True)
    origin_confidence: Mapped[str | None] = mapped_column(String(8), nullable=True)
    # Declared in the origin commit's trailers; never established.
    ai_declared: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    fix_commit: Mapped[str | None] = mapped_column(String(40), nullable=True)
    zombie_of: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True,
    )
    # Module 5: who can trigger it, and what it is worth in context.
    personas: Mapped[list | None] = mapped_column(JSON, nullable=True)
    contextual_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)

    audit: Mapped[Audit] = relationship(back_populates="findings")
    hypothesis: Mapped["Hypothesis | None"] = relationship(
        cascade="all, delete-orphan", uselist=False,
    )


class Hypothesis(Base):
    """A finding stated so that it can be refuted: from where, to what, how."""

    __tablename__ = "hypotheses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, unique=True,
    )
    source: Mapped[str | None] = mapped_column(Text, nullable=True)
    sink: Mapped[str | None] = mapped_column(Text, nullable=True)
    path: Mapped[list | None] = mapped_column(JSON, nullable=True)
    preconditions: Mapped[list | None] = mapped_column(JSON, nullable=True)
    complete: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    attempts: Mapped[list["RefutationAttempt"]] = relationship(
        cascade="all, delete-orphan", order_by="RefutationAttempt.id",
    )


class RefutationAttempt(Base):
    __tablename__ = "refutation_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    hypothesis_id: Mapped[int] = mapped_column(
        ForeignKey("hypotheses.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    method: Mapped[str] = mapped_column(String(32), nullable=False)
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class ViewDivergence(Base):
    """Two views of the same file that disagree (module 1)."""

    __tablename__ = "view_divergences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    file: Mapped[str] = mapped_column(String(512), nullable=False)
    view_a: Mapped[str] = mapped_column(String(16), nullable=False)
    view_b: Mapped[str] = mapped_column(String(16), nullable=False)
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    evidence: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class CanaryRun(Base):
    """How many planted decoys the auditor found. Decoys are never findings."""

    __tablename__ = "canary_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    canaries_planted: Mapped[int] = mapped_column(Integer, nullable=False)
    canaries_found: Mapped[int] = mapped_column(Integer, nullable=False)
    integrity_score: Mapped[float] = mapped_column(Float, nullable=False)
    detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class ImmuneRule(Base):
    """A Semgrep rule learnt from a fix, validated against the history (module 3)."""

    __tablename__ = "immune_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True,
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_yaml: Mapped[str] = mapped_column(Text, nullable=False)
    source_fix_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    vulnerable_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    validated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    validation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    matches_history: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False,
    )


class FileLeverage(Base):
    """How much damage a change here could do, against who would notice (module 4)."""

    __tablename__ = "file_leverage"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    file: Mapped[str] = mapped_column(String(512), nullable=False)
    leverage_score: Mapped[float] = mapped_column(Float, nullable=False)
    oversight_score: Mapped[float] = mapped_column(Float, nullable=False)
    reasons: Mapped[list | None] = mapped_column(JSON, nullable=True)


class AgentCapability(Base):
    """Something an AI agent opening the repository would inherit."""

    __tablename__ = "agent_capabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    source_file: Mapped[str] = mapped_column(String(512), nullable=False)
    capability: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False)


class CrownJewel(Base):
    """What an attacker of this project would be after."""

    __tablename__ = "crown_jewels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    declared_by: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False,
    )


class AttackNode(Base):
    """A capability an attacker can hold (module 5)."""

    __tablename__ = "attack_nodes"
    __table_args__ = (UniqueConstraint("audit_id", "key",
                                       name="uq_attack_nodes_audit_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    key: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    persona: Mapped[str | None] = mapped_column(String(32), nullable=True)
    crown_jewel_id: Mapped[int | None] = mapped_column(
        ForeignKey("crown_jewels.id", ondelete="SET NULL"), nullable=True,
    )


class AttackEdge(Base):
    """One step between capabilities, and what makes it possible."""

    __tablename__ = "attack_edges"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    source_node_id: Mapped[int] = mapped_column(
        ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False,
    )
    target_node_id: Mapped[int] = mapped_column(
        ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False,
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=True,
    )
    divergence_id: Mapped[int | None] = mapped_column(
        ForeignKey("view_divergences.id", ondelete="CASCADE"), nullable=True,
    )
    leverage_id: Mapped[int | None] = mapped_column(
        ForeignKey("file_leverage.id", ondelete="CASCADE"), nullable=True,
    )
    persona: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cost: Mapped[float] = mapped_column(Float, nullable=False)
    cost_detail: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    tentative: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    explanation: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class AttackPath(Base):
    """The cheapest way from where a profile starts to a crown jewel."""

    __tablename__ = "attack_paths"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    audit_id: Mapped[str] = mapped_column(
        ForeignKey("audits.id", ondelete="CASCADE"), nullable=False, index=True,
    )
    persona: Mapped[str] = mapped_column(String(32), nullable=False)
    target_node_id: Mapped[int] = mapped_column(
        ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False,
    )
    cost: Mapped[float] = mapped_column(Float, nullable=False)
    edges: Mapped[list] = mapped_column(JSON, nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)


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
        # Where the evidence check found the snippet, never the model's claim.
        line=_line_number(f.get("line")),
        line_end=_line_number(f.get("line_end")),
        anchor=str(f.get("anchor") or "")[:255],
        fingerprint=str(f.get("fingerprint") or "")[:16],
        code_snippet=snippet or None,
        verification_status=status,
        verification_note=note or None,
        # The first rung of module 2: a finding whose snippet was found in the
        # file is known to exist. Anything less has not been shown at all.
        epistemic_status=EXISTS if status == VERIFIED else None,
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
        "line_end": f.line_end,
        "anchor": f.anchor,
        "fingerprint": f.fingerprint,
        "verification_status": f.verification_status,
        "epistemic_status": f.epistemic_status,
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
        "coverage": audit.coverage_summary,
        "project_id": audit.project_id,
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
        d["modules"] = [module_run_to_dict(r) for r in audit.module_runs]
    return d


def coverage_from_dict(audit_id: str, row: dict) -> Coverage:
    try:
        tier = int(row.get("risk_tier"))
    except (TypeError, ValueError):
        tier = 5
    signals = row.get("signals")
    return Coverage(
        audit_id=audit_id,
        file=str(row.get("file") or "")[:512],
        audited=bool(row.get("audited")),
        reason=str(row.get("reason") or "")[:255],
        risk_tier=tier if 1 <= tier <= 6 else 5,
        signals=signals if isinstance(signals, list) and signals else None,
    )


def coverage_to_dict(row: Coverage) -> dict:
    return {"file": row.file, "audited": row.audited, "reason": row.reason,
            "risk_tier": row.risk_tier, "signals": row.signals or []}


def project_for(session, user_id: int | None, repo_url: str) -> Project:
    """The project an audit of repo_url by this owner belongs to, made if new.

    NULL owners do not collide in a unique constraint, so the instance's own
    projects are looked up here rather than left to the database.
    """
    from sqlalchemy import select

    owner = Project.user_id.is_(None) if user_id is None else Project.user_id == user_id
    project = session.scalar(select(Project).where(owner, Project.repo_url == repo_url))
    if project is None:
        project = Project(user_id=user_id, repo_url=repo_url)
        session.add(project)
        session.flush()
    return project


def module_run_to_dict(run: ModuleRun) -> dict:
    return {"module": run.module, "status": run.status, "backend": run.backend,
            "model": run.model, "tokens_in": run.tokens_in,
            "tokens_out": run.tokens_out, "duration_ms": run.duration_ms,
            "error": run.error, "detail": run.detail}
