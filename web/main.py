"""FastAPI app exposing the secaudit engine over HTTP."""

import json
import logging
import mimetypes
import os
import threading
import secrets
import shutil
import tempfile
import time
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import (BackgroundTasks, Cookie, Depends, FastAPI, Header,
                     HTTPException, Request, Response)
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session, aliased

from . import auth, runnerqueue, settings as settings_store
from .auth import AuthError, AuthUnavailable, NotInvited
from .db import get_session
from .engine import (AuditError, backend_config, backend_identity, backend_status,
                     run_audit, sanitize_error)
from .gitclone import (CloneError, check_repo_owner, clone_at_commit, clone_repo,
                       fetch_ref, validate_branch, validate_ref,
                       validate_repo_url)
from .models import (LANGUAGES, AgentCapability, AttackEdge, AttackNode, AttackPath,
                     Audit, CanaryRun, Component, component_to_dict, CrownJewel, FileLeverage, Finding, Hypothesis,
                     ImmuneRule, WhatIf, immune_rule_to_dict, what_if_to_dict,
                     ModuleRun, RefutationAttempt, User, ViewDivergence, audit_to_dict,
                     coverage_from_dict, coverage_to_dict, finding_from_dict,
                     finding_to_dict, jewel_to_dict, Project, project_for, summarize)
from .settings import InvalidOllamaURL, SecretsUnavailable
from .webhook import (
    EVENT_HEADER,
    SIGNATURE_HEADER,
    WebhookError,
    decode_payload,
    parse_pull_request_event,
    parse_push_event,
    verify_signature,
    webhook_secret,
)

# Importable once .engine has put the repository root on sys.path.
from analysis import attacker, evidence, falsify, immune, leverage, parallax  # noqa: E402
from analysis import (assessment, deadcode, deps, doc_claims, drift,  # noqa: E402
                      evidence_chain, mcp_audit, reports, secrets_scan, surface, taint,
                      pdf, trust, twin)
from .engine import engine as cli_engine  # noqa: E402
from . import prnotify, sandbox, scanproc, whatif  # noqa: E402

log = logging.getLogger(__name__)

INTERRUPTED = "interrupted: the service restarted while this audit was running"
BACKENDS = ("anthropic-api", "openai-api", "ollama", "claude-code")


def fail_interrupted_audits() -> int:
    """Close out audits the previous process was running when it stopped.

    Background tasks do not survive a restart, so anything still pending or
    running at startup would otherwise sit in that state forever.
    """
    session = get_session()
    try:
        stale = session.scalars(
            select(Audit).where(Audit.status.in_(("pending", "running")))
        ).all()
        for audit in stale:
            audit.status = "error"
            audit.error = INTERRUPTED
        for w in session.scalars(select(WhatIf).where(WhatIf.status == "running")).all():
            w.status, w.result = "error", {"error": INTERRUPTED}
        session.commit()
        return len(stale)
    finally:
        session.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    auth.check_startup_config()
    if auth.is_configured() and not auth.allowed_logins():
        log.warning(
            "%s is empty, so no GitHub account can sign in. Name the logins "
            "allowed, or set it to '%s' to accept anyone on purpose.",
            auth.ALLOWED_LOGINS_ENV, auth.OPEN_REGISTRATION,
        )
    fail_interrupted_audits()
    yield


TOOL_VERSION = "0.4.0"

app = FastAPI(title="secaudit web", version=TOOL_VERSION, lifespan=lifespan)


class AuditRequest(BaseModel):
    repo_url: str
    # The findings are written in this language by the backend itself; there is
    # no translation pass afterwards.
    language: str = "en"
    branch: str | None = None
    # Compare with this commit or branch instead of the previous audit (B14).
    base_ref: str | None = None
    # Audit exactly this commit, whatever the branch points at now.
    commit: str | None = None


class SettingsRequest(BaseModel):
    """Fields left unset are kept as they are."""
    backend: str | None = None
    model: str | None = None
    ollama_url: str | None = None
    api_key: str | None = None
    clear_api_key: bool = False


def db_session():
    session = get_session()
    try:
        yield session
    finally:
        session.close()


def _ms_since(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def record_llm_audit(session: Session, audit: Audit, backend: str | None,
                     model: str | None, usage: dict | None,
                     duration_ms: int | None, coverage_summary: dict | None) -> None:
    """The module run for the part of an audit that talks to a backend."""
    usage = usage if isinstance(usage, dict) else {}
    summary = coverage_summary if isinstance(coverage_summary, dict) else {}

    def tokens(key):
        try:
            return max(0, int(usage.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    session.add(ModuleRun(
        audit_id=audit.id, module="audit", status="ok", backend=backend,
        model=model, tokens_in=tokens("input_tokens"),
        tokens_out=tokens("output_tokens"),
        duration_ms=duration_ms if isinstance(duration_ms, int) else None,
        detail={k: summary[k] for k in ("requests", "failed_requests")
                if k in summary} or None,
    ))


def check_evidence(session: Session, audit: Audit, checkout: Path,
                   findings: list[dict], manifest) -> list[dict]:
    """Run the evidence check and record it as a module run."""
    start = time.monotonic()
    claimed = sum(1 for f in findings if f.get("verification_status") == "verified")
    evidence.verify_findings(checkout, findings, manifest)
    kept = sum(1 for f in findings if f.get("verification_status") == "verified")
    session.add(ModuleRun(
        audit_id=audit.id, module="evidence", status="ok",
        duration_ms=_ms_since(start),
        detail={"checked": len(findings), "claimed_verified": claimed,
                "downgraded": claimed - kept,
                "located": sum(1 for f in findings if f.get("line"))},
    ))
    return findings


def store_result(session: Session, audit: Audit, findings: list[dict],
                 coverage: list[dict] | None,
                 coverage_summary: dict | None,
                 rule_findings: list[dict] | None = None) -> list[tuple[Finding, dict]]:
    """Persist a finished audit: its findings, its coverage, and done.

    rule_findings come from this server's own deterministic scanners, never
    from the request: only they are stored with source "rule".

    Returns each stored finding with the dict it was made from, for the
    modules that work on findings once they have an id.
    """
    stored = []
    for f in findings:
        row = finding_from_dict(audit.id, f)
        session.add(row)
        stored.append((row, f))
    for f in rule_findings or []:
        f["fingerprint"] = cli_engine.make_fingerprint(f["category"], f["file"], f["anchor"])
        row = finding_from_dict(audit.id, f)
        row.source = assessment.SOURCE_RULE
        row.rule_id = str(f.get("rule_id") or "")[:64] or None
        row.detail = f.get("detail")
        session.add(row)
        stored.append((row, f))
    findings = list(findings) + list(rule_findings or [])
    for row in coverage or []:
        if isinstance(row, dict):
            session.add(coverage_from_dict(audit.id, row))
    audit.summary = summarize(findings)
    audit.coverage_summary = coverage_summary if isinstance(coverage_summary, dict) else None
    audit.status = "done"
    audit.error = None
    session.flush()
    return stored


def record_falsifiability(session: Session, audit: Audit, checkout: Path | None,
                          stored: list[tuple[Finding, dict]], backend: str | None,
                          model: str | None, usage: dict | None) -> None:
    """Module 2: try to refute every finding with evidence, and record how.

    Runs on this server's checkout, after the evidence check: only a finding
    whose snippet is really there exists, and only those are attacked. The
    devil's advocate's answer arrives with each finding as a claim; its quotes
    are checked here. A failure leaves the findings at exists — it never
    fails the audit, whose findings are already sound.
    """
    start = time.monotonic()
    usage = usage if isinstance(usage, dict) else {}
    by_status: dict[str, int] = {}
    hypotheses = 0
    try:
        index = None
        if checkout is not None and any(
                f.get("verification_status") == "verified"
                and str(f.get("file") or "").endswith(".py") for _, f in stored):
            index = falsify.Index(checkout)
        for row, f in stored:
            if checkout is None:
                outcome = {"hypothesis": falsify.normalize_hypothesis(f.get("hypothesis")),
                           "attempts": [], "status": row.epistemic_status}
            else:
                # The stored row has the verdict of the evidence check; the
                # dict may not, if the row's own rules downgraded it.
                f = {**f, "verification_status": row.verification_status,
                     "line": row.line, "line_end": row.line_end}
                outcome = falsify.assess(checkout, f, index)
            h = outcome["hypothesis"]
            if h:
                hypothesis = Hypothesis(finding_id=row.id, source=h["source"] or None,
                                        sink=h["sink"] or None, path=h["path"],
                                        preconditions=h["preconditions"],
                                        complete=h["complete"])
                session.add(hypothesis)
                session.flush()
                hypotheses += 1
                for a in outcome["attempts"]:
                    session.add(RefutationAttempt(
                        hypothesis_id=hypothesis.id, method=a["method"],
                        result=a["result"], evidence=a["evidence"],
                        note=(a["note"] or None) and a["note"][:2000]))
            row.epistemic_status = outcome["status"]
            if outcome["status"]:
                by_status[outcome["status"]] = by_status.get(outcome["status"], 0) + 1
        status, error = "ok", None
    except Exception as e:      # the findings stand without it
        log.exception("falsifiability failed for audit %s", audit.id)
        status, error = "error", sanitize_error(str(e))[:500]

    def tokens(key):
        try:
            return max(0, int(usage.get(key) or 0))
        except (TypeError, ValueError):
            return 0

    session.add(ModuleRun(
        audit_id=audit.id, module="falsifiability", status=status,
        backend=backend if usage.get("requested") else None,
        model=model if usage.get("requested") else None,
        tokens_in=tokens("input_tokens"), tokens_out=tokens("output_tokens"),
        duration_ms=_ms_since(start), error=error,
        detail={"items": hypotheses, "by_status": by_status,
                "devil_requested": tokens("requested"),
                "devil_error": sanitize_error(str(usage["error"]))[:200]
                if usage.get("error") else None},
    ))


def _count(value) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def record_parallax(session: Session, audit: Audit, checkout: Path | None,
                    coverage: list[dict] | None, coverage_summary: dict | None,
                    canary: dict | None, backend: str | None, model: str | None,
                    canary_source: str = "audit process") -> None:
    """Module 1: where the views of the repository disagree, and the canaries.

    The divergences are computed here, on this server's own checkout. The
    canary count comes from whoever held the key — the audit process or the
    owner's runner — and is recorded as what they reported. Like module 2, a
    failure is recorded on the module and never fails the audit.
    """
    start = time.monotonic()
    canary = canary if isinstance(canary, dict) else {}
    usage = canary.get("usage") if isinstance(canary.get("usage"), dict) else {}
    by_kind: dict[str, int] = {}
    items, release, integrity, left_out = 0, None, None, 0
    try:
        result = parallax.analyze(checkout, coverage, coverage_summary)
        for d in result["divergences"]:
            row = parallax.normalize_kind_severity(d)
            session.add(ViewDivergence(audit_id=audit.id, **row))
            by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
            items += 1
        release = result["published"]
        left_out = result.get("left_out") or 0
        status, error = "ok", None
    except Exception as e:      # the audit stands without it
        log.exception("parallax failed for audit %s", audit.id)
        status, error = "error", sanitize_error(str(e))[:500]

    planted, found = _count(canary.get("planted")), _count(canary.get("found"))
    if planted and not canary.get("error"):
        found = min(found, planted)
        integrity = round(found / planted, 3)
        decoys = canary.get("decoys") if isinstance(canary.get("decoys"), list) else []
        session.add(CanaryRun(
            audit_id=audit.id, canaries_planted=planted, canaries_found=found,
            integrity_score=integrity,
            # Kind, file and whether it was found: nothing of the decoy itself.
            detail={"decoys": [{"kind": str(d.get("kind") or "")[:40],
                                "file": str(d.get("file") or "")[:512],
                                "found": bool(d.get("found"))}
                               for d in decoys[:10] if isinstance(d, dict)],
                    "request": _count(canary.get("request")) or None,
                    "source": canary_source}))
    session.add(ModuleRun(
        audit_id=audit.id, module="parallax", status=status,
        backend=backend if planted else None, model=model if planted else None,
        tokens_in=_count(usage.get("input_tokens")),
        tokens_out=_count(usage.get("output_tokens")),
        duration_ms=_ms_since(start), error=error,
        detail={"items": items, "by_kind": by_kind, "published": release,
                "left_out": left_out,
                "integrity_score": integrity,
                "canary_skipped": str(canary.get("skipped"))[:200]
                if canary.get("skipped") else None,
                "canary_error": sanitize_error(str(canary["error"]))[:200]
                if canary.get("error") else None},
    ))


def previous_audit(session: Session, audit: Audit) -> Audit | None:
    """The last finished audit of the same project before this one."""
    if audit.project_id is None:
        return None
    return session.scalar(
        select(Audit).where(Audit.project_id == audit.project_id,
                            Audit.id != audit.id, Audit.status == "done",
                            Audit.created_at <= audit.created_at,
                            Audit.commit_sha.is_not(None))
        .order_by(Audit.created_at.desc()).limit(1))


def comparison_audit(session: Session, audit: Audit) -> Audit | None:
    """What an audit's changes are measured against: the audit it replays,
    the last audit of its base commit, or the previous audit."""
    if audit.replay_of:
        original = session.get(Audit, audit.replay_of)
        if original is not None:
            return original
    if audit.base_ref and audit.project_id is not None:
        same = session.scalar(select(Audit).where(
            Audit.project_id == audit.project_id, Audit.id != audit.id,
            Audit.status == "done", Audit.commit_sha == audit.base_ref)
            .order_by(Audit.created_at.desc()).limit(1))
        if same is not None:
            return same
        return None
    return previous_audit(session, audit)


def immune_context(session: Session, audit: Audit) -> dict | None:
    """What the audit process needs to propose rules for the fixes since the
    previous audit: that audit's commit and its findings shown to hold."""
    previous = previous_audit(session, audit)
    if previous is None:
        return None
    findings = []
    for f in previous.findings:
        d = finding_to_dict(f)
        if immune.evidenced(d):
            findings.append({k: d.get(k) for k in (
                "id", "fingerprint", "title", "category", "severity", "file",
                "line", "line_end", "code_snippet", "verification_status",
                "epistemic_status")})
    if not findings:
        return None
    return {"previous": findings, "previous_commit": previous.commit_sha}


def _set_provenance(checkout: Path, row: Finding, rev: str = "HEAD") -> bool:
    if row.verification_status != "verified" or not row.line:
        return False
    origin = immune.provenance(checkout, immune._norm_path(row.file), row.line,
                               row.line_end or row.line, rev)
    if not origin:
        return False
    row.origin_commit = origin["origin_commit"]
    row.origin_confidence = origin["origin_confidence"]
    row.ai_declared = origin["ai_declared"]
    return True


def _overlaps(row: Finding, match: dict) -> bool:
    if immune._norm_path(row.file) != match["file"] or not row.line:
        return False
    return row.line <= match["line_end"] and match["line"] <= (row.line_end or row.line)


def record_immune(session: Session, audit: Audit, checkout: Path | None,
                  stored: list[tuple[Finding, dict]], proposals: dict | None,
                  backend: str | None, model: str | None) -> None:
    """Module 3: provenance, the fixes since the last audit, and their rules.

    Everything decided here is decided on this server's checkout: which
    findings were fixed and by which commit, whether a proposed rule passes
    its test against the history, and what the project's validated rules
    catch now. The model only proposes rules; it decides none of this. Like
    the other modules, a failure is recorded and never fails the audit.
    """
    start = time.monotonic()
    proposals = proposals if isinstance(proposals, dict) else {}
    usage = proposals.get("usage") if isinstance(proposals.get("usage"), dict) else {}
    offered = proposals.get("proposals") if isinstance(proposals.get("proposals"), dict) else {}
    detail = {"items": 0, "provenance": 0, "ai_declared": 0, "fixed": 0,
              "rules_proposed": 0, "rules_validated": 0, "zombies": 0,
              "semgrep": bool(immune.semgrep_bin()), "notes": []}
    try:
        if checkout is None:
            raise immune.SemgrepError("the audited commit could not be checked out")
        for row, _ in stored:
            if _set_provenance(checkout, row):
                detail["provenance"] += 1
                detail["ai_declared"] += bool(row.ai_declared)

        previous = previous_audit(session, audit)
        if previous is not None and audit.project_id is not None:
            rows = {f.id: f for f in previous.findings}
            fixed = immune.find_fixed(checkout, [finding_to_dict(f) for f in rows.values()],
                                      previous.commit_sha)
            for entry in fixed:
                old = rows.get(entry["finding_id"])
                if old is None:
                    continue
                if not entry.get("fix_commit"):
                    if entry.get("reason"):
                        detail["notes"].append(f"{old.file}: {entry['reason']}")
                    continue
                old.fix_commit = entry["fix_commit"]
                detail["fixed"] += 1
                proposal = offered.get(old.fingerprint)
                if not isinstance(proposal, dict) or not entry.get("vulnerable_commit"):
                    continue
                rule = immune.normalize_rule(proposal.get("rule"), old.fingerprint,
                                             entry["file"])
                detail["rules_proposed"] += 1
                if rule is None:
                    validation = {"validated": False,
                                  "reason": "not a rule made only of pattern operators"}
                elif not detail["semgrep"]:
                    validation = {"validated": False, "reason": "semgrep is not installed"}
                else:
                    validation = immune.validate(checkout, rule, entry["file"],
                                                 entry["vulnerable_commit"],
                                                 entry["fix_commit"])
                validation["file"] = entry["file"]
                validation["explanation"] = str(proposal.get("explanation") or "")[:500]
                validation["rule"] = rule
                session.add(ImmuneRule(
                    project_id=audit.project_id, finding_id=old.id,
                    rule_id=(rule or {}).get("id", f"secaudit-immune-{old.fingerprint[:8]}")[:64],
                    rule_yaml=immune.to_yaml([rule]) if rule else "",
                    source_fix_commit=entry["fix_commit"],
                    vulnerable_commit=entry["vulnerable_commit"],
                    validated=bool(validation.get("validated")),
                    validation=validation, matches_history=[]))
                detail["rules_validated"] += bool(validation.get("validated"))
            session.flush()

        # Zombies: the same finding again, after a fix.
        fixed_before = {}
        if audit.project_id is not None:
            for f in session.scalars(
                    select(Finding).join(Audit, Finding.audit_id == Audit.id)
                    .where(Audit.project_id == audit.project_id,
                           Audit.id != audit.id, Finding.fix_commit.is_not(None))):
                fixed_before.setdefault(f.fingerprint, f)
        for row, _ in stored:
            old = fixed_before.get(row.fingerprint)
            if old is not None and row.verification_status == "verified":
                row.zombie_of = old.id
                detail["zombies"] += 1

        # And what the validated rules catch, whether the model saw it or not.
        # Validated is the test passing; only a rule a person approved is used.
        rules = list(session.scalars(select(ImmuneRule).where(
            ImmuneRule.project_id == audit.project_id,
            ImmuneRule.validated.is_(True),
            ImmuneRule.approved.is_(True)))) if audit.project_id is not None else []
        by_id = {r.rule_id: r for r in rules if (r.validation or {}).get("rule")}
        if by_id and detail["semgrep"]:
            matches = immune.run_semgrep([r.validation["rule"] for r in by_id.values()],
                                         checkout)
            for m in matches:
                rule = by_id.get(m["rule"])
                if rule is None:
                    continue
                history = list(rule.matches_history or [])
                history.append({"audit_id": audit.id, "file": m["file"],
                                "line": m["line"]})
                rule.matches_history = history[-50:]
                origin = session.get(Finding, rule.finding_id) if rule.finding_id else None
                hit = next((r for r, _ in stored if _overlaps(r, m)), None)
                if hit is not None:
                    # The pattern is back, but module 2 showed this one safe.
                    if hit.epistemic_status == falsify.REFUTED:
                        detail["refuted_matches"] = detail.get("refuted_matches", 0) + 1
                    elif hit.zombie_of is None and origin is not None:
                        hit.zombie_of = origin.id
                        detail["zombies"] += 1
                    continue
                code = immune.snippet_at(checkout, m["file"], m["line"], m["line_end"])
                if origin is None or not code.strip():
                    continue
                row = Finding(
                    audit_id=audit.id, severity=origin.severity,
                    category=origin.category,
                    title=f"Regression: {origin.title}"[:255],
                    description=(f"The validated rule {rule.rule_id}, learnt from the "
                                 f"fix {rule.source_fix_commit[:12]}, matches this code "
                                 f"again.\n\n{origin.description}"),
                    file=m["file"], line=m["line"], line_end=m["line_end"],
                    anchor=origin.anchor, fingerprint=origin.fingerprint,
                    code_snippet=code, verification_status="verified",
                    verification_note=f"matched by immune rule {rule.rule_id}"[:255],
                    epistemic_status=falsify.EXISTS, zombie_of=origin.id,
                    source="immune", rule_id=rule.rule_id[:64])
                session.add(row)
                session.flush()
                stored.append((row, finding_to_dict(row)))
                _set_provenance(checkout, row)
                detail["zombies"] += 1
                detail["regressions"] = detail.get("regressions", 0) + 1
            if detail.get("regressions"):
                audit.summary = summarize([d for _, d in stored])
        detail["items"] = detail["rules_validated"] + detail["zombies"]
        status, error = "ok", None
    except Exception as e:      # the audit stands without it
        log.exception("immune memory failed for audit %s", audit.id)
        status, error = "error", sanitize_error(str(e))[:500]
    detail["notes"] = detail["notes"][:10]
    if proposals.get("error"):
        detail["proposal_error"] = sanitize_error(str(proposals["error"]))[:200]
    requested = _count(proposals.get("requested"))
    session.add(ModuleRun(
        audit_id=audit.id, module="immune", status=status,
        backend=backend if requested else None, model=model if requested else None,
        tokens_in=_count(usage.get("input_tokens")),
        tokens_out=_count(usage.get("output_tokens")),
        duration_ms=_ms_since(start), error=error, detail=detail))


def record_leverage(session: Session, audit: Audit, checkout: Path | None,
                    stored: list[tuple[Finding, dict]]) -> None:
    """Module 4: leverage against oversight per file, and the agent surface.

    Computed on this server's checkout, with what the other modules already
    established: the findings shown to hold and the divergences of this
    audit add leverage to their files. GitHub is asked only with
    SECAUDIT_GITHUB_TOKEN, which never leaves this process. A failure is the
    module's, never the audit's.
    """
    start = time.monotonic()
    detail = {"items": 0}
    try:
        if checkout is None:
            raise RuntimeError("the audited commit could not be checked out")
        findings: dict[str, int] = {}
        for row, _ in stored:
            if row.verification_status == "verified" and \
                    row.epistemic_status in immune.EVIDENCED and row.file:
                rel = immune._norm_path(row.file)
                findings[rel] = findings.get(rel, 0) + 1
        session.flush()
        divergences: dict[str, list[str]] = {}
        for d in session.scalars(select(ViewDivergence)
                                 .where(ViewDivergence.audit_id == audit.id)):
            divergences.setdefault(d.file, []).append(d.kind)
        result = leverage.analyze(checkout, parallax.repository_texts(checkout),
                                  findings, divergences, audit.repo_url)
        for r in result["files"]:
            reasons = list(r["reasons"])
            if r["last_commit"]:
                reasons.append({"side": "meta", "code": "last_commit", "delta": 0,
                                "args": {"commit": r["last_commit"]}})
            session.add(FileLeverage(audit_id=audit.id, file=r["file"][:512],
                                     leverage_score=r["leverage_score"],
                                     oversight_score=r["oversight_score"],
                                     reasons=reasons))
        caps = []
        for c in result["agent"]["capabilities"]:
            row = AgentCapability(audit_id=audit.id, source_file=c["source_file"][:512],
                                  capability=c["capability"], detail=c["detail"])
            session.add(row)
            caps.append(row)
        session.flush()
        combos = [{"kind": c["kind"], "severity": c["severity"],
                   "unattended": c["unattended"],
                   "steps": [caps[i].id for i in c["steps"]]}
                  for c in result["agent"]["combinations"]]
        fragile = sum(1 for r in result["files"]
                      if r["leverage_score"] >= 0.7 and r["oversight_score"] < 0.3)
        github = result["github"]
        detail = {"items": fragile + len(combos), "fragile": fragile,
                  "files": len(result["files"]), "left_out": result["left_out"],
                  "codeowners": result["codeowners"], "history": result["history"],
                  "github": {**github, "error": sanitize_error(github["error"])[:200]
                             if github["error"] else None},
                  "capabilities": len(caps), "combinations": combos}
        status, error = "ok", None
    except Exception as e:      # the audit stands without it
        log.exception("leverage failed for audit %s", audit.id)
        status, error = "error", sanitize_error(str(e))[:500]
    session.add(ModuleRun(audit_id=audit.id, module="leverage", status=status,
                          duration_ms=_ms_since(start), error=error, detail=detail))


JEWEL_KINDS = tuple(attacker.JEWEL_KINDS)
DISMISSED = "dismissed"         # a suggestion the owner turned down


def suggest_crown_jewels(session: Session, audit: Audit, texts: dict,
                         leverage_rows: list[dict], findings: list[dict]) -> None:
    """Add what the repository points at as crown jewels, unless the owner
    already declared or turned down a jewel of that kind."""
    if audit.project is None:
        return
    taken = {j.kind for j in audit.project.crown_jewels}
    for s in attacker.suggest_jewels(texts, leverage_rows, findings, audit.language or "en"):
        if s["kind"] not in taken:
            audit.project.crown_jewels.append(CrownJewel(
                kind=s["kind"], target=s["target"][:512], declared_by="suggested"))
            taken.add(s["kind"])
    session.flush()


def record_attacker(session: Session, audit: Audit, checkout: Path | None,
                    stored: list[tuple[Finding, dict]]) -> None:
    """Module 5: the attack graph, the cheapest paths and the fix that cuts most.

    Everything comes from what the other modules stored for this audit:
    findings shown to hold, divergences, the leverage map and the agent
    surface. No model is asked. A failure is the module's, never the audit's.
    """
    start = time.monotonic()
    detail = {"items": 0}
    try:
        session.flush()
        findings = []
        for row, _ in stored:
            d = finding_to_dict(row)
            findings.append(d)
        divergences = [{"id": v.id, "kind": v.kind, "file": v.file, "detail": v.detail}
                       for v in session.scalars(select(ViewDivergence)
                                                .where(ViewDivergence.audit_id == audit.id))]
        lev_rows = list(session.scalars(select(FileLeverage)
                                        .where(FileLeverage.audit_id == audit.id)))
        leverage_rows = [{"id": r.id, "file": r.file, "leverage": r.leverage_score,
                          "oversight": r.oversight_score, "reasons": r.reasons or []}
                         for r in lev_rows]
        caps = [{"id": c.id, "capability": c.capability, "source_file": c.source_file}
                for c in session.scalars(select(AgentCapability)
                                         .where(AgentCapability.audit_id == audit.id))]
        lev_run = session.scalar(select(ModuleRun).where(
            ModuleRun.audit_id == audit.id, ModuleRun.module == "leverage")
            .order_by(ModuleRun.id.desc()).limit(1))
        combos = ((lev_run.detail or {}).get("combinations") or []) if lev_run else []
        texts = parallax.repository_texts(checkout) if checkout is not None else {}
        suggest_crown_jewels(session, audit, texts, leverage_rows, findings)
        jewels = [j for j in (audit.project.crown_jewels if audit.project else [])
                  if j.declared_by != DISMISSED]
        if not jewels:              # no project: what every application holds
            jewels = [CrownJewel(kind="secrets", target="secrets", declared_by="suggested")]
        result = attacker.analyze(findings, divergences, leverage_rows,
                                  {"capabilities": caps, "combinations": combos},
                                  [{"id": j.id, "kind": j.kind} for j in jewels])

        jewel_of = {}
        for j in jewels:
            jewel_of.setdefault(attacker.JEWEL_KINDS.get(j.kind), j.id)
        nodes = {}
        for key in result["nodes"]:
            persona = key.split(":", 1)[1] if key.startswith("start:") else None
            label = (f"starts as {persona.replace('_', ' ')}" if persona
                     else attacker.LABELS.get(key, key))
            node = AttackNode(audit_id=audit.id, key=key, label=label, persona=persona,
                              crown_jewel_id=jewel_of.get(key))
            session.add(node)
            nodes[key] = node
        session.flush()
        # Only the edges some path takes, and the steps of each flaw: the rest
        # of the structural graph is the same for every repository.
        keep = sorted(result["used"] | {i for i, e in enumerate(result["edges"])
                                        if not e.structural})
        edge_rows = {}
        for i in keep:
            e = result["edges"][i]
            row = AttackEdge(audit_id=audit.id, source_node_id=nodes[e.source].id,
                             target_node_id=nodes[e.target].id, finding_id=e.finding_id,
                             divergence_id=e.divergence_id, leverage_id=e.leverage_id,
                             persona=e.persona, cost=e.cost, cost_detail=e.cost_detail,
                             tentative=e.tentative,
                             explanation={**e.explanation,
                                          "structural": e.structural,
                                          "capability_ids": e.capability_ids})
            session.add(row)
            edge_rows[i] = row
        session.flush()
        for p in result["paths"]:
            session.add(AttackPath(audit_id=audit.id, persona=p["persona"],
                                   target_node_id=nodes[p["target"]].id, cost=p["cost"],
                                   edges=[edge_rows[i].id for i in p["edges"]],
                                   severity=p["severity"]))
        for row, _ in stored:
            c = result["contextual"].get(row.id)
            if c:
                row.contextual_severity = c["severity"]
                row.personas = c["personas"]
        # Module 4 counts being on an attack path as leverage.
        for r in lev_rows:
            if r.file in result["attack_files"] and not any(
                    x.get("code") == "attack_path" for x in r.reasons or []):
                r.leverage_score = round(min(1.0, r.leverage_score + 0.1), 3)
                r.reasons = [*(r.reasons or []), {"side": "leverage", "code": "attack_path",
                                                  "delta": 0.1, "args": {}}]

        def fix_label(fix):
            kind, ident = fix["type"], fix["id"]
            if kind == "finding":
                f = next((r for r, _ in stored if r.id == ident), None)
                return {"title": f.title if f else None, "file": f.file if f else None}
            if kind == "divergence":
                v = next((d for d in divergences if d["id"] == ident), None)
                return {"file": v["file"] if v else None, "kind": v["kind"] if v else None}
            if kind == "leverage":
                r = next((x for x in leverage_rows if x["id"] == ident), None)
                return {"file": r["file"] if r else None}
            return {"files": sorted({c["source_file"] for c in caps if c["id"] in ident})}

        cut = [{**c, **fix_label(c["fix"])} for c in result["min_cut"]]
        by_severity: dict[str, int] = {}
        for p in result["paths"]:
            by_severity[p["severity"]] = by_severity.get(p["severity"], 0) + 1
        detail = {"items": len(result["paths"]), "by_severity": by_severity,
                  "min_cut": cut, "jewels": sorted({j.kind for j in jewels}),
                  "edges": len(edge_rows)}
        status, error = "ok", None
    except Exception as e:      # the audit stands without it
        log.exception("attacker view failed for audit %s", audit.id)
        status, error = "error", sanitize_error(str(e))[:500]
    session.add(ModuleRun(audit_id=audit.id, module="attacker", status=status,
                          duration_ms=_ms_since(start), error=error, detail=detail))


def _overlap(a: dict, b: dict) -> bool:
    if immune._norm_path(a.get("file") or "") != immune._norm_path(b.get("file") or ""):
        return False
    if not a.get("line") or not b.get("line"):
        return False
    return a["line"] <= (b.get("line_end") or b["line"]) and \
        b["line"] <= (a.get("line_end") or a["line"])


def run_rule_scanners(session: Session, audit: Audit, checkout: Path | None,
                      model_findings: list[dict]) -> list[dict]:
    """Every deterministic scanner, in its own limited process (web/scanproc).

    Secrets, dependencies, the MCP auditor, taint, the attack surface, the
    documentation's claims and apparently unused code are each their own
    module run, and each failure is its own: the audit stands without them.
    What they return as findings carry source "rule" and go through the same
    evidence check as the model's (without a manifest: nothing was "sent"
    for a rule). Where the model already reported the same lines in the same
    category, the rule's copy is dropped.

    The only network calls are made here, in the server, after the scan and
    each behind its own opt-in: OSV.dev (SECAUDIT_OSV_CHECK) and the package
    registries (SECAUDIT_ABANDONED_CHECK). Only package names and versions go.
    """
    language = audit.language or "en"
    out: list[dict] = []
    scan, scan_error = None, "the audited commit could not be checked out"
    started = time.monotonic()
    if checkout is not None:
        try:
            scan = scanproc.run_scan(checkout, language, int(immune_history_depth()))
        except scanproc.ScanError as e:
            log.warning("scanners failed for audit %s: %s", audit.id, e)
            scan_error = str(e)
    scan_ms = _ms_since(started)

    def duplicate(f: dict) -> bool:
        return any(m.get("category") == f.get("category") and _overlap(m, f)
                   for m in model_findings)

    def run(module, key, fn):
        start = time.monotonic()
        try:
            if scan is None:
                raise RuntimeError(scan_error)
            part = scan.get(key)
            if part is None:
                raise RuntimeError((scan.get("errors") or {}).get(key)
                                   or "the scanner returned nothing")
            found, detail = fn(part)
            if found:
                evidence.verify_findings(checkout, found, None)
            out.extend(found)
            detail = {"items": len(found) if found else detail.pop("items", 0), **detail,
                      "isolated": True, "scan_ms": scan_ms,
                      "read": scan.get("read")}
            status, error = "ok", None
        except Exception as e:      # the audit stands without it
            log.exception("%s failed for audit %s", module, audit.id)
            detail, status, error = {"items": 0}, "error", sanitize_error(str(e))[:500]
        session.add(ModuleRun(audit_id=audit.id, module=module, status=status,
                              duration_ms=_ms_since(start), error=error, detail=detail))

    def secrets(part):
        found = [f for f in part["findings"] if not duplicate(f)]
        history = part["timeline"]
        present = {(f.get("detail") or {}).get("secret_id") for f in part["findings"]}
        for s in history["secrets"]:
            # The checkout itself is the better witness of what is there now.
            s["present_at_head"] = s["present_at_head"] or s["secret_id"] in present
        return found, {**part["summary"], "timeline": history,
                       "history_only": sum(1 for s in history["secrets"]
                                           if not s["present_at_head"])}

    def dependencies(part):
        inv = part["inventory"]
        osv = {"queried": False, "enabled": deps.osv_enabled()}
        if deps.osv_enabled():
            osv.update(deps.query_osv(inv["components"]))
        maintenance = {"queried": False, "enabled": deps.abandoned_enabled()}
        if deps.abandoned_enabled():
            maintenance.update(deps.query_abandoned(inv["components"]))
        for c in inv["components"]:
            session.add(Component(audit_id=audit.id, ecosystem=c["ecosystem"],
                                  name=c["name"][:255], version=(c["version"] or None)
                                  and str(c["version"])[:128], direct=bool(c["direct"]),
                                  scope=c["scope"], manifest=c["manifest"][:512],
                                  purl=c["purl"][:512], vulns=c.get("vulns"),
                                  maintenance=c.get("maintenance")))
        found = part["signals"] + \
            deps.vulnerability_findings(inv["components"], language) + \
            deps.maintenance_findings(inv["components"], language,
                                      part.get("manifest_texts"))
        by_eco: dict[str, int] = {}
        for c in inv["components"]:
            by_eco[c["ecosystem"]] = by_eco.get(c["ecosystem"], 0) + 1
        return found, {"components": len(inv["components"]),
                       "direct": sum(1 for c in inv["components"] if c["direct"]),
                       "by_ecosystem": by_eco, "manifests": inv["manifests"][:50],
                       "truncated": inv["truncated"], "osv": osv,
                       "maintenance": maintenance,
                       "transitive_note": "transitive" if any(
                           not c["direct"] for c in inv["components"]) else "direct_only",
                       "ghosts": part["ghosts"], "version": deps.DEPS_VERSION}

    def mcp(part):
        inv = part["inventory"]
        inv["tools"] = inv["tools"][:200]
        return part["findings"], {"detected": part["detected"],
                                  "by_category": part["by_category"],
                                  "inventory": inv, "taxonomy": part["taxonomy"],
                                  "version": part["version"]}

    def taint_(part):
        found = [f for f in part.pop("findings") if not duplicate(f)]
        return found, part

    def plain(part):
        return [], {"items": len(part.get("items") or []), **part}

    run("secrets", "secrets", secrets)
    run("dependencies", "dependencies", dependencies)
    run("mcp", "mcp", mcp)
    run("taint", "taint", taint_)
    run("surface", "surface", plain)
    run("claims", "claims", plain)
    run("deadcode", "deadcode", plain)
    return out


def immune_history_depth() -> str:
    from .gitclone import history_depth
    return history_depth()


def finding_changes(session: Session, audit: Audit) -> tuple[Audit | None, dict]:
    """The audit compared with, and the findings new, fixed, persisting and
    reintroduced against it."""
    previous = comparison_audit(session, audit)
    fixed_before = set()
    if audit.project_id is not None:
        fixed_before = {fp for (fp,) in session.execute(
            select(Finding.fingerprint).join(Audit, Finding.audit_id == Audit.id)
            .where(Audit.project_id == audit.project_id, Audit.id != audit.id,
                   Finding.fix_commit.is_not(None)))}
    current = [finding_to_dict(f) for f in audit.findings]
    before = [finding_to_dict(f) for f in previous.findings] if previous else []
    return previous, drift.finding_diff(before, current, fixed_before)


def notify_pull_request(session: Session, audit_id: str) -> None:
    try:
        _notify_pull_request(session, audit_id)
    except Exception:           # the audit is stored; a report failure stays here
        log.exception("could not record the pull request report for %s", audit_id)
        session.rollback()


def _notify_pull_request(session: Session, audit_id: str) -> None:
    """Report a pull request's audit back on the pull request, when enabled.

    After the audit is stored and committed: a GitHub failure is recorded on
    the module run and never touches the audit."""
    audit = session.get(Audit, audit_id)
    if audit is None or audit.status != "done" or not audit.pr_number or \
            not prnotify.enabled():
        return
    start = time.monotonic()
    try:
        _, diff = finding_changes(session, audit)
        run = next((m for m in reversed(audit.module_runs) if m.module == "drift"), None)
        drift_items = ((run.detail or {}).get("drift") or []) if run else []
        base = os.environ.get("SECAUDIT_PUBLIC_URL", "").rstrip("/")
        link = f"{base}/#summary/{audit.id}" if base.startswith("https://") else None
        detail = prnotify.notify(audit.pr_repo, audit.pr_number, audit.commit_sha, diff,
                                 drift_items, audit.language or "en", link, audit.base_ref)
        status, error = "ok", None
    except Exception as e:
        log.warning("pull request report failed for audit %s: %s", audit.id, e)
        detail, status, error = {"posted": False}, "error", sanitize_error(str(e))[:500]
    session.add(ModuleRun(audit_id=audit.id, module="pr_report", status=status,
                          duration_ms=_ms_since(start), error=error,
                          detail={"items": 1 if detail.get("posted") else 0, **detail}))
    session.commit()


def record_drift(session: Session, audit: Audit, checkout: Path | None) -> None:
    """B14/C24: what changed since the previous audit, and what got weaker."""
    start = time.monotonic()
    try:
        if checkout is None:
            raise RuntimeError("the audited commit could not be checked out")
        previous = comparison_audit(session, audit)
        base = previous.commit_sha if previous else None
        if audit.base_ref:
            # A pull request's base, or one chosen: fetched if not already here.
            base = audit.base_ref
            if not drift._has_commit(checkout, base):
                base = fetch_ref(checkout, base) or base
        result = drift.compare(checkout, base, audit.language or "en")
        result["previous_audit"] = previous.id if previous and not audit.base_ref else None
        result["base_ref"] = audit.base_ref
        result["pr_number"] = audit.pr_number
        detail = {"items": len(result.get("drift") or []), **result}
        status, error = "ok", None
    except Exception as e:
        log.exception("drift failed for audit %s", audit.id)
        detail, status, error = {"items": 0}, "error", sanitize_error(str(e))[:500]
    session.add(ModuleRun(audit_id=audit.id, module="drift", status=status,
                          duration_ms=_ms_since(start), error=error, detail=detail))


def execute_audit(audit_id: str) -> None:
    """Background task: clone the repo, run the engine, persist the outcome."""
    session = get_session()
    try:
        audit = session.get(Audit, audit_id)
        if audit is None:
            return
        owner = audit.user_id     # None for webhook audits: the instance default
        try:
            config = backend_config(settings_store.config_overrides(session, owner))
            # Travels with the rest of the engine config into the audit
            # process, which builds the prompt from it.
            config["language"] = audit.language
            config["immune"] = immune_context(session, audit)
            credentials = settings_store.credentials(session, owner)
        except SecretsUnavailable as e:
            audit.status = "error"
            audit.error = str(e)
            session.commit()
            return
        if config.get("backend") == runnerqueue.RUNNER_BACKEND:
            # This backend runs a binary signed in on someone's own machine,
            # which the server is not. Leave it queued for that user's runner.
            return
        with tempfile.TemporaryDirectory(prefix="secaudit-") as tmp:
            dest = Path(tmp) / "repo"
            try:
                audit.commit_sha = (
                    clone_at_commit(audit.repo_url, dest, audit.pinned_commit)
                    if audit.pinned_commit else
                    clone_repo(audit.repo_url, dest, branch=audit.branch))
                audit.status = "running"
                session.commit()
                start = time.monotonic()
                result = run_audit(dest, config, credentials)
                record_llm_audit(session, audit, *backend_identity(config),
                                 result.get("usage"), _ms_since(start),
                                 result.get("coverage_summary"))
                # Checked here, against this server's own checkout, not by
                # the process that talked to the backend.
                findings = check_evidence(session, audit, dest, result["findings"],
                                          result.get("manifest"))
                rules = run_rule_scanners(session, audit, dest, findings)
                stored = store_result(session, audit, findings, result.get("coverage"),
                                      result.get("coverage_summary"), rules)
                record_falsifiability(session, audit, dest, stored,
                                      *backend_identity(config),
                                      result.get("refutation_usage"))
                record_parallax(session, audit, dest, result.get("coverage"),
                                result.get("coverage_summary"), result.get("canary"),
                                *backend_identity(config))
                record_immune(session, audit, dest, stored, result.get("immune"),
                              *backend_identity(config))
                record_leverage(session, audit, dest, stored)
                record_attacker(session, audit, dest, stored)
                record_drift(session, audit, dest)
            except (CloneError, AuditError) as e:
                audit.status = "error"
                audit.error = sanitize_error(str(e))
                session.commit()
                return
            except Exception as e:  # never leave an audit stuck in "running"
                session.rollback()          # nothing half-stored survives
                audit.status = "error"
                audit.error = sanitize_error(f"internal error: {e}")
                session.commit()
                return
        session.commit()
        notify_pull_request(session, audit_id)
    finally:
        session.close()


def queue_audit(session: Session, background_tasks: BackgroundTasks, repo_url: str,
                trigger: str, branch: str | None = None,
                commit_sha: str | None = None, user_id: int | None = None,
                language: str = "en", base_ref: str | None = None,
                pinned_commit: str | None = None, replay_of: str | None = None,
                pr_number: int | None = None, pr_repo: str | None = None) -> Audit:
    """Record a pending audit and hand it to a background worker.

    commit_sha is what the caller announced; the worker replaces it with the
    sha it actually checked out. pinned_commit, when given, is the one it
    checks out: a replay or a pull request's head.
    """
    audit = Audit(repo_url=repo_url, branch=branch, trigger=trigger,
                  commit_sha=commit_sha, user_id=user_id, language=language,
                  base_ref=base_ref, pinned_commit=pinned_commit, replay_of=replay_of,
                  pr_number=pr_number, pr_repo=pr_repo,
                  project_id=project_for(session, user_id, repo_url).id)
    session.add(audit)
    session.commit()
    background_tasks.add_task(execute_audit, audit.id)
    return audit


# ---------------------------------------------------------------------------
# Sign-in
# ---------------------------------------------------------------------------

OAUTH_STATE_COOKIE = "secaudit_oauth_state"


def public_url(request: Request) -> str:
    """The address browsers reach this instance at, for the OAuth redirect."""
    configured = os.environ.get("SECAUDIT_PUBLIC_URL", "").rstrip("/")
    if configured:
        return configured
    # Behind the reverse proxy the scheme is only in the forwarded header.
    scheme = request.headers.get("x-forwarded-proto") or request.url.scheme
    return f"{scheme}://{request.headers.get('host', request.url.netloc)}"


def redirect_uri(request: Request) -> str:
    return f"{public_url(request)}/api/auth/callback"


def bearer_token(authorization: str | None) -> str | None:
    """The token out of an Authorization header, if it carries one.

    'Bearer' with nothing after it is a malformed header, not a token: it has
    to read as absent rather than raise on the missing second half.
    """
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer":
        return None
    return token.strip() or None


def current_user(session: Session = Depends(db_session),
                 secaudit_session: str | None = Cookie(default=None),
                 authorization: str | None = Header(default=None)) -> User | None:
    owner = auth.single_user(session)
    if owner is not None:
        return owner
    user = auth.user_for_token(session, secaudit_session)
    if user is None:
        # A service token — a runner, the MCP server — stands in for the
        # cookie: it names the same account and is stored only as a hash. It
        # therefore carries the same authority as a browser session, so it is
        # a credential of the same weight and not a lesser, runner-only one.
        user = runnerqueue.user_for_token(session, bearer_token(authorization))
    # The guest list is what decides who may use the instance, so a credential
    # issued before a login was taken off it stops working with it.
    if user is not None and not auth.is_invited(user.login):
        return None
    return user


def require_user(user: User | None = Depends(current_user)) -> User:
    if user is None:
        raise HTTPException(status_code=401, detail="sign in to use secaudit")
    return user


@app.get("/api/auth/login")
def auth_login(request: Request):
    try:
        url = auth.authorize_url(secrets.token_urlsafe(16), redirect_uri(request))
    except AuthUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))
    # The state is echoed back by GitHub and compared with this cookie, so a
    # callback the user did not initiate cannot sign anyone in.
    state = url.split("state=")[1].split("&")[0]
    response = RedirectResponse(url, status_code=307)
    response.set_cookie(OAUTH_STATE_COOKIE, state, httponly=True, samesite="lax",
                        secure=public_url(request).startswith("https://"),
                        max_age=600)
    return response


@app.get("/api/auth/callback")
def auth_callback(request: Request, code: str = "", state: str = "",
                  session: Session = Depends(db_session),
                  secaudit_oauth_state: str | None = Cookie(default=None)):
    if not code or not state or state != secaudit_oauth_state:
        raise HTTPException(status_code=400, detail="invalid sign-in callback")
    try:
        profile = auth.exchange_code(code, redirect_uri(request))
    except AuthUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))
    except AuthError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        user = auth.upsert_user(session, profile)
    except NotInvited as e:
        raise HTTPException(status_code=403, detail=str(e))
    token = auth.start_session(session, user)
    response = RedirectResponse("/", status_code=303)
    response.set_cookie(auth.COOKIE_NAME, token, httponly=True,
                        samesite="lax", max_age=auth.SESSION_DAYS * 86400,
                        secure=public_url(request).startswith("https://"))
    response.delete_cookie(OAUTH_STATE_COOKIE)
    return response


@app.post("/api/auth/logout")
def auth_logout(session: Session = Depends(db_session),
                secaudit_session: str | None = Cookie(default=None)):
    auth.end_session(session, secaudit_session)
    response = Response(status_code=204)
    response.delete_cookie(auth.COOKIE_NAME)
    return response


@app.get("/api/me")
def me(user: User | None = Depends(current_user)):
    return {
        "user": auth.user_to_dict(user),
        "sign_in_enabled": auth.is_configured(),
        "single_user": auth.single_user_login() is not None,
    }


@app.post("/api/audits", status_code=202)
def create_audit(req: AuditRequest, background_tasks: BackgroundTasks,
                 user: User = Depends(require_user),
                 session: Session = Depends(db_session)):
    try:
        url = validate_repo_url(req.repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        check_repo_owner(url)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    language = (req.language or "en").lower()
    if language not in LANGUAGES:
        raise HTTPException(status_code=400,
                            detail=f"unsupported language '{req.language}'. "
                                   f"Valid: {', '.join(LANGUAGES)}")

    try:
        branch = validate_branch(req.branch) if req.branch else None
        base_ref = validate_ref(req.base_ref) if req.base_ref else None
        commit = validate_ref(req.commit) if req.commit else None
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if commit and len(commit) != 40:
        raise HTTPException(status_code=400, detail="commit must be a full 40-character sha")
    audit = queue_audit(session, background_tasks, url, "manual",
                        user_id=user.id, language=language, branch=branch,
                        base_ref=base_ref, pinned_commit=commit)
    return audit_to_dict(audit)


@app.post("/api/webhook/github", status_code=202)
async def github_webhook(request: Request, response: Response,
                         background_tasks: BackgroundTasks,
                         session: Session = Depends(db_session)):
    secret = webhook_secret()
    if secret is None:
        raise HTTPException(status_code=503,
                            detail="GITHUB_WEBHOOK_SECRET is not configured")

    # Authenticate the raw body before it is parsed or acted upon.
    body = await request.body()
    try:
        verify_signature(body, request.headers.get(SIGNATURE_HEADER), secret)
    except WebhookError as e:
        raise HTTPException(status_code=401, detail=str(e))

    event = request.headers.get(EVENT_HEADER, "")
    if event == "ping":
        response.status_code = 200
        return {"status": "pong"}
    if event not in ("push", "pull_request"):
        response.status_code = 200
        return {"status": "ignored", "reason": f"unsupported event '{event}'"}

    try:
        payload = decode_payload(body, request.headers.get("content-type", ""))
        push = parse_push_event(payload) if event == "push" else \
            parse_pull_request_event(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if event == "pull_request":
        if push is None:
            response.status_code = 200
            return {"status": "ignored", "reason": "pull request action not audited"}
        try:
            # The head may be a fork: it is what gets cloned, so its owner counts.
            check_repo_owner(push["repo_url"])
        except (PermissionError, ValueError) as e:
            response.status_code = 200
            return {"status": "ignored", "reason": str(e)}
        language = os.environ.get("SECAUDIT_DEFAULT_LANGUAGE", "en").lower()
        audit = queue_audit(session, background_tasks, push["repo_url"], "webhook",
                            branch=push["branch"], commit_sha=push["sha"],
                            language=language if language in LANGUAGES else "en",
                            base_ref=push["base_sha"], pinned_commit=push["sha"],
                            pr_number=push["number"],
                            pr_repo=prnotify.valid_repo(push.get("base_repo")))
        return audit_to_dict(audit)
    if push is None:
        response.status_code = 200
        return {"status": "ignored", "reason": "push does not update a branch"}
    try:
        check_repo_owner(push["repo_url"])
    except (PermissionError, ValueError) as e:
        # Signed by GitHub, so answered; but nothing is cloned for it.
        response.status_code = 200
        return {"status": "ignored", "reason": str(e)}

    # Nobody picks a language for a webhook audit, so the instance sets one.
    language = os.environ.get("SECAUDIT_DEFAULT_LANGUAGE", "en").lower()
    audit = queue_audit(session, background_tasks, push["repo_url"], "webhook",
                        branch=push["branch"], commit_sha=push["sha"],
                        language=language if language in LANGUAGES else "en")
    return audit_to_dict(audit)


@app.get("/api/audits")
def list_audits(user: User = Depends(require_user),
                session: Session = Depends(db_session)):
    query = select(Audit).order_by(Audit.created_at.desc())
    if not user.is_admin:
        query = query.where(Audit.user_id == user.id)
    return [audit_to_dict(a) for a in session.scalars(query).all()]


@app.get("/api/stats/refutation")
def refutation_stats(user: User = Depends(require_user),
                     session: Session = Depends(db_session)):
    """How often each backend and model's findings fell when tested.

    Counted over the findings that were actually tested: backed by code,
    stated as a complete hypothesis, and attacked at least once. The share refuted is a measured false
    positive rate of that model, not a guess at one.
    """
    run = aliased(ModuleRun)
    query = (select(run.backend, run.model, Finding.epistemic_status,
                    func.count(Finding.id))
             .join(Audit, Audit.id == Finding.audit_id)
             .join(run, (run.audit_id == Audit.id) & (run.module == "audit"))
             .join(Hypothesis, Hypothesis.finding_id == Finding.id)
             .where(Hypothesis.complete.is_(True), Hypothesis.attempts.any(),
                    Finding.epistemic_status.is_not(None))
             .group_by(run.backend, run.model, Finding.epistemic_status))
    if not user.is_admin:
        query = query.where(Audit.user_id == user.id)
    rows: dict[tuple, dict] = {}
    for backend, model, status, count in session.execute(query).all():
        entry = rows.setdefault((backend, model), {
            "backend": backend, "model": model, "tested": 0, "refuted": 0,
            "by_status": {}})
        entry["tested"] += count
        entry["by_status"][status] = count
        if status == falsify.REFUTED:
            entry["refuted"] += count
    out = sorted(rows.values(), key=lambda e: -e["tested"])
    for entry in out:
        entry["rate"] = round(entry["refuted"] / entry["tested"], 3)
    return out


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str, verified_only: bool = False,
              user: User = Depends(require_user),
              session: Session = Depends(db_session)):
    """One audit and its findings.

    verified_only=true lists only the findings anchored to code in the audited
    repository, leaving out the ones the engine could not evidence.
    """
    audit = session.get(Audit, audit_id)
    # Someone else's audit reads as absent rather than forbidden, so the
    # response does not confirm that the id exists.
    if audit is None or not (user.is_admin or audit.user_id == user.id):
        raise HTTPException(status_code=404, detail="audit not found")
    return audit_to_dict(audit, include_findings=True,
                         verified_only=verified_only)


@app.get("/api/audits/{audit_id}/coverage")
def get_coverage(audit_id: str, user: User = Depends(require_user),
                 session: Session = Depends(db_session)):
    """Every file of the audited checkout: audited, in part, or not and why."""
    audit = session.get(Audit, audit_id)
    if audit is None or not (user.is_admin or audit.user_id == user.id):
        raise HTTPException(status_code=404, detail="audit not found")
    return {"summary": audit.coverage_summary,
            "files": [coverage_to_dict(row) for row in audit.coverage]}


def owned_project(session: Session, user: User, project_id: int) -> Project:
    project = session.get(Project, project_id)
    if project is None or not (user.is_admin or project.user_id == user.id):
        raise HTTPException(status_code=404, detail="project not found")
    return project


class JewelIn(BaseModel):
    kind: str
    target: str


@app.get("/api/projects/{project_id}/crown-jewels")
def list_crown_jewels(project_id: int, user: User = Depends(require_user),
                      session: Session = Depends(db_session)):
    project = owned_project(session, user, project_id)
    return [jewel_to_dict(j) for j in project.crown_jewels if j.declared_by != DISMISSED]


@app.post("/api/projects/{project_id}/crown-jewels", status_code=201)
def add_crown_jewel(project_id: int, jewel: JewelIn, user: User = Depends(require_user),
                    session: Session = Depends(db_session)):
    """What the owner says an attacker would be after. It counts from the next audit."""
    project = owned_project(session, user, project_id)
    target = jewel.target.strip()
    if jewel.kind not in JEWEL_KINDS:
        raise HTTPException(status_code=422, detail=f"kind must be one of {', '.join(JEWEL_KINDS)}")
    if not target or len(target) > 512:
        raise HTTPException(status_code=422, detail="describe the target in 1-512 characters")
    for j in list(project.crown_jewels):
        if j.kind == jewel.kind and j.declared_by in ("suggested", DISMISSED):
            project.crown_jewels.remove(j)      # the owner's word replaces the guess
    row = CrownJewel(kind=jewel.kind, target=target, declared_by="user")
    project.crown_jewels.append(row)
    session.commit()
    return jewel_to_dict(row)


@app.delete("/api/projects/{project_id}/crown-jewels/{jewel_id}", status_code=204)
def delete_crown_jewel(project_id: int, jewel_id: int, user: User = Depends(require_user),
                       session: Session = Depends(db_session)):
    """Remove a jewel. A suggested one is remembered as turned down, so the
    next audit does not suggest it again."""
    project = owned_project(session, user, project_id)
    jewel = next((j for j in project.crown_jewels if j.id == jewel_id), None)
    if jewel is None or jewel.declared_by == DISMISSED:
        raise HTTPException(status_code=404, detail="crown jewel not found")
    if jewel.declared_by == "suggested":
        jewel.declared_by = DISMISSED
    else:
        project.crown_jewels.remove(jewel)
    session.commit()
    return Response(status_code=204)


@app.get("/api/projects/{project_id}/immune-rules.yaml")
def export_immune_rules(project_id: int, user: User = Depends(require_user),
                        session: Session = Depends(db_session)):
    """The project's validated rules, as a Semgrep config to run anywhere."""
    project = session.get(Project, project_id)
    if project is None or not (user.is_admin or project.user_id == user.id):
        raise HTTPException(status_code=404, detail="project not found")
    rules = [r.validation["rule"] for r in project.immune_rules
             if r.validated and r.approved and (r.validation or {}).get("rule")]
    return Response(content=immune.to_yaml(rules), media_type="application/x-yaml",
                    headers={"Content-Disposition":
                             f'attachment; filename="secaudit-immune-{project_id}.yaml"'})


def _owned_rule(session: Session, user: User, project_id: int, rule_id: int) -> ImmuneRule:
    project = owned_project(session, user, project_id)
    rule = session.get(ImmuneRule, rule_id)
    if rule is None or rule.project_id != project.id:
        raise HTTPException(status_code=404, detail="rule not found")
    return rule


@app.post("/api/projects/{project_id}/immune-rules/{rule_id}/approval")
def approve_immune_rule(project_id: int, rule_id: int, user: User = Depends(require_user),
                        session: Session = Depends(db_session)):
    """A person accepts a learnt rule: from the next audit it looks for regressions.

    Only a rule that passed its test (caught the code before the fix and not
    after) can be approved; a proposal that failed stays a proposal.
    """
    rule = _owned_rule(session, user, project_id, rule_id)
    if not rule.validated:
        raise HTTPException(status_code=409,
                            detail="only a rule that passed its test can be approved")
    rule.approved = True
    rule.approved_by = user.login[:64]
    rule.approved_at = datetime.now(timezone.utc)
    session.commit()
    return immune_rule_to_dict(rule)


@app.delete("/api/projects/{project_id}/immune-rules/{rule_id}/approval")
def revoke_immune_rule(project_id: int, rule_id: int, user: User = Depends(require_user),
                       session: Session = Depends(db_session)):
    rule = _owned_rule(session, user, project_id, rule_id)
    rule.approved = False
    rule.approved_by = None
    rule.approved_at = None
    session.commit()
    return immune_rule_to_dict(rule)


# ---------------------------------------------------------------------------
# Reading an audit: trust, evidence chains, exports, changes, replay
# ---------------------------------------------------------------------------

ENGINE_VERSIONS = {
    "secaudit": TOOL_VERSION,
    "trust": trust.TRUST_VERSION,
    "evidence_chain": evidence_chain.CHAIN_VERSION,
    "secrets": secrets_scan.SCANNER_VERSION,
    "dependencies": deps.DEPS_VERSION,
    "mcp_audit": mcp_audit.MCP_AUDIT_VERSION,
    "owasp_mcp": mcp_audit.OWASP_MCP_VERSION,
    "surface": surface.SURFACE_VERSION,
    "drift": drift.DRIFT_VERSION,
    "reports": reports.REPORT_VERSION,
    "taint": taint.TAINT_VERSION,
    "doc_claims": doc_claims.CLAIMS_VERSION,
    "deadcode": deadcode.DEADCODE_VERSION,
    "twin": twin.TWIN_VERSION,
}


def owned_audit(session: Session, user: User, audit_id: str) -> Audit:
    audit = session.get(Audit, audit_id)
    if audit is None or not (user.is_admin or audit.user_id == user.id):
        raise HTTPException(status_code=404, detail="audit not found")
    return audit


def _trust_of(audit: Audit) -> dict:
    d = audit_to_dict(audit, include_findings=True)
    return trust.compute(d, [coverage_to_dict(r) for r in audit.coverage])


def _download(content: str, media_type: str, name: str) -> Response:
    return Response(content=content, media_type=media_type,
                    headers={"Content-Disposition": f'attachment; filename="{name}"',
                             "X-Content-Type-Options": "nosniff"})


@app.get("/api/audits/{audit_id}/trust")
def get_trust(audit_id: str, user: User = Depends(require_user),
              session: Session = Depends(db_session)):
    """Audit Confidence: coverage, evidence and adversarial resistance, apart."""
    return _trust_of(owned_audit(session, user, audit_id))


@app.get("/api/audits/{audit_id}/findings/{finding_id}/evidence-chain")
def get_evidence_chain(audit_id: str, finding_id: int, user: User = Depends(require_user),
                       session: Session = Depends(db_session)):
    audit = owned_audit(session, user, audit_id)
    row = next((f for f in audit.findings if f.id == finding_id), None)
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    d = audit_to_dict(audit)
    return evidence_chain.build(finding_to_dict(row), d, language=audit.language or "en")


@app.get("/api/audits/{audit_id}/findings/{finding_id}/blue-team")
def get_blue_team(audit_id: str, finding_id: int, user: User = Depends(require_user),
                  session: Session = Depends(db_session)):
    """Detection proposals for a finding: logs, a detection idea, a Sigma
    skeleton. Always marked NOT VALIDATED."""
    audit = owned_audit(session, user, audit_id)
    row = next((f for f in audit.findings if f.id == finding_id), None)
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    return reports.blue_team(finding_to_dict(row), audit.language or "en") or {}


@app.get("/api/audits/{audit_id}/report.sarif")
def report_sarif(audit_id: str, user: User = Depends(require_user),
                 session: Session = Depends(db_session)):
    audit = owned_audit(session, user, audit_id)
    body = reports.to_sarif(audit_to_dict(audit, include_findings=True), TOOL_VERSION)
    return _download(json.dumps(body, indent=2, ensure_ascii=False),
                     "application/sarif+json", f"secaudit-{audit.id}.sarif")


@app.get("/api/audits/{audit_id}/report.json")
def report_json(audit_id: str, user: User = Depends(require_user),
                session: Session = Depends(db_session)):
    audit = owned_audit(session, user, audit_id)
    body = reports.to_json_report(audit_to_dict(audit, include_findings=True),
                                  _trust_of(audit), TOOL_VERSION)
    return _download(json.dumps(body, indent=2, ensure_ascii=False, default=str),
                     "application/json", f"secaudit-{audit.id}.json")


@app.get("/api/audits/{audit_id}/report.html")
def report_html(audit_id: str, user: User = Depends(require_user),
                session: Session = Depends(db_session)):
    """The printable report. It quotes the audited repository, so it runs no
    script at all: the CSP allows its own inline style and nothing else."""
    audit = owned_audit(session, user, audit_id)
    body = reports.to_html(audit_to_dict(audit, include_findings=True),
                           _trust_of(audit), TOOL_VERSION)
    return Response(content=body, media_type="text/html; charset=utf-8", headers={
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                   "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"})


@app.get("/api/audits/{audit_id}/report.pdf")
def report_pdf(audit_id: str, user: User = Depends(require_user),
               session: Session = Depends(db_session)):
    """The report as a PDF: text only, nothing in it able to run."""
    audit = owned_audit(session, user, audit_id)
    body = pdf.to_pdf(audit_to_dict(audit, include_findings=True), _trust_of(audit),
                      TOOL_VERSION)
    return Response(content=body, media_type="application/pdf", headers={
        "Content-Disposition": f'attachment; filename="secaudit-{audit.id}.pdf"',
        "X-Content-Type-Options": "nosniff"})


@app.get("/api/audits/{audit_id}/components")
def list_components(audit_id: str, user: User = Depends(require_user),
                    session: Session = Depends(db_session)):
    audit = owned_audit(session, user, audit_id)
    return [component_to_dict(c) for c in audit.components]


@app.get("/api/audits/{audit_id}/sbom.cdx.json")
def sbom(audit_id: str, user: User = Depends(require_user),
         session: Session = Depends(db_session)):
    """The dependency inventory as a CycloneDX 1.5 SBOM."""
    audit = owned_audit(session, user, audit_id)
    comps = [component_to_dict(c) for c in audit.components]
    body = deps.to_cyclonedx(comps, audit.repo_url, audit.commit_sha, TOOL_VERSION)
    return _download(json.dumps(body, indent=2), "application/vnd.cyclonedx+json",
                     f"secaudit-{audit.id}.cdx.json")


@app.get("/api/audits/{audit_id}/diff")
def audit_diff(audit_id: str, user: User = Depends(require_user),
               session: Session = Depends(db_session)):
    """New, fixed, persisting and reintroduced findings since the previous
    audit of the project, with the files and controls that changed."""
    audit = owned_audit(session, user, audit_id)
    previous, diff = finding_changes(session, audit)
    run = next((m for m in reversed(audit.module_runs) if m.module == "drift"), None)

    def brief(f):
        return {k: f.get(k) for k in ("id", "title", "severity", "category", "file",
                                      "line", "fingerprint", "assessment")}
    return {"previous_audit": previous.id if previous else None,
            "previous_commit": previous.commit_sha if previous else None,
            "base_ref": audit.base_ref, "pr_number": audit.pr_number,
            "replay_of": audit.replay_of,
            "commit": audit.commit_sha,
            **{k: [brief(f) for f in v] for k, v in diff.items()},
            "changes": run.detail if run else None}


@app.get("/api/audits/{audit_id}/replay.json")
def replay(audit_id: str, user: User = Depends(require_user),
           session: Session = Depends(db_session)):
    """SecAudit Replay: what this audit ran on, with which versions and settings."""
    audit = owned_audit(session, user, audit_id)
    d = audit_to_dict(audit, include_findings=True)
    config = backend_config(settings_store.config_overrides(session, audit.user_id))
    safe = {k: v for k, v in config.items()
            if k in ("backend", "model", "context_chars", "max_output_tokens", "max_chunks",
                     "max_refutations", "canaries", "max_rules")}
    safe.update({"history_depth": immune_history_depth(),
                 "osv_check": deps.osv_enabled(),
                 "published_check": parallax.published_check_enabled(),
                 "github_token": bool(leverage.github_token()),
                 "note": "the configuration in force now; the model actually used is "
                         "under 'model'"})
    body = reports.replay_manifest(d, safe, ENGINE_VERSIONS, d.get("immune_rules") or [],
                                   TOOL_VERSION)
    return _download(json.dumps(body, indent=2, default=str), "application/json",
                     f"secaudit-{audit.id}-replay.json")


class WhatIfRequest(BaseModel):
    finding_id: int
    patch: str


@app.post("/api/audits/{audit_id}/what-if")
def what_if(audit_id: str, req: WhatIfRequest, background_tasks: BackgroundTasks,
            response: Response, user: User = Depends(require_user),
            session: Session = Depends(db_session)):
    """Try a fix for a finding on a temporary copy of the audited commit (C29).

    The original repository is never touched and the repository's code is
    never run: the copy is measured with the server's own checks (web/whatif).
    """
    audit = owned_audit(session, user, audit_id)
    row = next((f for f in audit.findings if f.id == req.finding_id), None)
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    if not audit.commit_sha:
        raise HTTPException(status_code=409, detail="the audit has no commit to patch")
    try:
        whatif.check_patch(req.patch)
    except whatif.WhatIfError as e:
        raise HTTPException(status_code=400, detail=str(e))
    rules = [r.validation for r in (audit.project.immune_rules if audit.project else [])
             if r.validated and r.approved and (r.validation or {}).get("rule")]
    args = (audit.repo_url, audit.commit_sha, finding_to_dict(row), req.patch,
            audit.language or "en", rules, int(immune_history_depth()))
    if sandbox.enabled():
        # Running tests takes minutes: answered at once, finished in the background.
        record = WhatIf(audit_id=audit.id, finding_id=row.id, user_id=user.id,
                        patch=req.patch, status="running", result=None)
        session.add(record)
        session.commit()
        background_tasks.add_task(finish_what_if, record.id, args)
        response.status_code = 202
        return what_if_to_dict(record)
    try:
        result = whatif.run(*args)
        status = "ok"
    except (whatif.WhatIfError, scanproc.ScanError) as e:
        result, status = {"error": sanitize_error(str(e))[:500]}, "error"
    record = WhatIf(audit_id=audit.id, finding_id=row.id, user_id=user.id,
                    patch=req.patch, status=status, result=result)
    session.add(record)
    session.commit()
    return what_if_to_dict(record)


_SANDBOX_LOCK = threading.Semaphore(1)      # one container run at a time


def finish_what_if(record_id: int, args: tuple) -> None:
    with _SANDBOX_LOCK:
        try:
            result, status = whatif.run(*args, run_tests=True), "ok"
        except (whatif.WhatIfError, scanproc.ScanError) as e:
            result, status = {"error": sanitize_error(str(e))[:500]}, "error"
        except Exception as e:      # never leave it "running"
            log.exception("what if %s failed", record_id)
            result, status = {"error": sanitize_error(f"internal error: {e}")[:500]}, "error"
    session = get_session()
    try:
        record = session.get(WhatIf, record_id)
        if record is not None:
            record.status, record.result = status, result
            session.commit()
    finally:
        session.close()


@app.get("/api/audits/{audit_id}/what-if")
def list_what_ifs(audit_id: str, user: User = Depends(require_user),
                  session: Session = Depends(db_session)):
    audit = owned_audit(session, user, audit_id)
    return [what_if_to_dict(w) for w in session.scalars(
        select(WhatIf).where(WhatIf.audit_id == audit.id).order_by(WhatIf.id.desc()))]


@app.get("/api/audits/{audit_id}/twin")
def digital_twin(audit_id: str, user: User = Depends(require_user),
                 session: Session = Depends(db_session)):
    """Security Digital Twin: areas, entries, assets, services, dependencies,
    findings and attack paths of the audited commit, with what is unknown."""
    audit = owned_audit(session, user, audit_id)
    d = audit_to_dict(audit, include_findings=True)
    d["components"] = [component_to_dict(c) for c in audit.components]
    return twin.build(d, [coverage_to_dict(r) for r in audit.coverage])


class TwinSimulation(BaseModel):
    fix_findings: list[int] = []
    confirm_findings: list[int] = []
    remove_capabilities: list[int] = []
    remove_divergences: list[int] = []


def attack_inputs(session: Session, audit: Audit) -> dict:
    """What the attack graph was built from, as stored: the same inputs
    record_attacker passed to attacker.analyze, read back without writing."""
    lev_run = session.scalar(select(ModuleRun).where(
        ModuleRun.audit_id == audit.id, ModuleRun.module == "leverage")
        .order_by(ModuleRun.id.desc()).limit(1))
    jewels = [j for j in (audit.project.crown_jewels if audit.project else [])
              if j.declared_by != DISMISSED] or [CrownJewel(kind="secrets", target="secrets")]
    return {
        "findings": [finding_to_dict(f) for f in audit.findings],
        "divergences": [{"id": v.id, "kind": v.kind, "file": v.file, "detail": v.detail}
                        for v in session.scalars(select(ViewDivergence)
                                                 .where(ViewDivergence.audit_id == audit.id))],
        "leverage": [{"id": r.id, "file": r.file, "leverage": r.leverage_score,
                      "oversight": r.oversight_score, "reasons": r.reasons or []}
                     for r in session.scalars(select(FileLeverage)
                                              .where(FileLeverage.audit_id == audit.id))],
        "agent": {"capabilities": [{"id": c.id, "capability": c.capability,
                                    "source_file": c.source_file}
                                   for c in session.scalars(select(AgentCapability).where(
                                       AgentCapability.audit_id == audit.id))],
                  "combinations": ((lev_run.detail or {}).get("combinations") or [])
                  if lev_run else []},
        "jewels": [{"id": j.id, "kind": j.kind} for j in jewels],
    }


@app.post("/api/audits/{audit_id}/twin/simulate")
def simulate_twin(audit_id: str, req: TwinSimulation, user: User = Depends(require_user),
                  session: Session = Depends(db_session)):
    """Change the twin and see which attack paths close, harden or open.

    Fixing a finding removes its steps; confirming one makes its steps solid.
    Recomputed on the stored graph: nothing runs, nothing is written."""
    audit = owned_audit(session, user, audit_id)
    if audit.status != "done":
        raise HTTPException(409, "the audit has not finished")
    inputs = attack_inputs(session, audit)
    known = {
        "fix_findings": {f["id"] for f in inputs["findings"]},
        "confirm_findings": {f["id"] for f in inputs["findings"]},
        "remove_capabilities": {c["id"] for c in inputs["agent"]["capabilities"]},
        "remove_divergences": {d["id"] for d in inputs["divergences"]},
    }
    changes = req.model_dump()
    for key, ids in changes.items():
        if len(ids) > 500:
            raise HTTPException(400, f"{key}: too many ids")
        unknown = set(ids) - known[key]
        if unknown:
            raise HTTPException(400, f"{key}: not in this audit: {sorted(unknown)[:10]}")
    if not any(changes.values()):
        raise HTTPException(400, "nothing to change")
    return twin.simulate(inputs, **changes)


@app.post("/api/audits/{audit_id}/replay", status_code=202)
def replay_audit(audit_id: str, background_tasks: BackgroundTasks,
                 user: User = Depends(require_user), session: Session = Depends(db_session)):
    """SecAudit Replay, executed: the same commit audited again.

    Same repository, same exact commit, same language, with the engine and
    settings in force now. A model does not answer twice the same, so the
    result is compared with the original (GET .../reproducibility) rather
    than expected to match.
    """
    original = owned_audit(session, user, audit_id)
    if not original.commit_sha:
        raise HTTPException(status_code=409, detail="the audit has no commit to replay")
    try:
        check_repo_owner(original.repo_url)
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    audit = queue_audit(session, background_tasks, original.repo_url, "replay",
                        branch=original.branch, user_id=user.id,
                        language=original.language or "en",
                        pinned_commit=original.commit_sha, replay_of=original.id)
    return audit_to_dict(audit)


@app.get("/api/audits/{audit_id}/reproducibility")
def reproducibility(audit_id: str, user: User = Depends(require_user),
                    session: Session = Depends(db_session)):
    """A replay against the audit it repeats: what both found, and what only one did."""
    audit = owned_audit(session, user, audit_id)
    if not audit.replay_of:
        raise HTTPException(status_code=404, detail="this audit is not a replay")
    original = session.get(Audit, audit.replay_of)
    if original is None:
        raise HTTPException(status_code=404, detail="the original audit is gone")

    def by_fp(a):
        return {f.fingerprint: finding_to_dict(f) for f in a.findings if f.fingerprint}

    def brief(f):
        return {k: f.get(k) for k in ("id", "title", "severity", "file", "line",
                                      "source", "assessment")}

    def modules(a):
        return {m.module: {"backend": m.backend, "model": m.model, "status": m.status}
                for m in a.module_runs}

    old, new = by_fp(original), by_fp(audit)
    both = sorted(set(old) & set(new))
    changed = [{"fingerprint": fp, "before": old[fp]["assessment"],
                "after": new[fp]["assessment"], "title": new[fp]["title"]}
               for fp in both if old[fp]["assessment"] != new[fp]["assessment"]]
    rule_old = {fp for fp, f in old.items() if f.get("source") == "rule"}
    rule_new = {fp for fp, f in new.items() if f.get("source") == "rule"}
    union = set(old) | set(new)
    return {
        "original": original.id, "replay": audit.id, "commit": audit.commit_sha,
        "same_commit": original.commit_sha == audit.commit_sha,
        "in_both": len(both), "only_original": [brief(old[fp]) for fp in sorted(set(old) - set(new))],
        "only_replay": [brief(new[fp]) for fp in sorted(set(new) - set(old))],
        "assessment_changed": changed,
        "agreement": round(len(both) / len(union), 3) if union else None,
        # Deterministic rules on the same commit should agree exactly.
        "rules_agree": rule_old == rule_new,
        "modules": {"original": modules(original), "replay": modules(audit)},
        "note": ("The model's findings vary between runs; rule findings on the same "
                 "commit should not. Disagreement on a rule finding means the engine "
                 "or its settings changed."),
    }


@app.get("/api/projects/{project_id}/history")
def project_history(project_id: int, user: User = Depends(require_user),
                    session: Session = Depends(db_session)):
    """SecAudit DNA: per audit, what was new, fixed and recurrent."""
    project = owned_project(session, user, project_id)
    audits = list(session.scalars(select(Audit).where(
        Audit.project_id == project.id, Audit.status == "done")
        .order_by(Audit.created_at)))
    out, previous, fixed_ever = [], [], set()
    for a in audits:
        current = [finding_to_dict(f) for f in a.findings]
        diff = drift.finding_diff(previous, current, fixed_ever)
        fixed_ever |= {f["fingerprint"] for f in diff["fixed"]}
        out.append({"audit_id": a.id, "commit_sha": a.commit_sha,
                    "created_at": a.created_at.isoformat() if a.created_at else None,
                    "total": len(current),
                    **{k: len(v) for k, v in diff.items()}})
        previous = current
    recurring: dict[str, int] = {}
    for a in audits:
        for f in a.findings:
            recurring[f.fingerprint] = recurring.get(f.fingerprint, 0) + 1
    return {"project_id": project.id, "repo_url": project.repo_url, "audits": out,
            "recurrent_fingerprints": sum(1 for n in recurring.values() if n > 1)}


_TAXONOMY_CHECK: dict = {}
TAXONOMY_TTL = 24 * 3600


@app.get("/api/mcp/catalog")
def mcp_catalog(language: str = "en", user: User = Depends(require_user)):
    """The MCP rules per OWASP MCP category: what, how, limits."""
    return {"taxonomy": {"name": mcp_audit.OWASP_MCP_VERSION, "url": mcp_audit.OWASP_MCP_URL,
                         "checked": mcp_audit.OWASP_MCP_CHECKED,
                         "last_check": _TAXONOMY_CHECK.get("result")},
            "categories": mcp_audit.catalog(language)}


@app.post("/api/mcp/taxonomy-check")
def mcp_taxonomy_check(user: User = Depends(require_user)):
    """Compare the pinned OWASP MCP names with the official page, now.

    Fetches only the public OWASP page; nothing about any audit leaves. The
    answer is kept for a day so the page is not asked on every click.
    """
    cached = _TAXONOMY_CHECK.get("result")
    if cached and time.monotonic() - _TAXONOMY_CHECK.get("at", 0) < TAXONOMY_TTL \
            and cached.get("checked"):
        return cached
    result = mcp_audit.check_taxonomy()
    _TAXONOMY_CHECK.update(result=result, at=time.monotonic())
    return result


@app.delete("/api/audits/{audit_id}", status_code=204)
def delete_audit(audit_id: str, user: User = Depends(require_user),
                 session: Session = Depends(db_session)):
    audit = session.get(Audit, audit_id)
    # Same 404-for-someone-else's rule as reading one.
    if audit is None or not (user.is_admin or audit.user_id == user.id):
        raise HTTPException(status_code=404, detail="audit not found")
    session.delete(audit)          # findings go with it, via cascade
    session.commit()
    return Response(status_code=204)


def settings_response(session: Session, user_id: int | None) -> dict:
    stored = settings_store.to_dict(settings_store.load(session, user_id))
    stored["backend_status"] = backend_status(
        backend_config(settings_store.config_overrides(session, user_id)),
        settings_store.credentials(session, user_id))
    return stored


@app.get("/api/settings")
def get_settings(user: User = Depends(require_user),
                 session: Session = Depends(db_session)):
    return settings_response(session, user.id)


@app.put("/api/settings")
def put_settings(req: SettingsRequest, user: User = Depends(require_user),
                 session: Session = Depends(db_session)):
    backend = req.backend
    # A key alone is enough: its prefix says which backend it belongs to.
    if not backend and req.api_key:
        backend = settings_store.detect_backend(req.api_key)
        if backend is None:
            raise HTTPException(
                status_code=400,
                detail="cannot tell which backend this key belongs to; "
                       "choose one explicitly",
            )
    if backend and backend not in BACKENDS:
        raise HTTPException(status_code=400,
                            detail=f"unknown backend '{backend}'. "
                                   f"Valid: {', '.join(BACKENDS)}")
    try:
        settings_store.save(session, user.id, backend=backend, model=req.model,
                            ollama_url=req.ollama_url, api_key=req.api_key,
                            clear_api_key=req.clear_api_key)
    except InvalidOllamaURL as e:
        # The server is the one that would fetch this address, so a rejected
        # one is the caller's mistake, not a failure of the instance.
        raise HTTPException(status_code=400, detail=str(e))
    except SecretsUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))
    return settings_response(session, user.id)



# ---------------------------------------------------------------------------
# Runners: audits executed on the owner's own machine
# ---------------------------------------------------------------------------

class RunnerResult(BaseModel):
    audit_id: str
    commit_sha: str | None = None
    findings: list[dict] | None = None
    coverage: list[dict] | None = None
    coverage_summary: dict | None = None
    # What each request carried, so the evidence can be checked against it.
    manifest: list[dict] | None = None
    usage: dict | None = None
    # The devil's advocate's request; its verdicts ride on the findings.
    refutation_usage: dict | None = None
    # How many planted decoys the auditor found, as the runner counted them.
    canary: dict | None = None
    # The rules it proposed for the fixes since the last audit; the server
    # works out the fixes itself and tests each rule before keeping it.
    immune: dict | None = None
    duration_ms: int | None = None
    error: str | None = None


UNCHECKABLE = ("degraded to unverified: the server could not check out the "
               "audited commit to check the evidence ({reason})")


def verify_runner_result(audit_id: str, result: dict) -> None:
    """Background task: check a runner's findings against our own checkout.

    The runner is someone's own machine, so what it sends is a claim, exactly
    like a model's. The server clones the commit the runner says it audited
    and runs the same evidence check it runs on its own audits. If that
    commit cannot be checked out, nothing it sent can count as verified.
    """
    session = get_session()
    try:
        audit = session.get(Audit, audit_id)
        if audit is None:
            return
        findings = [f for f in (result.get("findings") or []) if isinstance(f, dict)]
        with tempfile.TemporaryDirectory(prefix="secaudit-verify-") as tmp:
            dest = Path(tmp) / "repo"
            try:
                clone_at_commit(audit.repo_url, dest, audit.commit_sha or "")
            except CloneError as e:
                checkout = None
                for f in findings:
                    f["line"] = f["line_end"] = None
                    if str(f.get("verification_status")) == "verified":
                        f["verification_status"] = "unverified"
                        f["verification_note"] = UNCHECKABLE.format(reason=e)
            else:
                checkout = dest
                check_evidence(session, audit, dest, findings, result.get("manifest"))
            # What the runner says it spent: it is the one that talked to the model.
            record_llm_audit(session, audit, runnerqueue.RUNNER_BACKEND, None,
                             result.get("usage"), result.get("duration_ms"),
                             result.get("coverage_summary"))
            rules = run_rule_scanners(session, audit, checkout, findings)
            stored = store_result(session, audit, findings, result.get("coverage"),
                                  result.get("coverage_summary"), rules)
            record_falsifiability(session, audit, checkout, stored,
                                  runnerqueue.RUNNER_BACKEND, None,
                                  result.get("refutation_usage"))
            record_parallax(session, audit, checkout, result.get("coverage"),
                            result.get("coverage_summary"), result.get("canary"),
                            runnerqueue.RUNNER_BACKEND, None, canary_source="runner")
            record_immune(session, audit, checkout, stored, result.get("immune"),
                          runnerqueue.RUNNER_BACKEND, None)
            record_leverage(session, audit, checkout, stored)
            record_attacker(session, audit, checkout, stored)
            record_drift(session, audit, checkout)
        audit.runner_claimed_at = None
        session.commit()
        notify_pull_request(session, audit_id)
    except Exception as e:  # never leave an audit stuck in "running"
        session.rollback()
        audit = session.get(Audit, audit_id)
        if audit is not None:
            audit.status = "error"
            audit.error = sanitize_error(f"internal error checking the result: {e}")
            audit.runner_claimed_at = None
            session.commit()
    finally:
        session.close()


def runner_user(session: Session = Depends(db_session),
                authorization: str | None = Header(default=None)) -> User:
    user = runnerqueue.user_for_token(session, bearer_token(authorization))
    if user is None or not auth.is_invited(user.login):
        raise HTTPException(status_code=401, detail="invalid runner token")
    return user


@app.post("/api/runner/token")
def create_runner_token(user: User = Depends(require_user),
                        session: Session = Depends(db_session)):
    """Issue a runner token, shown once and never retrievable again."""
    return {"token": runnerqueue.issue_token(session, user)}


@app.delete("/api/runner/token", status_code=204)
def delete_runner_token(user: User = Depends(require_user),
                        session: Session = Depends(db_session)):
    runnerqueue.revoke_token(session, user)
    return Response(status_code=204)


@app.post("/api/runner/claim")
def runner_claim(response: Response, user: User = Depends(runner_user),
                 session: Session = Depends(db_session)):
    audit = runnerqueue.claim_next(session, user)
    if audit is None:
        response.status_code = 204
        return Response(status_code=204)
    job = runnerqueue.to_dict(audit)
    job["immune"] = immune_context(session, audit)
    return job


@app.post("/api/runner/result")
def runner_result(result: RunnerResult, background_tasks: BackgroundTasks,
                  user: User = Depends(runner_user),
                  session: Session = Depends(db_session)):
    audit = session.get(Audit, result.audit_id)
    if audit is None or not (user.is_admin or audit.user_id == user.id):
        raise HTTPException(status_code=404, detail="audit not found")
    if audit.runner_claimed_at is None:
        raise HTTPException(status_code=409, detail="audit was not claimed")

    if result.commit_sha:
        audit.commit_sha = result.commit_sha[:40]
    if result.error is not None:
        audit.status = "error"
        # Written on someone else's machine by their backend's SDK.
        audit.error = sanitize_error(result.error)
        audit.runner_claimed_at = None
    else:
        # Stays running until the evidence is checked; the fresh claim keeps
        # another runner from taking it in the meantime.
        audit.status = "running"
        audit.runner_claimed_at = datetime.now(timezone.utc)
        background_tasks.add_task(verify_runner_result, audit.id,
                                  result.model_dump())
    session.commit()
    return audit_to_dict(audit)


@app.get("/api/health")
def health(session: Session = Depends(db_session)):
    git_ok = shutil.which("git") is not None
    try:
        session.execute(text("SELECT 1"))
        db_ok = True
        audits_stored = session.scalar(select(func.count()).select_from(Audit))
    except Exception:
        db_ok = False
        audits_stored = None
    # Same config the audits will actually run with, so the header and the
    # settings panel can never disagree.
    try:
        instance_credentials = settings_store.credentials(session)
    except SecretsUnavailable:
        instance_credentials = {}
    backend = backend_status(backend_config(settings_store.config_overrides(session)),
                             instance_credentials)
    ok = git_ok and db_ok and backend["ready"]
    return {
        "status": "ok" if ok else "degraded",
        "git_available": git_ok,
        "database": db_ok,
        "backend": backend,
        "audits_stored": audits_stored,
    }


# Mounted last: a mount at "/" matches any path, so it must come after every
# API route or it would shadow them.
STATIC_DIR = Path(__file__).resolve().parent / "static"
# The slim image has no /etc/mime.types, which is where .woff2 is usually
# learnt; without this the fonts go out as application/octet-stream.
mimetypes.add_type("font/woff2", ".woff2")
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
