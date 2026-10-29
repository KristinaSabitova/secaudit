"""FastAPI app exposing the secaudit engine over HTTP."""

import logging
import mimetypes
import os
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
from .gitclone import CloneError, clone_at_commit, clone_repo, validate_repo_url
from .models import (LANGUAGES, Audit, CanaryRun, Finding, Hypothesis, ImmuneRule,
                     ModuleRun, RefutationAttempt, User, ViewDivergence, audit_to_dict,
                     coverage_from_dict, coverage_to_dict, finding_from_dict,
                     finding_to_dict, Project, project_for, summarize)
from .settings import InvalidOllamaURL, SecretsUnavailable
from .webhook import (
    EVENT_HEADER,
    SIGNATURE_HEADER,
    WebhookError,
    decode_payload,
    parse_push_event,
    verify_signature,
    webhook_secret,
)

# Importable once .engine has put the repository root on sys.path.
from analysis import evidence, falsify, immune, parallax  # noqa: E402

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


app = FastAPI(title="secaudit web", version="0.2.0", lifespan=lifespan)


class AuditRequest(BaseModel):
    repo_url: str
    # The findings are written in this language by the backend itself; there is
    # no translation pass afterwards.
    language: str = "en"


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
                 coverage_summary: dict | None) -> list[tuple[Finding, dict]]:
    """Persist a finished audit: its findings, its coverage, and done.

    Returns each stored finding with the dict it was made from, for the
    modules that work on findings once they have an id.
    """
    stored = []
    for f in findings:
        row = finding_from_dict(audit.id, f)
        session.add(row)
        stored.append((row, f))
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
        rules = list(session.scalars(select(ImmuneRule).where(
            ImmuneRule.project_id == audit.project_id,
            ImmuneRule.validated.is_(True)))) if audit.project_id is not None else []
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
                    if hit.zombie_of is None and origin is not None:
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
                    epistemic_status=falsify.EXISTS, zombie_of=origin.id)
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
                audit.commit_sha = clone_repo(audit.repo_url, dest,
                                              branch=audit.branch)
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
                stored = store_result(session, audit, findings, result.get("coverage"),
                                      result.get("coverage_summary"))
                record_falsifiability(session, audit, dest, stored,
                                      *backend_identity(config),
                                      result.get("refutation_usage"))
                record_parallax(session, audit, dest, result.get("coverage"),
                                result.get("coverage_summary"), result.get("canary"),
                                *backend_identity(config))
                record_immune(session, audit, dest, stored, result.get("immune"),
                              *backend_identity(config))
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
    finally:
        session.close()


def queue_audit(session: Session, background_tasks: BackgroundTasks, repo_url: str,
                trigger: str, branch: str | None = None,
                commit_sha: str | None = None, user_id: int | None = None,
                language: str = "en") -> Audit:
    """Record a pending audit and hand it to a background worker.

    commit_sha is what the caller announced; the worker replaces it with the
    sha it actually checked out.
    """
    audit = Audit(repo_url=repo_url, branch=branch, trigger=trigger,
                  commit_sha=commit_sha, user_id=user_id, language=language,
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
    language = (req.language or "en").lower()
    if language not in LANGUAGES:
        raise HTTPException(status_code=400,
                            detail=f"unsupported language '{req.language}'. "
                                   f"Valid: {', '.join(LANGUAGES)}")

    audit = queue_audit(session, background_tasks, url, "manual",
                        user_id=user.id, language=language)
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
    if event != "push":
        response.status_code = 200
        return {"status": "ignored", "reason": f"unsupported event '{event}'"}

    try:
        payload = decode_payload(body, request.headers.get("content-type", ""))
        push = parse_push_event(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    if push is None:
        response.status_code = 200
        return {"status": "ignored", "reason": "push does not update a branch"}

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


@app.get("/api/projects/{project_id}/immune-rules.yaml")
def export_immune_rules(project_id: int, user: User = Depends(require_user),
                        session: Session = Depends(db_session)):
    """The project's validated rules, as a Semgrep config to run anywhere."""
    project = session.get(Project, project_id)
    if project is None or not (user.is_admin or project.user_id == user.id):
        raise HTTPException(status_code=404, detail="project not found")
    rules = [r.validation["rule"] for r in project.immune_rules
             if r.validated and (r.validation or {}).get("rule")]
    return Response(content=immune.to_yaml(rules), media_type="application/x-yaml",
                    headers={"Content-Disposition":
                             f'attachment; filename="secaudit-immune-{project_id}.yaml"'})


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
            stored = store_result(session, audit, findings, result.get("coverage"),
                                  result.get("coverage_summary"))
            record_falsifiability(session, audit, checkout, stored,
                                  runnerqueue.RUNNER_BACKEND, None,
                                  result.get("refutation_usage"))
            record_parallax(session, audit, checkout, result.get("coverage"),
                            result.get("coverage_summary"), result.get("canary"),
                            runnerqueue.RUNNER_BACKEND, None, canary_source="runner")
            record_immune(session, audit, checkout, stored, result.get("immune"),
                          runnerqueue.RUNNER_BACKEND, None)
        audit.runner_claimed_at = None
        session.commit()
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
