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
from .models import (LANGUAGES, Audit, Finding, Hypothesis, ModuleRun,
                     RefutationAttempt, User, audit_to_dict,
                     coverage_from_dict, coverage_to_dict, finding_from_dict,
                     project_for, summarize)
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
from analysis import evidence, falsify  # noqa: E402

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
    return runnerqueue.to_dict(audit)


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
