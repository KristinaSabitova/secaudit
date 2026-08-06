"""FastAPI app exposing the secaudit engine over HTTP."""

import os
import shutil
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from . import settings as settings_store
from .db import get_session
from .engine import AuditError, backend_config, backend_status, run_audit
from .gitclone import CloneError, clone_repo, validate_repo_url
from .models import Audit, audit_to_dict, finding_from_dict, summarize
from .settings import SecretsUnavailable
from .webhook import (
    EVENT_HEADER,
    SIGNATURE_HEADER,
    WebhookError,
    decode_payload,
    parse_push_event,
    verify_signature,
    webhook_secret,
)

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


def restore_stored_credentials() -> None:
    """Publish the dashboard-configured credential into the environment."""
    session = get_session()
    try:
        settings_store.apply_to_environment(session)
    except SecretsUnavailable:
        pass  # /api/settings reports the same problem where a user can see it
    finally:
        session.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    fail_interrupted_audits()
    restore_stored_credentials()
    yield


app = FastAPI(title="secaudit web", version="0.2.0", lifespan=lifespan)


class AuditRequest(BaseModel):
    repo_url: str


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


def execute_audit(audit_id: str) -> None:
    """Background task: clone the repo, run the engine, persist the outcome."""
    session = get_session()
    try:
        audit = session.get(Audit, audit_id)
        if audit is None:
            return
        with tempfile.TemporaryDirectory(prefix="secaudit-") as tmp:
            dest = Path(tmp) / "repo"
            try:
                audit.commit_sha = clone_repo(audit.repo_url, dest,
                                              branch=audit.branch)
                audit.status = "running"
                session.commit()
                findings = run_audit(
                    dest, backend_config(settings_store.config_overrides(session)))
            except (CloneError, AuditError) as e:
                audit.status = "error"
                audit.error = str(e)
                session.commit()
                return
            except Exception as e:  # never leave an audit stuck in "running"
                audit.status = "error"
                audit.error = f"internal error: {e}"
                session.commit()
                return
        for f in findings:
            session.add(finding_from_dict(audit.id, f))
        audit.summary = summarize(findings)
        audit.status = "done"
        session.commit()
    finally:
        session.close()


def queue_audit(session: Session, background_tasks: BackgroundTasks, repo_url: str,
                trigger: str, branch: str | None = None,
                commit_sha: str | None = None) -> Audit:
    """Record a pending audit and hand it to a background worker.

    commit_sha is what the caller announced; the worker replaces it with the
    sha it actually checked out.
    """
    audit = Audit(repo_url=repo_url, branch=branch, trigger=trigger,
                  commit_sha=commit_sha)
    session.add(audit)
    session.commit()
    background_tasks.add_task(execute_audit, audit.id)
    return audit


@app.post("/api/audits", status_code=202)
def create_audit(req: AuditRequest, background_tasks: BackgroundTasks,
                 session: Session = Depends(db_session)):
    try:
        url = validate_repo_url(req.repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    audit = queue_audit(session, background_tasks, url, "manual")
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

    audit = queue_audit(session, background_tasks, push["repo_url"], "webhook",
                        branch=push["branch"], commit_sha=push["sha"])
    return audit_to_dict(audit)


@app.get("/api/audits")
def list_audits(session: Session = Depends(db_session)):
    audits = session.scalars(
        select(Audit).order_by(Audit.created_at.desc())
    ).all()
    return [audit_to_dict(a) for a in audits]


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str, session: Session = Depends(db_session)):
    audit = session.get(Audit, audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="audit not found")
    return audit_to_dict(audit, include_findings=True)


def settings_response(session: Session) -> dict:
    stored = settings_store.to_dict(settings_store.load(session))
    stored["backend_status"] = backend_status(
        backend_config(settings_store.config_overrides(session)))
    return stored


@app.get("/api/settings")
def get_settings(session: Session = Depends(db_session)):
    return settings_response(session)


@app.put("/api/settings")
def put_settings(req: SettingsRequest, session: Session = Depends(db_session)):
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
        settings_store.save(session, backend=backend, model=req.model,
                            ollama_url=req.ollama_url, api_key=req.api_key,
                            clear_api_key=req.clear_api_key)
        if req.clear_api_key:
            for env_name in settings_store.CREDENTIAL_ENV.values():
                os.environ.pop(env_name, None)
        settings_store.apply_to_environment(session)
    except SecretsUnavailable as e:
        raise HTTPException(status_code=503, detail=str(e))
    return settings_response(session)


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
    backend = backend_status(backend_config(settings_store.config_overrides(session)))
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
app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
