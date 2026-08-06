"""FastAPI app exposing the secaudit engine over HTTP."""

import shutil
import tempfile
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .db import get_session
from .engine import AuditError, backend_status, run_audit
from .gitclone import CloneError, clone_repo, validate_repo_url
from .models import Audit, audit_to_dict, finding_from_dict, summarize
from .webhook import (
    EVENT_HEADER,
    SIGNATURE_HEADER,
    WebhookError,
    decode_payload,
    parse_push_event,
    verify_signature,
    webhook_secret,
)

app = FastAPI(title="secaudit web", version="0.2.0")


class AuditRequest(BaseModel):
    repo_url: str


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
                findings = run_audit(dest)
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
    backend = backend_status()
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
