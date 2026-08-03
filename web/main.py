"""FastAPI app exposing the secaudit engine over HTTP."""

import shutil
import tempfile
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from .db import get_session
from .engine import AuditError, backend_status, run_audit
from .gitclone import CloneError, clone_repo, validate_repo_url
from .models import Audit, audit_to_dict, finding_from_dict, summarize

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
                audit.commit_sha = clone_repo(audit.repo_url, dest)
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


@app.post("/api/audits", status_code=202)
def create_audit(req: AuditRequest, background_tasks: BackgroundTasks,
                 session: Session = Depends(db_session)):
    try:
        url = validate_repo_url(req.repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    audit = Audit(repo_url=url, trigger="manual")
    session.add(audit)
    session.commit()
    background_tasks.add_task(execute_audit, audit.id)
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
