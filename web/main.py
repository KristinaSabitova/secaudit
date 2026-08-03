"""FastAPI app exposing the secaudit engine over HTTP."""

import shutil
import tempfile
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .engine import AuditError, backend_status, run_audit
from .gitclone import CloneError, clone_repo, validate_repo_url
from .store import AuditStore

app = FastAPI(title="secaudit web", version="0.1.0")
store = AuditStore()


class AuditRequest(BaseModel):
    repo_url: str


@app.post("/api/audits", status_code=201)
def create_audit(req: AuditRequest):
    try:
        url = validate_repo_url(req.repo_url)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    audit = store.create(repo_url=url)
    audit_id = audit["id"]
    with tempfile.TemporaryDirectory(prefix="secaudit-") as tmp:
        dest = Path(tmp) / "repo"
        try:
            commit_sha = clone_repo(url, dest)
            store.update(audit_id, status="running", commit_sha=commit_sha)
            findings = run_audit(dest)
        except (CloneError, AuditError) as e:
            store.update(audit_id, status="error", error=str(e))
            return store.get(audit_id)
        store.update(audit_id, status="done", findings=findings)
    return store.get(audit_id)


@app.get("/api/audits")
def list_audits():
    return store.list()


@app.get("/api/audits/{audit_id}")
def get_audit(audit_id: str):
    audit = store.get(audit_id)
    if audit is None:
        raise HTTPException(status_code=404, detail="audit not found")
    return audit


@app.get("/api/health")
def health():
    git_ok = shutil.which("git") is not None
    backend = backend_status()
    ok = git_ok and backend["ready"]
    return {
        "status": "ok" if ok else "degraded",
        "git_available": git_ok,
        "backend": backend,
        "audits_stored": store.count(),
    }
