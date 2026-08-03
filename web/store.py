"""In-memory audit store (replaced by PostgreSQL in a later phase)."""

import copy
import threading
import uuid
from datetime import datetime, timezone

SEVERITIES = ["critical", "high", "medium", "low", "info"]


def _summarize(findings: list[dict]) -> dict:
    summary = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev = f.get("severity")
        summary[sev if sev in summary else "info"] += 1
    return summary


class AuditStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._audits: dict[str, dict] = {}

    def create(self, repo_url: str, trigger: str = "manual") -> dict:
        audit = {
            "id": uuid.uuid4().hex[:12],
            "repo_url": repo_url,
            "commit_sha": None,
            "trigger": trigger,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "error": None,
            "summary": {s: 0 for s in SEVERITIES},
            "findings": [],
        }
        with self._lock:
            self._audits[audit["id"]] = audit
        return copy.deepcopy(audit)

    def update(self, audit_id: str, **fields) -> None:
        with self._lock:
            audit = self._audits[audit_id]
            audit.update(fields)
            if "findings" in fields:
                audit["summary"] = _summarize(fields["findings"])

    def get(self, audit_id: str) -> dict | None:
        with self._lock:
            audit = self._audits.get(audit_id)
            return copy.deepcopy(audit) if audit else None

    def list(self) -> list[dict]:
        """Newest first, without the findings payload."""
        with self._lock:
            audits = [
                {k: copy.deepcopy(v) for k, v in a.items() if k != "findings"}
                for a in self._audits.values()
            ]
        return sorted(audits, key=lambda a: a["created_at"], reverse=True)

    def count(self) -> int:
        with self._lock:
            return len(self._audits)

    def clear(self) -> None:
        with self._lock:
            self._audits.clear()
