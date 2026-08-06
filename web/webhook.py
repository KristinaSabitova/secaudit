"""GitHub webhook: delivery authentication and push-event parsing."""

import hashlib
import hmac
import os

from .gitclone import validate_branch, validate_repo_url

SIGNATURE_HEADER = "X-Hub-Signature-256"
EVENT_HEADER = "X-GitHub-Event"

# GitHub reports a deleted branch with an all-zero "after" sha.
_NULL_SHA = "0" * 40
_BRANCH_PREFIX = "refs/heads/"


class WebhookError(Exception):
    """The delivery could not be authenticated."""


def webhook_secret() -> str | None:
    return os.environ.get("GITHUB_WEBHOOK_SECRET") or None


def sign(body: bytes, secret: str) -> str:
    """Return the X-Hub-Signature-256 value GitHub would send for body."""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(body: bytes, signature: str | None, secret: str) -> None:
    """Raise WebhookError unless signature authenticates body."""
    if not signature:
        raise WebhookError(f"missing {SIGNATURE_HEADER} header")
    if not hmac.compare_digest(sign(body, secret), signature):
        raise WebhookError("signature does not match")


def parse_push_event(payload: dict) -> dict | None:
    """Describe the audit a push event asks for, or None if there is nothing
    to audit (tag pushes, branch deletions).

    Raises ValueError if the payload names a repository we refuse to clone.
    """
    ref = payload.get("ref") or ""
    if not ref.startswith(_BRANCH_PREFIX) or payload.get("deleted"):
        return None
    branch = ref[len(_BRANCH_PREFIX):]
    sha = payload.get("after") or ""
    if not branch or sha == _NULL_SHA:
        return None

    repo = payload.get("repository") or {}
    return {
        "repo_url": validate_repo_url(repo.get("clone_url") or ""),
        "branch": validate_branch(branch),
        "sha": sha or None,
    }
