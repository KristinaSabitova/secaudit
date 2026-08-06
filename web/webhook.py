"""GitHub webhook: delivery authentication and push-event parsing."""

import hashlib
import hmac
import json
import os
from urllib.parse import parse_qs

from .gitclone import validate_branch, validate_repo_url

SIGNATURE_HEADER = "X-Hub-Signature-256"
EVENT_HEADER = "X-GitHub-Event"
FORM_CONTENT_TYPE = "application/x-www-form-urlencoded"

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


def decode_payload(body: bytes, content_type: str = "") -> dict:
    """Decode an authenticated delivery body into its event payload.

    A hook's "Content type" setting decides the encoding: GitHub's default,
    application/x-www-form-urlencoded, wraps the JSON in a "payload" field,
    while application/json sends it as the body. Raises ValueError on anything
    that does not decode to a JSON object.
    """
    if content_type.split(";", 1)[0].strip().lower() == FORM_CONTENT_TYPE:
        fields = parse_qs(body.decode("utf-8", "replace"))
        if not fields.get("payload"):
            raise ValueError(f"{FORM_CONTENT_TYPE} body has no 'payload' field")
        raw = fields["payload"][0]
    else:
        raw = body.decode("utf-8", "replace")

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        raise ValueError("body is not valid JSON")
    if not isinstance(payload, dict):
        raise ValueError("payload must be a JSON object")
    return payload


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
