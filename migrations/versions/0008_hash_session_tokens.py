"""store session tokens hashed, as runner tokens already are

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-04

user_sessions.token held the cookie value verbatim, so anything that could read
the table — a backup, a replica, a SQL injection — held every live session.
Runner tokens were already kept as a SHA-256 hash; sessions now are too.

Existing rows are hashed in place rather than deleted, so the cookies already
in people's browsers keep working: the browser still presents the same token
and the lookup hashes it before matching. A SHA-256 hex digest is 64
characters, exactly what the column already allows.

"""
import hashlib

import sqlalchemy as sa
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

_sessions = sa.table(
    "user_sessions",
    sa.column("token", sa.String),
)


def upgrade() -> None:
    connection = op.get_bind()
    rows = connection.execute(sa.select(_sessions.c.token)).fetchall()
    for (token,) in rows:
        # A row already hashed would be a re-run; 64 hex characters is the
        # tell, and re-hashing one would silently log that person out.
        if token is None or (len(token) == 64 and _is_hex(token)):
            continue
        connection.execute(
            _sessions.update()
            .where(_sessions.c.token == token)
            .values(token=hashlib.sha256(token.encode()).hexdigest())
        )


def _is_hex(value: str) -> bool:
    try:
        int(value, 16)
        return True
    except ValueError:
        return False


def downgrade() -> None:
    # A hash cannot be turned back into the token it came from. Going back
    # means every session is unusable, so they are cleared and everyone signs
    # in again — which is the honest outcome, not a broken lookup.
    op.execute(sa.delete(_sessions))
