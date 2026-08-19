"""record the language an audit's findings are written in

Revision ID: 0007
Revises: 0006
Create Date: 2026-08-19

"""
from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Everything audited so far was written in English, which is also what an
    # audit gets when the caller does not ask for a language.
    op.add_column(
        "audits",
        sa.Column("language", sa.String(8), nullable=False, server_default="en"),
    )


def downgrade() -> None:
    op.drop_column("audits", "language")
