"""add runner tokens and audit claims

Revision ID: 0005
Revises: 0004
Create Date: 2026-08-06

"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users",
                  sa.Column("runner_token_hash", sa.String(64), nullable=True))
    op.add_column("audits",
                  sa.Column("runner_claimed_at", sa.DateTime(timezone=True),
                            nullable=True))


def downgrade() -> None:
    op.drop_column("audits", "runner_claimed_at")
    op.drop_column("users", "runner_token_hash")
