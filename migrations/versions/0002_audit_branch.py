"""add audits.branch

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-06

"""
from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audits", sa.Column("branch", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("audits", "branch")
