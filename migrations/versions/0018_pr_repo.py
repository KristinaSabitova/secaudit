"""the repository a pull request belongs to

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-02

audits.pr_repo: owner/name of the repository whose pull request a webhook
audit was made for. The head may be a fork, which is what gets cloned
(repo_url); the report goes back to the base repository, this one.
"""
import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("audits") as batch:
        batch.add_column(sa.Column("pr_repo", sa.String(255), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("audits") as batch:
        batch.drop_column("pr_repo")
