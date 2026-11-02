"""human approval of learnt rules, pinned and compared audits, What If runs

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-02

immune_rules.approved: a rule that passed its test against the history is
still a proposal until a person approves it (C26). Only approved rules look
for regressions. Rules from before this migration start unapproved: they
were accepted automatically, which is what this column exists to stop, so
each one waits for a person like any new one.

audits.base_ref: the commit or branch a differential audit compares with
(a pull request's base, or one chosen by hand), instead of the previous
audit. audits.pinned_commit: the exact commit to check out (a replay, or a
pull request's head). audits.replay_of: the audit a replay repeats.
audits.pr_number: the pull request a webhook audit was made for.

components.maintenance: last release and deprecation, from the package's
registry, only when SECAUDIT_ABANDONED_CHECK=1.

what_ifs: a fix tried on a temporary copy of the audited commit, and what
the server's own checks said about it (C29).
"""
import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("immune_rules") as batch:
        batch.add_column(sa.Column("approved", sa.Boolean(), nullable=False,
                                   server_default=sa.false()))
        batch.add_column(sa.Column("approved_by", sa.String(64), nullable=True))
        batch.add_column(sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
    with op.batch_alter_table("audits") as batch:
        batch.add_column(sa.Column("base_ref", sa.String(255), nullable=True))
        batch.add_column(sa.Column("pinned_commit", sa.String(40), nullable=True))
        batch.add_column(sa.Column("replay_of", sa.String(32), nullable=True))
        batch.add_column(sa.Column("pr_number", sa.Integer(), nullable=True))
    with op.batch_alter_table("components") as batch:
        batch.add_column(sa.Column("maintenance", sa.JSON(), nullable=True))
    op.create_table(
        "what_ifs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.Integer(),
                  sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("patch", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),     # ok | error
        sa.Column("result", sa.JSON(), nullable=True),
    )
    op.create_index("ix_what_ifs_audit_id", "what_ifs", ["audit_id"])


def downgrade() -> None:
    op.drop_index("ix_what_ifs_audit_id", table_name="what_ifs")
    op.drop_table("what_ifs")
    with op.batch_alter_table("components") as batch:
        batch.drop_column("maintenance")
    with op.batch_alter_table("audits") as batch:
        batch.drop_column("pr_number")
        batch.drop_column("replay_of")
        batch.drop_column("pinned_commit")
        batch.drop_column("base_ref")
    with op.batch_alter_table("immune_rules") as batch:
        batch.drop_column("approved_at")
        batch.drop_column("approved_by")
        batch.drop_column("approved")
