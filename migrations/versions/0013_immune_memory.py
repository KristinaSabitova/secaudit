"""provenance, regressions and rules learnt from fixes (module 3)

Revision ID: 0013
Revises: 0012
Create Date: 2026-10-28

origin_commit is the commit that most probably introduced a finding, with
how sure that is; ai_declared is whether that commit declares AI
participation in its trailers — declared, never established. fix_commit is
set on a finding once a later audit shows it gone, and zombie_of on a later
finding that brings a fixed one back.

An immune rule is a Semgrep rule written from a fix. It is only kept as
validated when it matches the code before the fix and does not match the
code after it.

"""
import sqlalchemy as sa
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("origin_commit", sa.String(40), nullable=True))
        # high | medium | low
        batch.add_column(sa.Column("origin_confidence", sa.String(8), nullable=True))
        batch.add_column(sa.Column("ai_declared", sa.Boolean(), nullable=True))
        batch.add_column(sa.Column("fix_commit", sa.String(40), nullable=True))
        batch.add_column(sa.Column("zombie_of", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_findings_zombie_of", "findings",
                                 ["zombie_of"], ["id"], ondelete="SET NULL")
    op.create_table(
        "immune_rules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("project_id", sa.Integer(),
                  sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        # The fixed finding the rule was learnt from.
        sa.Column("finding_id", sa.Integer(),
                  sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("rule_yaml", sa.Text(), nullable=False),
        sa.Column("source_fix_commit", sa.String(40), nullable=False),
        sa.Column("vulnerable_commit", sa.String(40), nullable=False),
        sa.Column("validated", sa.Boolean(), nullable=False, server_default=sa.false()),
        # What the validation saw: matches before the fix, matches after it.
        sa.Column("validation", sa.JSON(), nullable=True),
        sa.Column("matches_history", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_immune_rules_project_id", "immune_rules", ["project_id"])


def downgrade() -> None:
    op.drop_index("ix_immune_rules_project_id", table_name="immune_rules")
    op.drop_table("immune_rules")
    with op.batch_alter_table("findings") as batch:
        batch.drop_constraint("fk_findings_zombie_of", type_="foreignkey")
        for column in ("zombie_of", "fix_commit", "ai_declared",
                       "origin_confidence", "origin_commit"):
            batch.drop_column(column)
