"""record what each audit covered, and where a finding's evidence ends

Revision ID: 0009
Revises: 0008
Create Date: 2026-10-28

An audit is now split into several requests ordered by risk, and every file of
the checkout is accounted for: audited, audited in part, or not and why. That
is the coverage table. findings.line used to be whatever line the model named;
it is now where the snippet was found in the file, and line_end is where it
stops. Rows stored before this migration keep the line the model gave them:
they were never checked, and their verification_status already says so.

"""
from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("line_end", sa.Integer(), nullable=True))
    # Counts for the audit as a whole, so a list of audits can show them
    # without reading every coverage row. NULL for audits from before.
    op.add_column("audits", sa.Column("coverage_summary", sa.JSON(), nullable=True))
    op.create_table(
        "coverage",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("file", sa.String(512), nullable=False),
        sa.Column("audited", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.String(255), nullable=False),
        sa.Column("risk_tier", sa.Integer(), nullable=False),
        # Padding signals: near-duplicate, oversized, unreferenced.
        sa.Column("signals", sa.JSON(), nullable=True),
    )
    op.create_index("ix_coverage_audit_id", "coverage", ["audit_id"])


def downgrade() -> None:
    op.drop_index("ix_coverage_audit_id", table_name="coverage")
    op.drop_table("coverage")
    op.drop_column("audits", "coverage_summary")
    op.drop_column("findings", "line_end")
