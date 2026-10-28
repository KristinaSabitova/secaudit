"""divergences between views of a repository, and auditor integrity (module 1)

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-28

A divergence is a place where two views of the same file disagree: what a
person sees on GitHub against the bytes (hidden content), the bytes against
what would run (unexpected execution), the bytes against what the auditor was
sent (blind spot), git against the published package (release mismatch).

canary_runs records how many planted decoys the auditor found in an isolated
copy of the repository. The decoys themselves are never stored as findings.

"""
import sqlalchemy as sa
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "view_divergences",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("file", sa.String(512), nullable=False),
        # human | bytes | machine | llm | published
        sa.Column("view_a", sa.String(16), nullable=False),
        sa.Column("view_b", sa.String(16), nullable=False),
        # hidden_content | unexpected_execution | audit_blind_spot | release_mismatch
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        # Where in the file, and what differs: line ranges, code points.
        sa.Column("evidence", sa.JSON(), nullable=True),
    )
    op.create_index("ix_view_divergences_audit_id", "view_divergences", ["audit_id"])
    op.create_table(
        "canary_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("canaries_planted", sa.Integer(), nullable=False),
        sa.Column("canaries_found", sa.Integer(), nullable=False),
        sa.Column("integrity_score", sa.Float(), nullable=False),
        # Kind and file of each decoy, never its content.
        sa.Column("detail", sa.JSON(), nullable=True),
    )
    op.create_index("ix_canary_runs_audit_id", "canary_runs", ["audit_id"])


def downgrade() -> None:
    op.drop_index("ix_canary_runs_audit_id", table_name="canary_runs")
    op.drop_table("canary_runs")
    op.drop_index("ix_view_divergences_audit_id", table_name="view_divergences")
    op.drop_table("view_divergences")
