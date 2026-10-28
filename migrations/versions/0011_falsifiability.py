"""findings as refutable hypotheses (module 2)

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-28

epistemic_status says how far a finding has been shown to hold: its code is
there (exists), something reaches it from an entry point (reachable), it
survived every attempt to refute it (corroborated), one of them refuted it
(refuted), or neither could be established (inconclusive).

Findings stored before this migration get NULL, not "exists": they were
marked verified on the model's word, before snippets were checked against the
file, so nothing has been shown about them.

A hypothesis belongs to one finding and is reached from it; the finding does
not point back, which would make the two tables reference each other.

"""
import sqlalchemy as sa
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("epistemic_status", sa.String(16), nullable=True))
        batch.create_index("ix_findings_epistemic_status", ["epistemic_status"])
    op.create_table(
        "hypotheses",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("finding_id", sa.Integer(),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"),
                  nullable=False, unique=True),
        sa.Column("source", sa.Text(), nullable=True),    # attacker-controlled input
        sa.Column("sink", sa.Text(), nullable=True),      # the dangerous use
        sa.Column("path", sa.JSON(), nullable=True),      # functions in between
        sa.Column("preconditions", sa.JSON(), nullable=True),
        # Whether source, sink and path were all given: without that the
        # finding cannot rise above "exists".
        sa.Column("complete", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "refutation_attempts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("hypothesis_id", sa.Integer(),
                  sa.ForeignKey("hypotheses.id", ondelete="CASCADE"), nullable=False),
        # callgraph | sanitizer | reachability | devil_advocate
        sa.Column("method", sa.String(32), nullable=False),
        # refuted | survived | inconclusive
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
    )
    op.create_index("ix_refutation_attempts_hypothesis_id", "refutation_attempts",
                    ["hypothesis_id"])


def downgrade() -> None:
    op.drop_index("ix_refutation_attempts_hypothesis_id",
                  table_name="refutation_attempts")
    op.drop_table("refutation_attempts")
    op.drop_table("hypotheses")
    with op.batch_alter_table("findings") as batch:
        batch.drop_index("ix_findings_epistemic_status")
        batch.drop_column("epistemic_status")
