"""record whether a finding is backed by evidence from the audited code

Revision ID: 0006
Revises: 0005
Create Date: 2026-08-19

"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("code_snippet", sa.Text(), nullable=True))
    # Findings stored before this migration were never checked against the
    # code, so the honest value for them is the one they get by default.
    op.add_column(
        "findings",
        sa.Column("verification_status", sa.String(16), nullable=False,
                  server_default="unverified"),
    )
    op.add_column("findings",
                  sa.Column("verification_note", sa.String(255), nullable=True))
    op.create_index("ix_findings_verification_status", "findings",
                    ["verification_status"])


def downgrade() -> None:
    op.drop_index("ix_findings_verification_status", table_name="findings")
    op.drop_column("findings", "verification_note")
    op.drop_column("findings", "verification_status")
    op.drop_column("findings", "code_snippet")
