"""leverage against oversight per file, agent surface, crown jewels (module 4)

Revision ID: 0014
Revises: 0013
Create Date: 2026-10-28

file_leverage scores how much damage a malicious change to a file could do
against how much real human review that file gets. agent_capabilities is
what an AI agent opening the repository would inherit — permissions, MCP
servers, hooks, instructions — one row per capability and where it comes
from. Crown jewels are what an attacker would be after; the owner declares
them, or secaudit suggests them.

"""
import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "file_leverage",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("file", sa.String(512), nullable=False),
        sa.Column("leverage_score", sa.Float(), nullable=False),
        sa.Column("oversight_score", sa.Float(), nullable=False),
        sa.Column("reasons", sa.JSON(), nullable=True),
    )
    op.create_index("ix_file_leverage_audit_id", "file_leverage", ["audit_id"])
    op.create_table(
        "agent_capabilities",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_file", sa.String(512), nullable=False),
        # reads_files | network | executes | runs_on_start | mcp_server | instructions
        sa.Column("capability", sa.String(32), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False),
    )
    op.create_index("ix_agent_capabilities_audit_id", "agent_capabilities", ["audit_id"])
    op.create_table(
        "crown_jewels",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("project_id", sa.Integer(),
                  sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        # secrets | user_data | deployment | administration | other
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("declared_by", sa.String(16), nullable=False),  # user | suggested
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_crown_jewels_project_id", "crown_jewels", ["project_id"])


def downgrade() -> None:
    op.drop_index("ix_crown_jewels_project_id", table_name="crown_jewels")
    op.drop_table("crown_jewels")
    op.drop_index("ix_agent_capabilities_audit_id", table_name="agent_capabilities")
    op.drop_table("agent_capabilities")
    op.drop_index("ix_file_leverage_audit_id", table_name="file_leverage")
    op.drop_table("file_leverage")
