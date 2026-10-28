"""the attacker's view: capabilities, the steps between them, paths (module 5)

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-28

Nodes are capabilities an attacker can hold (reads_secret, executes_code...).
An edge is a step from one to another and says what makes it possible: a
reachable or corroborated finding, a divergence, or a leverage route, at a
cost. A path is the cheapest sequence of edges from where an attacker
profile starts to a crown jewel.

findings.personas lists the attacker profiles that can trigger a finding,
and contextual_severity is the severity of the cheapest path it enables.

"""
import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("personas", sa.JSON(), nullable=True))
        batch.add_column(sa.Column("contextual_severity", sa.String(16), nullable=True))
    op.create_table(
        "attack_nodes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key", sa.String(64), nullable=False),
        sa.Column("label", sa.String(255), nullable=False),
        # The attacker profile that starts here, for a starting node.
        sa.Column("persona", sa.String(32), nullable=True),
        sa.Column("crown_jewel_id", sa.Integer(),
                  sa.ForeignKey("crown_jewels.id", ondelete="SET NULL"), nullable=True),
        sa.UniqueConstraint("audit_id", "key", name="uq_attack_nodes_audit_key"),
    )
    op.create_index("ix_attack_nodes_audit_id", "attack_nodes", ["audit_id"])
    op.create_table(
        "attack_edges",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_node_id", sa.Integer(),
                  sa.ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_node_id", sa.Integer(),
                  sa.ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False),
        # What makes the step possible: exactly one of these is set.
        sa.Column("finding_id", sa.Integer(),
                  sa.ForeignKey("findings.id", ondelete="CASCADE"), nullable=True),
        sa.Column("divergence_id", sa.Integer(),
                  sa.ForeignKey("view_divergences.id", ondelete="CASCADE"), nullable=True),
        sa.Column("leverage_id", sa.Integer(),
                  sa.ForeignKey("file_leverage.id", ondelete="CASCADE"), nullable=True),
        sa.Column("persona", sa.String(32), nullable=True),
        sa.Column("cost", sa.Float(), nullable=False),
        # steps, privileges needed, whether it leaves a trace
        sa.Column("cost_detail", sa.JSON(), nullable=True),
        # An inconclusive finding: drawn dashed, left out of the minimum cut.
        sa.Column("tentative", sa.Boolean(), nullable=False, server_default=sa.false()),
        # what the attacker would see, why it works (CWE, ATT&CK), what it
        # needs, what it gains
        sa.Column("explanation", sa.JSON(), nullable=True),
    )
    op.create_index("ix_attack_edges_audit_id", "attack_edges", ["audit_id"])
    op.create_table(
        "attack_paths",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("persona", sa.String(32), nullable=False),
        sa.Column("target_node_id", sa.Integer(),
                  sa.ForeignKey("attack_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("cost", sa.Float(), nullable=False),
        sa.Column("edges", sa.JSON(), nullable=False),     # attack_edges ids, in order
        sa.Column("severity", sa.String(16), nullable=False),
    )
    op.create_index("ix_attack_paths_audit_id", "attack_paths", ["audit_id"])


def downgrade() -> None:
    op.drop_index("ix_attack_paths_audit_id", table_name="attack_paths")
    op.drop_table("attack_paths")
    op.drop_index("ix_attack_edges_audit_id", table_name="attack_edges")
    op.drop_table("attack_edges")
    op.drop_index("ix_attack_nodes_audit_id", table_name="attack_nodes")
    op.drop_table("attack_nodes")
    with op.batch_alter_table("findings") as batch:
        batch.drop_column("contextual_severity")
        batch.drop_column("personas")
