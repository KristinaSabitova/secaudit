"""deterministic rules beside the model, and the dependency inventory

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-02

findings.source says who produced a finding: the model (a claim, checked
afterwards), a deterministic rule run on the server's checkout (secrets,
dependencies, the MCP auditor), or an immune rule. NULL is the model, which
is what every finding before this migration came from. rule_id names the
rule, and detail carries what a rule states about its own finding: OWASP MCP
category, CWE, prerequisites, impact, confidence, its own assessment.

components is the inventory of dependencies an audit found, direct and
transitive, which the CycloneDX SBOM is built from.

"""
import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("findings") as batch:
        batch.add_column(sa.Column("source", sa.String(16), nullable=True))
        batch.add_column(sa.Column("rule_id", sa.String(64), nullable=True))
        batch.add_column(sa.Column("detail", sa.JSON(), nullable=True))
    op.create_table(
        "components",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ecosystem", sa.String(16), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        # Exact when a lockfile pins it; otherwise the range as declared.
        sa.Column("version", sa.String(128), nullable=True),
        sa.Column("direct", sa.Boolean(), nullable=False),
        sa.Column("scope", sa.String(16), nullable=True),     # runtime | dev | optional
        sa.Column("manifest", sa.String(512), nullable=False),
        sa.Column("purl", sa.String(512), nullable=True),
        # Advisory ids from OSV.dev, with their aliases; NULL when not asked.
        sa.Column("vulns", sa.JSON(), nullable=True),
    )
    op.create_index("ix_components_audit_id", "components", ["audit_id"])


def downgrade() -> None:
    op.drop_index("ix_components_audit_id", table_name="components")
    op.drop_table("components")
    with op.batch_alter_table("findings") as batch:
        batch.drop_column("detail")
        batch.drop_column("rule_id")
        batch.drop_column("source")
