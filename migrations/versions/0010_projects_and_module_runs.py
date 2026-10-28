"""give audits a project, and record what each module of an audit cost

Revision ID: 0010
Revises: 0009
Create Date: 2026-10-28

A project is a repository as one owner audits it: immune rules and crown
jewels belong to it, not to a single audit. Until now audits only carried the
repository URL as text, so each existing (owner, repository) pair becomes a
project here and its audits point at it. Webhook audits have no owner and get
the instance's project for that repository.

module_runs records every stage an audit goes through — the LLM audit, the
evidence check, and later each module — with its status, duration and the
tokens it spent, so the cost of an audit is never a guess.

"""
from datetime import datetime, timezone

import sqlalchemy as sa
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None

_audits = sa.table("audits", sa.column("id", sa.String), sa.column("user_id", sa.Integer),
                   sa.column("repo_url", sa.String), sa.column("project_id", sa.Integer))
_projects = sa.table("projects", sa.column("id", sa.Integer),
                     sa.column("user_id", sa.Integer), sa.column("repo_url", sa.String),
                     sa.column("created_at", sa.DateTime(timezone=True)))


def upgrade() -> None:
    op.create_table(
        "projects",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        # NULL is the instance's own project, which webhook audits belong to.
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=True),
        sa.Column("repo_url", sa.String(255), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("user_id", "repo_url", name="uq_projects_user_repo"),
    )
    op.create_index("ix_projects_user_id", "projects", ["user_id"])
    with op.batch_alter_table("audits") as batch:
        batch.add_column(sa.Column("project_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_audits_project_id", "projects",
                                 ["project_id"], ["id"], ondelete="SET NULL")
        batch.create_index("ix_audits_project_id", ["project_id"])

    connection = op.get_bind()
    pairs = connection.execute(
        sa.select(_audits.c.user_id, _audits.c.repo_url).distinct()).fetchall()
    now = datetime.now(timezone.utc)
    for user_id, repo_url in pairs:
        project_id = connection.execute(
            _projects.insert().values(user_id=user_id, repo_url=repo_url,
                                      created_at=now)
            .returning(_projects.c.id)).scalar_one()
        owner = (_audits.c.user_id.is_(None) if user_id is None
                 else _audits.c.user_id == user_id)
        connection.execute(_audits.update()
                           .where(owner, _audits.c.repo_url == repo_url)
                           .values(project_id=project_id))

    op.create_table(
        "module_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("audit_id", sa.String(32),
                  sa.ForeignKey("audits.id", ondelete="CASCADE"), nullable=False),
        # audit, evidence, parallax, falsifiability, immune, leverage, attack...
        sa.Column("module", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),   # ok | error | skipped
        sa.Column("backend", sa.String(32), nullable=True),
        sa.Column("model", sa.String(128), nullable=True),
        sa.Column("tokens_in", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("tokens_out", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_module_runs_audit_id", "module_runs", ["audit_id"])


def downgrade() -> None:
    op.drop_index("ix_module_runs_audit_id", table_name="module_runs")
    op.drop_table("module_runs")
    with op.batch_alter_table("audits") as batch:
        batch.drop_index("ix_audits_project_id")
        batch.drop_constraint("fk_audits_project_id", type_="foreignkey")
        batch.drop_column("project_id")
    op.drop_index("ix_projects_user_id", table_name="projects")
    op.drop_table("projects")
