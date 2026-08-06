"""add users, sessions, and per-user ownership

Revision ID: 0004
Revises: 0003
Create Date: 2026-08-06

"""
from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("github_id", sa.String(32), nullable=False, unique=True),
        sa.Column("login", sa.String(100), nullable=False),
        sa.Column("name", sa.String(200), nullable=True),
        sa.Column("avatar_url", sa.String(512), nullable=True),
        sa.Column("is_admin", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_table(
        "user_sessions",
        sa.Column("token", sa.String(64), primary_key=True),
        sa.Column("user_id", sa.Integer(),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])

    # Existing rows keep a NULL owner: audits already run stay attributed to the
    # instance, and the settings row created before sign-in existed becomes the
    # instance-wide default that webhook audits use.
    #
    # batch_alter_table because SQLite cannot add a constraint with ALTER TABLE;
    # it recreates the table there and is a plain ALTER on PostgreSQL.
    with op.batch_alter_table("audits") as batch:
        batch.add_column(sa.Column("user_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_audits_user_id", "users",
                                 ["user_id"], ["id"], ondelete="SET NULL")
    op.create_index("ix_audits_user_id", "audits", ["user_id"])

    with op.batch_alter_table("settings") as batch:
        batch.add_column(sa.Column("user_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_settings_user_id", "users",
                                 ["user_id"], ["id"], ondelete="CASCADE")
        batch.create_unique_constraint("uq_settings_user_id", ["user_id"])


def downgrade() -> None:
    with op.batch_alter_table("settings") as batch:
        batch.drop_constraint("uq_settings_user_id", type_="unique")
        batch.drop_constraint("fk_settings_user_id", type_="foreignkey")
        batch.drop_column("user_id")

    op.drop_index("ix_audits_user_id", table_name="audits")
    with op.batch_alter_table("audits") as batch:
        batch.drop_constraint("fk_audits_user_id", type_="foreignkey")
        batch.drop_column("user_id")

    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_table("user_sessions")
    op.drop_table("users")
