"""

Revision ID: 26f3f3105e26
Revises: 0ea8d083d800
Create Date: 2023-10-24 01:21:43.023652

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from app.core.db import GUID

# revision identifiers, used by Alembic.
revision: str = "26f3f3105e26"
down_revision: str | None = "0ea8d083d800"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "auth__refresh_tokens",
        sa.Column("token", sa.String(length=255), nullable=False),
        sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column("user_id", GUID(), nullable=False),
        sa.Column("id", GUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user__users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id"),
    )
    op.create_index(
        op.f("ix_auth__refresh_tokens_token"), "auth__refresh_tokens", ["token"], unique=True
    )
    op.create_unique_constraint(None, "user__users", ["id"])
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, "user__users", type_="unique")
    op.drop_index(op.f("ix_auth__refresh_tokens_token"), table_name="auth__refresh_tokens")
    op.drop_table("auth__refresh_tokens")
    # ### end Alembic commands ###
