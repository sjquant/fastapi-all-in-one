"""

Revision ID: 863bf8f66115
Revises: 
Create Date: 2023-10-08 00:09:22.195301

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from app.core.db import GUID

# revision identifiers, used by Alembic.
revision: str = "863bf8f66115"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "user__users",
        sa.Column("email", sa.String(), nullable=False),
        sa.Column("nickname", sa.String(length=12), nullable=False),
        sa.Column("photo", sa.String(), nullable=False),
        sa.Column("hashed_password", sa.String(), nullable=True),
        sa.Column("last_logged_in", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("id", GUID(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id"),
    )
    op.create_index(op.f("ix_user__users_email"), "user__users", ["email"], unique=True)
    op.create_index(op.f("ix_user__users_nickname"), "user__users", ["nickname"], unique=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f("ix_user__users_nickname"), table_name="user__users")
    op.drop_index(op.f("ix_user__users_email"), table_name="user__users")
    op.drop_table("user__users")
    # ### end Alembic commands ###