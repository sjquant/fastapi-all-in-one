"""

Revision ID: 66d56c113f0a
Revises: c1d1484bf6f3
Create Date: 2024-01-07 22:40:10.466401

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from app.core.db import GUID

# revision identifiers, used by Alembic.
revision: str = "66d56c113f0a"
down_revision: str | None = "c1d1484bf6f3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "auth__oauth_credentials",
        sa.Column("provider", sa.String(), nullable=False),
        sa.Column("access_token", sa.String(), nullable=False),
        sa.Column("refresh_token", sa.String(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("uid", sa.String(), nullable=False),
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
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table("auth__oauth_credentials")
    # ### end Alembic commands ###
