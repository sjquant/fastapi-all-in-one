"""

Revision ID: b45f9ba6a4b5
Revises: 66d56c113f0a
Create Date: 2024-01-10 00:32:36.785438

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op
from app.core.db import GUID

# revision identifiers, used by Alembic.
revision: str = "b45f9ba6a4b5"
down_revision: str | None = "66d56c113f0a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        "auth__oauth_states",
        sa.Column("state", sa.String(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("id", GUID(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id"),
    )
    op.create_index(
        op.f("ix_auth__oauth_states_state"), "auth__oauth_states", ["state"], unique=False
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f("ix_auth__oauth_states_state"), table_name="auth__oauth_states")
    op.drop_table("auth__oauth_states")
    # ### end Alembic commands ###