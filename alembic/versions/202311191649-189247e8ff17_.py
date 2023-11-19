"""

Revision ID: 189247e8ff17
Revises: 61fd7ddbb63e
Create Date: 2023-11-19 16:49:35.384684

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "189247e8ff17"
down_revision: str | None = "61fd7ddbb63e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column(
        "user__users",
        sa.Column("email_verified", sa.Boolean(), server_default=sa.text("false"), nullable=False),
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column("user__users", "email_verified")
    # ### end Alembic commands ###