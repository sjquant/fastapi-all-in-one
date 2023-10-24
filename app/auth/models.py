import datetime
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Model, TimestampMixin


class RefreshToken(Model, TimestampMixin):
    __tablename__ = "auth__refresh_tokens"

    token: Mapped[str] = mapped_column(sa.String(255), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(sa.ForeignKey("user__users.id"), nullable=False)

    @property
    def is_expired(self):
        return self.expires_at < datetime.datetime.now(datetime.UTC)
