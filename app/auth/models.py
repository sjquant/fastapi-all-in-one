import datetime
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column

from app.auth.constants import ErrorEnum
from app.core.config import config
from app.core.db import Model, TimestampMixin
from app.core.errors import UnauthorizedError


class RefreshToken(Model, TimestampMixin):
    __tablename__ = "auth__refresh_tokens"

    token: Mapped[str] = mapped_column(sa.String(255), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=False
    )
    user_id: Mapped[UUID] = mapped_column(sa.ForeignKey("user__users.id"), nullable=False)
    is_revoked: Mapped[bool] = mapped_column(
        sa.Boolean, nullable=False, default=False, index=True, server_default=sa.false()
    )

    @property
    def is_expired(self):
        return self.expires_at < datetime.datetime.now(datetime.UTC)

    @property
    def is_stale(self):
        return self.created_at <= datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(
            seconds=config.refresh_token_stale_seconds
        )

    def validate(self):
        if self.is_expired or self.is_revoked:
            raise UnauthorizedError(ErrorEnum.INVALID_REFRESH_TOKEN)
