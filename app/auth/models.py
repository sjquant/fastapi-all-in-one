from __future__ import annotations

import datetime
import secrets
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.auth.constants import ErrorEnum, VerificationUsage
from app.core.config import config
from app.core.db import Model, TimestampMixin
from app.core.errors import UnauthorizedError
from app.user.models import User


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

    @classmethod
    def from_user_id(cls, user_id: UUID) -> RefreshToken:
        return cls(
            token=secrets.token_urlsafe(32),
            expires_at=datetime.datetime.now(datetime.UTC)
            + datetime.timedelta(seconds=config.refresh_token_expires_seconds),
            user_id=user_id,
        )

    @property
    def is_expired(self):
        return self.expires_at < datetime.datetime.now(datetime.UTC)

    @property
    def is_stale(self):
        return self.created_at <= datetime.datetime.now(tz=datetime.UTC) - datetime.timedelta(
            seconds=config.refresh_token_stale_seconds
        )

    @property
    def is_valid(self):
        return not self.is_expired and not self.is_revoked

    def validate(self):
        if not self.is_valid:
            raise UnauthorizedError(ErrorEnum.INVALID_REFRESH_TOKEN)


class EmailVerification(Model, TimestampMixin):
    __tablename__ = "auth__email_verifications"

    email: Mapped[str] = mapped_column(sa.String, nullable=False)
    code: Mapped[str] = mapped_column(sa.String, nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(sa.DateTime, nullable=False)
    verified: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    user_id: Mapped[int] = mapped_column(sa.ForeignKey("user__users.id"), nullable=False)
    usage: Mapped[VerificationUsage] = mapped_column(sa.String, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False, index=True)

    user: Mapped[User] = relationship("User")

    @classmethod
    def from_user(cls, user: User, usage: VerificationUsage) -> EmailVerification:
        code = "".join(secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(8))
        return cls(
            email=user.email,
            code=code,
            expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=3600),
            user_id=user.id,
            usage=usage,
        )

    @property
    def is_expired(self):
        return self.expires_at < datetime.datetime.now(datetime.UTC)

    @property
    def is_valid(self):
        return not self.is_expired and not self.is_revoked
