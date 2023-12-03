from __future__ import annotations

import datetime
import secrets
from uuid import UUID

import sqlalchemy as sa
from pydantic import ValidationError
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.auth.constants import ErrorEnum, VerificationUsage
from app.core.config import config
from app.core.db import Model, TimestampMixin
from app.core.utils import is_valid_email


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
        """
        Create a new RefreshToken instance from a user ID.

        Args:
            user_id: The ID of the user.

        Returns:
            RefreshToken: The newly created RefreshToken instance.
        """
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


class EmailVerification(Model, TimestampMixin):
    __tablename__ = "auth__email_verifications"

    email: Mapped[str] = mapped_column(sa.String, nullable=False, index=True)
    code: Mapped[str] = mapped_column(sa.String, nullable=False)
    state: Mapped[str] = mapped_column(sa.String, nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False
    )
    verified: Mapped[bool] = mapped_column(sa.Boolean, default=False, nullable=False)
    user_id: Mapped[UUID | None] = mapped_column(sa.ForeignKey("user__users.id"), nullable=True)
    usage: Mapped[VerificationUsage] = mapped_column(sa.String, nullable=False)
    is_revoked: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False, index=True)

    @classmethod
    def random(
        cls, *, email: str, usage: VerificationUsage, user_id: UUID | None = None
    ) -> EmailVerification:
        """
        Generate a random EmailVerification instance.

        Args:
            email: The email address associated with the verification.
            usage : The usage of the verification.
            user_id: The ID of the user associated with the verification. Defaults to None.

        Returns:
            EmailVerification: The generated EmailVerification instance.
        """
        code = "".join(
            secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ")
            for _ in range(config.email_verification_code_length)
        )
        state = secrets.token_urlsafe(32)
        return cls(
            email=email,
            code=code,
            state=state,
            expires_at=datetime.datetime.now(datetime.UTC)
            + datetime.timedelta(seconds=config.email_verificaton_token_expires_seconds),
            user_id=user_id,
            usage=usage,
        )

    @property
    def is_expired(self):
        return self.expires_at < datetime.datetime.now(datetime.UTC)

    @property
    def is_valid(self):
        return not self.is_expired and not self.is_revoked

    @validates("email")
    def validate_email(self, key: str, email: str):
        if not is_valid_email(email):
            raise ValidationError(ErrorEnum.INVALID_EMAIL)
        return email
