import datetime
import secrets
from uuid import UUID

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.constants import ErrorEnum
from app.auth.models import RefreshToken
from app.core.config import config
from app.core.errors import NotFoundError, UnauthorizedError, ValidationError
from app.user.models import User


class AuthService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def sign_up_by_email(self, email: str, password: str, nickname: str):
        user = User(
            email=email,
            nickname=nickname,
        )
        user.set_password(password)
        self.session.add(user)

        try:
            await self.session.flush()
        except IntegrityError as e:
            if "duplicate" in str(e):
                raise ValidationError(ErrorEnum.USER_ALREADY_EXISTS)
            raise e

        user.last_logged_in = datetime.datetime.now(tz=datetime.UTC)
        refresh_token = RefreshToken(
            user_id=user.id,
            expires_at=datetime.datetime.now(tz=datetime.UTC)
            + datetime.timedelta(seconds=config.refresh_token_expires_seconds),
            token=secrets.token_urlsafe(32),
        )
        self.session.add(refresh_token)
        await self.session.commit()

        return user, refresh_token

    async def sign_in_by_email(self, email: str, password: str):
        res = await self.session.execute(sa.select(User).where(User.email == email))
        user = res.scalar_one_or_none()

        if user is None:
            raise NotFoundError(ErrorEnum.USER_NOT_FOUND)

        if not user.verify_password(password):
            raise ValidationError(ErrorEnum.PASSWORD_DOES_NOT_MATCH)

        user.last_logged_in = datetime.datetime.now(tz=datetime.UTC)
        refresh_token = RefreshToken(
            user_id=user.id,
            expires_at=datetime.datetime.now(tz=datetime.UTC)
            + datetime.timedelta(seconds=config.refresh_token_expires_seconds),
            token=secrets.token_urlsafe(32),
        )
        self.session.add(refresh_token)

        await self.session.commit()

        return user, refresh_token

    async def renew_refresh_token_if_needed(self, user_id: UUID, token: str):
        old_token = await self.session.scalar(
            sa.select(RefreshToken).where(
                RefreshToken.user_id == user_id,
                RefreshToken.token == token,
                RefreshToken.is_revoked.is_(False),
            )
        )

        if old_token is None:
            raise UnauthorizedError(ErrorEnum.INVALID_REFRESH_TOKEN)

        old_token.validate()

        if old_token.is_stale:
            old_token.is_revoked = True
            new_refresh_token = RefreshToken(
                user_id=user_id,
                expires_at=datetime.datetime.now(tz=datetime.UTC)
                + datetime.timedelta(seconds=config.refresh_token_expires_seconds),
                token=secrets.token_urlsafe(32),
            )
            await self.session.commit()
            return new_refresh_token

        return None
