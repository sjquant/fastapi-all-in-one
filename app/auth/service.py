import datetime

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.constants import ErrorEnum, VerificationUsage
from app.auth.models import EmailVerification, RefreshToken
from app.core.errors import NotFoundError, ValidationError
from app.user.models import User


class AuthService:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def sign_up_by_email(self, *, email: str, code: str, state: str, nickname: str):
        await self.verify_email(
            email=email, code=code, state=state, usage=VerificationUsage.SIGN_UP
        )
        user = User(
            email=email,
            nickname=nickname,
        )
        self.session.add(user)

        try:
            await self.session.flush()
        except IntegrityError as e:
            if "duplicate" in str(e):
                raise ValidationError(ErrorEnum.USER_ALREADY_EXISTS)
            raise e

        user.last_logged_in = datetime.datetime.now(tz=datetime.UTC)
        refresh_token = RefreshToken.from_user_id(user.id)
        self.session.add(refresh_token)
        await self.session.commit()

        return user, refresh_token

    async def sign_in_by_email(self, email: str, password: str):
        """
        Sign in a user using their email and password.

        Args:
            email: The user's email.
            password: The user's password.

        Returns:
            Tuple[User, RefreshToken]: A tuple containing the signed-in user and the refresh token.
        """
        res = await self.session.execute(sa.select(User).where(User.email == email))
        user = res.scalar_one_or_none()

        if user is None:
            raise NotFoundError(ErrorEnum.USER_NOT_FOUND)

        if not user.verify_password(password):
            raise ValidationError(ErrorEnum.PASSWORD_DOES_NOT_MATCH)

        user.last_logged_in = datetime.datetime.now(tz=datetime.UTC)
        refresh_token = RefreshToken.from_user_id(user.id)
        self.session.add(refresh_token)

        await self.session.commit()

        return user, refresh_token

    async def renew_refresh_token_if_needed(self, token: str):
        """
        Renew the refresh token if it is stale, otherwise return the existing token.

        Args:
            token: The refresh token to check.

        Returns:
            A tuple containing the new refresh token and a boolean indicating
            whether the token was renewed, or the existing refresh token if it is not stale.
        """
        old_token = await self.session.scalar(
            sa.select(RefreshToken).where(
                RefreshToken.token == token,
                RefreshToken.is_revoked.is_(False),
            )
        )

        if old_token is None or not old_token.is_valid:
            raise ValidationError(ErrorEnum.INVALID_REFRESH_TOKEN)

        if old_token.is_stale:
            old_token.is_revoked = True
            new_refresh_token = RefreshToken.from_user_id(old_token.user_id)
            await self.session.commit()
            return new_refresh_token, True

        return old_token, False

    async def verify_email(self, *, email: str, code: str, state: str, usage: VerificationUsage):
        """
        Verify the email using the provided verification code.

        Args:
            email: The email address to verify.
            code: The verification code.
            usage: The usage type of the verification.

        Raises:
            ValidationError: If the verification code is invalid.

        Returns:
            None if the verification is successful
        """
        verification = await self.session.scalar(
            sa.select(EmailVerification).where(
                EmailVerification.email == email,
                EmailVerification.code == code,
                EmailVerification.usage == usage,
                EmailVerification.state == state,
                EmailVerification.is_revoked.is_(False),
            )
        )

        if verification is None or not verification.is_valid:
            raise ValidationError(ErrorEnum.INVALID_VERIFICATION_CODE)
