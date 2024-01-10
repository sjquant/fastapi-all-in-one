import datetime
import uuid
from typing import cast

import sqlalchemy as sa
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.constants import ErrorEnum, VerificationUsage
from app.auth.dto import OAuth2UserData, SignupStatus
from app.auth.models import EmailVerification, OAuthCredential, RefreshToken
from app.core.config import config
from app.core.email import EmailBackendBase
from app.core.errors import NotFoundError, PermissionDenied, ValidationError
from app.core.oauth2.base import OAuth2Token
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
            raise PermissionDenied(ErrorEnum.PASSWORD_DOES_NOT_MATCH)

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
            raise PermissionDenied(ErrorEnum.INVALID_REFRESH_TOKEN)

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
            raise PermissionDenied(ErrorEnum.INVALID_VERIFICATION_CODE)

    async def get_signup_status(self, email: str):
        """
        Get the sign up status of the email.

        Args:
            email: The email address to check.

        Returns:
            A tuple containing whether the email is signed up and whether the email has a password.
        """
        user = await self.session.scalar(sa.select(User).where(User.email == email))

        has_account = user is not None
        has_password = user is not None and user.hashed_password is not None

        return SignupStatus(has_account=has_account, has_password=has_password)

    async def send_signup_email(self, email_backend: EmailBackendBase, email: str):
        """
        Send a sign up email to the user.

        Args:
            email_backend: The email backend to use.
            email: The user's email address.

        Returns:
            The state of the email verification.
        """
        user = await self.session.scalar(sa.select(User).where(User.email == email))
        if user:
            raise ValidationError(ErrorEnum.USER_ALREADY_EXISTS)

        old_verifications = await self.session.scalars(
            sa.select(EmailVerification).where(
                EmailVerification.email == email,
                EmailVerification.is_revoked.is_(False),
                EmailVerification.expires_at > datetime.datetime.now(datetime.UTC),
            )
        )

        for each in old_verifications:
            each.is_revoked = True

        verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
        self.session.add(verification)

        await self.session.commit()

        subject = f"Your signup code is {verification.code}"
        body_plain = f"""Copy and paste this temporary signup code: {verification.code}

If you didn't try to signup, you can safely ignore this email."""
        await email_backend.send(
            sender=config.email_sender, recipients=[email], subject=subject, body_plain=body_plain
        )

        return verification.state

    async def handle_oauth2_flow(
        self, provider: str, token: OAuth2Token, user_data: OAuth2UserData
    ):
        """
        Handles the OAuth2 flow for the specified provider.

        Args:
            provider: The OAuth2 provider.
            token: The OAuth2 token.
            user_data: The user data obtained from the OAuth2 provider.

        Returns:
            A tuple containing the user object, refresh token,
            and a flag indicating if the user is new.
        """
        cred = await self.session.scalar(
            sa.select(OAuthCredential).where(
                OAuthCredential.provider == provider,
                OAuthCredential.uid == user_data.uid,
            )
        )
        user, is_new_user = await self._get_or_create_user_by_oauth_cred(cred, user_data)
        cred = await self._update_or_create_oauth_cred(
            cred=cred, provider=provider, user=user, token=token, uid=user_data.uid
        )
        refresh_token = RefreshToken.from_user_id(user.id)
        self.session.add(refresh_token)
        await self.session.commit()

        return user, refresh_token, is_new_user

    async def _get_or_create_user_by_oauth_cred(
        self, cred: OAuthCredential | None, user_data: OAuth2UserData
    ):
        is_new_user = False
        if cred is None:
            user = await self.session.scalar(sa.select(User).where(User.email == user_data.email))
            if user is None:
                user = User(
                    email=user_data.email,
                    photo=user_data.photo,
                    nickname=uuid.uuid4().hex[:12],  # TODO: Generate random nickname
                )
                self.session.add(user)
                await self.session.flush()
                is_new_user = True
            else:
                user.last_logged_in = datetime.datetime.now(tz=datetime.UTC)
        else:
            user = cast(
                User, await self.session.scalar(sa.select(User).where(User.id == cred.user_id))
            )
            user.last_logged_in = datetime.datetime.now(tz=datetime.UTC)
        return user, is_new_user

    async def _update_or_create_oauth_cred(
        self,
        *,
        cred: OAuthCredential | None,
        provider: str,
        user: User,
        uid: str,
        token: OAuth2Token,
    ):
        if cred is None:
            cred = OAuthCredential(
                provider=provider,
                uid=uid,
                user_id=user.id,
                access_token=token.access_token,
                refresh_token=token.refresh_token,
                expires_at=(
                    datetime.datetime.fromtimestamp(token.expires_at, tz=datetime.UTC)
                    if token.expires_at
                    else None
                ),
            )
            self.session.add(cred)
        else:
            cred.access_token = token.access_token
            cred.refresh_token = token.refresh_token
            cred.expires_at = (
                datetime.datetime.fromtimestamp(token.expires_at, tz=datetime.UTC)
                if token.expires_at
                else None
            )
        return cred
