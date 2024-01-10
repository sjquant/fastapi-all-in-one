import datetime
import secrets
from typing import cast
from unittest.mock import ANY, Mock

import sqlalchemy as sa
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.constants import ErrorEnum, VerificationUsage
from app.auth.deps import current_user, oauth2_token, oauth2_user_data, oauth_provider
from app.auth.dto import AuthenticatedUser, OAuth2UserData, SignInResponse
from app.auth.models import EmailVerification, RefreshToken
from app.core.config import config
from app.core.deps import email_backend
from app.core.email import EmailBackendBase
from app.core.oauth2.base import OAuth2Base, OAuth2Token
from app.main import app
from app.user.models import User


async def test_signin_by_email(client: AsyncClient, session: AsyncSession):
    """Test sign in by email"""
    # given
    user = User(
        email="testuser@test.com",
        nickname="testuser",
    )
    user.set_password("password123!")
    session.add(user)
    await session.flush()

    # when
    response = await client.post(
        "/auth/sign-in/email",
        json={
            "email": "testuser@test.com",
            "password": "password123!",
        },
    )

    # then
    assert response.status_code == 200
    data = response.json()
    assert SignInResponse(**data) == SignInResponse(
        access_token=data["access_token"], user=AuthenticatedUser.model_validate(user)
    )

    result = await session.scalar(sa.select(RefreshToken).where(RefreshToken.user_id == user.id))
    assert cast(RefreshToken, result).token == response.cookies["refresh_token"]


async def test_signup_by_email(client: AsyncClient, session: AsyncSession):
    """Test sign up by email"""
    # given
    email = "test@test.com"
    verification = EmailVerification.random(
        email=email,
        usage=VerificationUsage.SIGN_UP,
    )
    session.add(verification)
    await session.flush()

    # when
    response = await client.post(
        "/auth/sign-up/email",
        json={
            "email": email,
            "code": verification.code,
            "state": verification.state,
            "nickname": "testuser",
        },
    )

    # then
    assert response.status_code == 200
    data = response.json()
    assert SignInResponse(**data) == SignInResponse(
        access_token=data["access_token"], user=AuthenticatedUser(**data["user"])
    )

    result = await session.scalar(sa.select(User).where(User.email == "test@test.com"))
    assert result is not None

    token = await session.scalar(sa.select(RefreshToken).where(RefreshToken.user_id == result.id))
    assert cast(RefreshToken, token).token == response.cookies["refresh_token"]


async def test_refresh_token(client: AsyncClient, session: AsyncSession):
    """Test refresh token works"""
    # given
    user = User(
        email="test@test.com",
        nickname="testuser",
    )
    user.set_password("password123!")
    session.add(user)
    await session.flush()

    refresh_token = RefreshToken(
        token=secrets.token_urlsafe(32),
        user_id=user.id,
        expires_at=datetime.datetime.now(tz=datetime.UTC) + datetime.timedelta(days=1),
    )
    session.add(refresh_token)
    await session.flush()

    app.dependency_overrides[current_user] = lambda: user

    # when
    response = await client.post(
        "/auth/refresh-token",
        cookies={"refresh_token": refresh_token.token},
    )

    # then
    assert response.status_code == 200
    data = response.json()
    assert data["access_token"] is not None


async def test_cannot_refresh_token_without_refresh_token(
    client: AsyncClient, session: AsyncSession
):
    """Test cannot refresh token without refresh token"""
    # given
    user = User(
        email="test@test.com",
        nickname="testuser",
    )
    user.set_password("password123!")
    session.add(user)
    await session.flush()
    app.dependency_overrides[current_user] = lambda: user

    # when
    response = await client.post("/auth/refresh-token")

    # then
    assert response.status_code == 409
    assert response.json() == {
        "code": ErrorEnum.NO_REFRESH_TOKEN.code,
        "message": ErrorEnum.NO_REFRESH_TOKEN.message,
    }


async def test_signup_status(client: AsyncClient, session: AsyncSession):
    """Test get signup status"""
    # given
    user = User(
        email="test@test.com",
        nickname="testuser",
    )
    session.add(user)
    await session.flush()

    # when
    response = await client.post("/auth/get-signup-status", json={"email": user.email})

    # then
    assert response.status_code == 200
    assert response.json() == {
        "has_account": True,
        "has_password": False,
    }


async def test_send_signup_email(client: AsyncClient, session: AsyncSession):
    """Test send signup email"""
    # given
    email_backend_mock = Mock(spec=EmailBackendBase)
    app.dependency_overrides[email_backend] = lambda: email_backend_mock
    recipient_email = "test@test.com"

    # when
    response = await client.post("/auth/send-signup-email", json={"email": recipient_email})

    # then
    assert response.status_code == 200
    assert response.json() == {
        "state": ANY,
    }
    email_backend_mock.send.assert_called_with(  # type: ignore
        sender=config.email_sender, recipients=[recipient_email], subject=ANY, body_plain=ANY
    )


async def test_get_authorization_url(client: AsyncClient, session: AsyncSession):
    """Test get authorization url"""
    # given
    oauth_provider_mock = Mock(spec=OAuth2Base)
    oauth_provider_mock.get_authorization_url.return_value = "https://test.com"
    app.dependency_overrides[oauth_provider] = lambda: oauth_provider_mock

    # when
    response = await client.post("/auth/oauth2/test/get-authorization-url")

    # then
    assert response.status_code == 200
    assert response.json() == {
        "url": "https://test.com",
    }


async def test_oauth2_callback(client: AsyncClient, session: AsyncSession):
    """Test oauth2 callback"""
    # given
    token = OAuth2Token.model_validate(
        {
            "access_token": "ACCCESS_TOEKN",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "TEST_TOKEN",
            "scope": "test",
        }
    )
    app.dependency_overrides[oauth2_token] = lambda: token
    user_data = OAuth2UserData(
        uid="test",
        email="test@test.com",
        photo="https://test.com",
    )
    app.dependency_overrides[oauth2_user_data] = lambda: user_data

    # when
    response = await client.get(
        "/auth/oauth2/test/callback",
        params={"code": "test", "state": "test"},
    )

    # then
    assert response.status_code == 200
    assert response.cookies["refresh_token"] is not None

    user = await session.scalar(sa.select(User).where(User.email == user_data.email))
    assert user is not None


async def test_oauth2_callback_with_invalid_state(client: AsyncClient, session: AsyncSession):
    """Test oauth2 callback does not work with invalid state"""
    # given
    user_data = OAuth2UserData(
        uid="test",
        email="test@test.com",
        photo="https://test.com",
    )
    app.dependency_overrides[oauth2_user_data] = lambda: user_data

    # when
    response = await client.get(
        "/auth/oauth2/kakao/callback",
        params={"code": "test", "state": "invalid"},
    )

    # then
    assert response.status_code == 403
    assert response.json() == {
        "code": ErrorEnum.INVALID_OAUTH_STATE.code,
        "message": ErrorEnum.INVALID_OAUTH_STATE.message,
    }
