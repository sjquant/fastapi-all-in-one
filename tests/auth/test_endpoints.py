import datetime
import secrets
from typing import cast

import sqlalchemy as sa
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.constants import ErrorEnum, VerificationUsage
from app.auth.deps import current_user
from app.auth.dto import AuthenticatedUser, SignInResponse
from app.auth.models import EmailVerification, RefreshToken
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
    # when
    response = await client.post(
        "/auth/sign-up/email",
        json={
            "email": "test@test.com",
            "password": "password123!",
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


async def test_verify_email(client: AsyncClient, session: AsyncSession):
    """Test verify email"""
    # given
    user = User(
        email="test@test.com",
        nickname="testuser",
    )
    user.set_password("password123!")
    session.add(user)
    await session.flush()
    app.dependency_overrides[current_user] = lambda: user

    verification = EmailVerification.from_user(user, VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    # when
    response = await client.post(
        "/auth/verify-email",
        json={
            "email": "test@test.com",
            "code": verification.code,
        },
    )

    # then
    assert response.status_code == 200
