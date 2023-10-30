from typing import cast

import sqlalchemy as sa
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dto import AuthenticatedUser, SignInResponse
from app.auth.models import RefreshToken
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


async def test_signin_by_email_fails_with_non_existing_user(client: AsyncClient):
    """Test sign in by email fails with non existing user"""
    # when
    response = await client.post(
        "/auth/sign-in/email",
        json={
            "email": "randomuser@test.com",
            "password": "password123!",
        },
    )

    # then
    assert response.status_code == 404
    assert response.json() == {
        "code": "USER_NOT_FOUND",
        "message": "Specified user does not exist.",
    }


async def test_signin_by_email_fails_with_wrong_password(
    client: AsyncClient, session: AsyncSession
):
    """Test sign in by email fails with wrong password"""
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
            "password": "wrongpassword123!",
        },
    )

    # then
    assert response.status_code == 409
    assert response.json() == {
        "code": "PASSWORD_DOES_NOT_MATCH",
        "message": "Provided password does not match.",
    }