import asyncio

import pytest
import pytest_mock
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.constants import ErrorEnum
from app.auth.service import AuthService
from app.core.config import config
from app.core.errors import NotFoundError, UnauthorizedError, ValidationError
from app.user.models import User


async def test_sign_up_by_email(session: AsyncSession):
    """Sign up by email works"""
    # given
    service = AuthService(session)
    email = "test@test.com"
    password = "password123!"
    nickname = "testuser"

    # when
    user, token = await service.sign_up_by_email(email, password, nickname)

    # then
    actual = await session.get(User, user.id)
    assert actual == user
    assert token.user_id == user.id


async def test_cannot_sign_up_by_duplicate_email(session: AsyncSession):
    """Cannot sign up by duplicate email"""
    # given
    service = AuthService(session)
    email = "test@test.com"
    password = "password123!"
    nickname = "testuser"

    await service.sign_up_by_email(email, password, nickname)

    # when & then
    with pytest.raises(ValidationError) as e:
        await service.sign_up_by_email(email, password, "testuser2")

    assert e.value.error_code == "USER_ALREADY_EXISTS"
    assert e.value.message == "Specified user already exists."


async def test_cannot_sign_up_by_duplicate_nickname(session: AsyncSession):
    """Cannot sign up by duplicate nickname"""
    # given
    service = AuthService(session)
    email = "test@test.com"
    password = "password123!"
    nickname = "testuser"

    await service.sign_up_by_email(email, password, nickname)

    # when & then
    with pytest.raises(ValidationError) as e:
        await service.sign_up_by_email("test2@test.com", password, nickname)

    assert e.value.error_code == "USER_ALREADY_EXISTS"
    assert e.value.message == "Specified user already exists."


async def test_sign_in_by_email(session: AsyncSession):
    """Sign in by email works"""
    # given
    service = AuthService(session)

    email = "test@test.com"
    nickname = "testuser"
    password = "password123!"
    user = User(
        email=email,
        nickname=nickname,
    )
    user.set_password(password)
    session.add(user)
    await session.flush()

    # when
    user, token = await service.sign_in_by_email(email, password)

    # then
    actual = await session.get(User, user.id)
    assert actual == user
    assert token.user_id == user.id


async def test_cannot_sign_in_by_email_with_wrong_password(session: AsyncSession):
    """Cannot sign in by email with wrong password"""
    # given
    service = AuthService(session)

    email = "test@test.com"
    nickname = "testuser"
    password = "password123!"
    user = User(
        email=email,
        nickname=nickname,
    )
    user.set_password(password)
    session.add(user)
    await session.flush()

    # when & then
    with pytest.raises(ValidationError) as e:
        await service.sign_in_by_email(email, "wrongpassword123!")

    assert e.value.error_code == "PASSWORD_DOES_NOT_MATCH"
    assert e.value.message == "Provided password does not match."


async def test_cannot_sign_in_by_email_with_non_existing_user(session: AsyncSession):
    """Cannot sign in by email with non existing user"""
    # given
    service = AuthService(session)

    # when & then
    with pytest.raises(NotFoundError) as e:
        await service.sign_in_by_email("random@test.com", "password123!")

    assert e.value.error_code == "USER_NOT_FOUND"
    assert e.value.message == "Specified user does not exist."


async def test_cannot_renew_refresh_token_with_expired_token(session: AsyncSession):
    """Cannot renew refresh token with invalid token"""
    # given
    service = AuthService(session)

    # when & then
    with pytest.raises(UnauthorizedError) as e:
        await service.renew_refresh_token_if_needed("invalidtoken")

    assert e.value.error_code == ErrorEnum.INVALID_REFRESH_TOKEN.code
    assert e.value.message == ErrorEnum.INVALID_REFRESH_TOKEN.message


async def test_renew_refresh_token_if_stale(
    session: AsyncSession, mocker: pytest_mock.MockerFixture
) -> None:
    """Renew refresh token if old token is stale"""
    # given
    mocker.patch.object(config, "refresh_token_stale_seconds", 0.01)
    service = AuthService(session)

    _, old_token = await service.sign_up_by_email("test@test.com", "test123!", "testuser")

    # when
    await asyncio.sleep(0.02)
    new_token, is_renewed = await service.renew_refresh_token_if_needed(old_token.token)

    # then
    assert new_token.token != old_token.token  # type: ignore
    assert is_renewed


async def test_do_not_renew_refresh_token_if_not_stale(
    session: AsyncSession, mocker: pytest_mock.MockerFixture
) -> None:
    """If old token is not stale, do not renew refresh token and return None"""
    # given
    service = AuthService(session)

    _, old_token = await service.sign_up_by_email("test@test.com", "test123!", "testuser")
    new_token, is_renewed = await service.renew_refresh_token_if_needed(old_token.token)

    # then
    assert new_token == old_token
    assert not is_renewed
