import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.service import AuthService
from app.core.errors import NotFoundError, ValidationError
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
