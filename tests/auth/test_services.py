import asyncio

import pytest
import pytest_mock
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.constants import ErrorEnum, VerificationUsage
from app.auth.models import EmailVerification
from app.auth.service import AuthService
from app.core.config import config
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

    assert e.value.error_code == ErrorEnum.PASSWORD_DOES_NOT_MATCH.code
    assert e.value.message == ErrorEnum.PASSWORD_DOES_NOT_MATCH.message


async def test_cannot_sign_in_by_email_with_non_existing_user(session: AsyncSession):
    """Cannot sign in by email with non existing user"""
    # given
    service = AuthService(session)

    # when & then
    with pytest.raises(NotFoundError) as e:
        await service.sign_in_by_email("random@test.com", "password123!")

    assert e.value.error_code == ErrorEnum.USER_NOT_FOUND.code
    assert e.value.message == ErrorEnum.USER_NOT_FOUND.message


async def test_cannot_renew_refresh_token_with_expired_token(session: AsyncSession):
    """Cannot renew refresh token with invalid token"""
    # given
    service = AuthService(session)

    # when & then
    with pytest.raises(ValidationError) as e:
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


async def test_verify_email(session: AsyncSession):
    """Verify email works"""
    # given
    email = "test@test.com"
    user = User(
        email=email,
        nickname="testuser",
    )
    user.set_password("password123!")
    session.add(user)
    await session.flush()

    verification = EmailVerification.from_user(user, VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    # when
    service = AuthService(session)
    await service.verify_email(email=email, code=verification.code, usage=VerificationUsage.SIGN_UP)

    # then
    await session.refresh(user)
    assert user.email_verified


async def test_cannot_verify_email_with_invalid_code(session: AsyncSession):
    """Cannot verify email with invalid code"""
    # given
    email = "test@test.com"
    user = User(
        email=email,
        nickname="testuser",
    )
    user.set_password("password123!")
    session.add(user)
    await session.flush()

    verification = EmailVerification.from_user(user, VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    # when & then
    service = AuthService(session)
    with pytest.raises(ValidationError) as e:
        await service.verify_email(email=email, code="invalidcode", usage=VerificationUsage.SIGN_UP)

    assert e.value.error_code == ErrorEnum.INVALID_VERIFICATION_CODE.code
    assert e.value.message == ErrorEnum.INVALID_VERIFICATION_CODE.message


async def test_cannot_verify_email_with_different_email(session: AsyncSession):
    """Cannot verify email with different email"""
    # given
    email = "test@test.com"
    user = User(
        email=email,
        nickname="testuser",
    )
    user.set_password("password123!")
    session.add(user)
    await session.flush()

    verification = EmailVerification.from_user(user, VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    # when & then
    service = AuthService(session)
    with pytest.raises(ValidationError) as e:
        await service.verify_email(
            email="different@test.com", code=verification.code, usage=VerificationUsage.SIGN_UP
        )

    assert e.value.error_code == ErrorEnum.INVALID_VERIFICATION_CODE.code
    assert e.value.message == ErrorEnum.INVALID_VERIFICATION_CODE.message
