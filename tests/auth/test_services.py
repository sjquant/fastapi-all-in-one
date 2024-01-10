import asyncio
from unittest.mock import Mock

import pytest
import pytest_mock
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.constants import ErrorEnum, VerificationUsage
from app.auth.dto import OAuth2UserData, SignupStatus
from app.auth.models import EmailVerification, OAuthCredential, OAuthState
from app.auth.service import AuthService
from app.core.config import config
from app.core.email import EmailBackendBase
from app.core.errors import NotFoundError, PermissionDenied, ValidationError
from app.core.oauth2.base import OAuth2Token
from app.user.models import User


async def test_sign_up_by_email(session: AsyncSession):
    """Sign up by email works"""
    # given
    email = "test@test.com"
    verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    # when
    service = AuthService(session)
    user, token = await service.sign_up_by_email(
        email=email, code=verification.code, state=verification.state, nickname="testuser"
    )

    # then
    actual = await session.get(User, user.id)
    assert actual == user
    assert token.user_id == user.id


async def test_cannot_sign_up_by_duplicate_email(session: AsyncSession):
    """Cannot sign up by duplicate email"""
    # given
    email = "test@test.com"
    verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    user = User(
        email=email,
        nickname="testuser",
    )
    session.add(user)
    await session.flush()

    # when & then
    service = AuthService(session)
    with pytest.raises(ValidationError) as e:
        await service.sign_up_by_email(
            email=email, code=verification.code, state=verification.state, nickname="someoneelse"
        )

    assert e.value.error_code == ErrorEnum.USER_ALREADY_EXISTS.code
    assert e.value.message == ErrorEnum.USER_ALREADY_EXISTS.message


async def test_cannot_sign_up_by_duplicate_nickname(session: AsyncSession):
    """Cannot sign up by duplicate nickname"""
    # given
    email = "test1@test.com"
    verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()
    await create_user(session, nickname="testuser")

    # when & then
    service = AuthService(session)
    with pytest.raises(ValidationError) as e:
        await service.sign_up_by_email(
            email=email, code=verification.code, state=verification.state, nickname="testuser"
        )

    assert e.value.error_code == ErrorEnum.USER_ALREADY_EXISTS.code
    assert e.value.message == ErrorEnum.USER_ALREADY_EXISTS.message


async def test_sign_in_by_email(session: AsyncSession):
    """Sign in by email works"""
    # given
    user = await create_user(session, nickname="testuser", password="password123!")
    service = AuthService(session)

    # when
    user, token = await service.sign_in_by_email(user.email, "password123!")

    # then
    actual = await session.get(User, user.id)
    assert actual == user
    assert token.user_id == user.id


async def test_cannot_sign_in_by_email_with_wrong_password(session: AsyncSession):
    """Cannot sign in by email with wrong password"""
    # given
    user = await create_user(session, nickname="testuser", password="password123!")
    service = AuthService(session)

    # when & then
    with pytest.raises(PermissionDenied) as e:
        await service.sign_in_by_email(user.email, "wrongpassword123!")

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
    with pytest.raises(PermissionDenied) as e:
        await service.renew_refresh_token_if_needed("invalidtoken")

    assert e.value.error_code == ErrorEnum.INVALID_REFRESH_TOKEN.code
    assert e.value.message == ErrorEnum.INVALID_REFRESH_TOKEN.message


async def test_renew_refresh_token_if_stale(
    session: AsyncSession, mocker: pytest_mock.MockerFixture
) -> None:
    """Renew refresh token if old token is stale"""
    # given
    mocker.patch.object(config, "refresh_token_stale_seconds", 0.01)
    email = "test@test.com"
    verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    service = AuthService(session)

    _, old_token = await service.sign_up_by_email(
        email=email, code=verification.code, state=verification.state, nickname="testuser"
    )

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
    email = "test@test.com"
    verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    # when
    service = AuthService(session)
    _, old_token = await service.sign_up_by_email(
        email=email, code=verification.code, state=verification.state, nickname="testuser"
    )
    new_token, is_renewed = await service.renew_refresh_token_if_needed(old_token.token)

    # then
    assert new_token == old_token
    assert not is_renewed


async def test_verify_email(session: AsyncSession):
    """Verify email works"""
    # given
    email = "test@test.com"
    verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    # when
    service = AuthService(session)
    await service.verify_email(
        email=email,
        code=verification.code,
        state=verification.state,
        usage=VerificationUsage.SIGN_UP,
    )


async def test_cannot_verify_email_with_invalid_code(session: AsyncSession):
    """Cannot verify email with invalid code"""
    # given
    email = "test@test.com"
    verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    # when & then
    service = AuthService(session)
    with pytest.raises(PermissionDenied) as e:
        await service.verify_email(
            email=email,
            code="invalidcode",
            state=verification.state,
            usage=VerificationUsage.SIGN_UP,
        )

    assert e.value.error_code == ErrorEnum.INVALID_VERIFICATION_CODE.code
    assert e.value.message == ErrorEnum.INVALID_VERIFICATION_CODE.message


async def test_cannot_verify_email_with_different_email(session: AsyncSession):
    """Cannot verify email with different email"""
    # given
    email = "test@test.com"
    verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    # when & then
    service = AuthService(session)
    with pytest.raises(PermissionDenied) as e:
        await service.verify_email(
            email="different@test.com",
            code=verification.code,
            state=verification.state,
            usage=VerificationUsage.SIGN_UP,
        )

    assert e.value.error_code == ErrorEnum.INVALID_VERIFICATION_CODE.code
    assert e.value.message == ErrorEnum.INVALID_VERIFICATION_CODE.message


async def test_cannot_verify_email_with_different_state(session: AsyncSession):
    """Cannot verify email with different state"""
    # given
    email = "test@test.com"
    verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
    session.add(verification)
    await session.flush()

    # when & then
    service = AuthService(session)
    with pytest.raises(PermissionDenied) as e:
        await service.verify_email(
            email=email,
            code=verification.code,
            state="differentstate",
            usage=VerificationUsage.SIGN_UP,
        )

    assert e.value.error_code == ErrorEnum.INVALID_VERIFICATION_CODE.code
    assert e.value.message == ErrorEnum.INVALID_VERIFICATION_CODE.message


async def test_signup_status(session: AsyncSession):
    """Signup status with no password works"""
    # given
    user = await create_user(session, nickname="testuser", password=None)

    # when
    service = AuthService(session)
    res = await service.get_signup_status(user.email)

    # then
    assert res == SignupStatus(has_account=True, has_password=False)


async def test_signup_status_with_password(session: AsyncSession):
    """Signup status with password works"""
    # given
    user = await create_user(session, nickname="testuser", password="password123!")

    # when
    service = AuthService(session)
    res = await service.get_signup_status(user.email)

    # then
    assert res == SignupStatus(has_account=True, has_password=True)


async def test_signup_status_with_no_account(session: AsyncSession):
    """Signup status with no account works"""
    # given
    email = "no-account@test.com"

    # when
    service = AuthService(session)
    res = await service.get_signup_status(email)

    # then
    assert res == SignupStatus(has_account=False, has_password=False)


async def test_send_signup_email(session: AsyncSession):
    """Send signup email works"""
    # given
    email = "test@test.com"
    email_backend = Mock(spec=EmailBackendBase)

    # when
    service = AuthService(session)
    state = await service.send_signup_email(email_backend, email)

    # then
    actual = await session.scalar(
        sa.select(EmailVerification).where(EmailVerification.email == email)
    )
    assert actual.state == state  # type: ignore


async def test_send_signup_email_with_existing_email(session: AsyncSession):
    """Send signup email with existing email raises error"""
    # given
    email = "test@test.com"
    email_backend = Mock(spec=EmailBackendBase)
    user = User(
        email=email,
        nickname="testuser",
    )
    session.add(user)
    await session.flush()
    service = AuthService(session)

    # when & then
    with pytest.raises(ValidationError) as e:
        await service.send_signup_email(email_backend, email)

    assert e.value.error_code == ErrorEnum.USER_ALREADY_EXISTS.code
    assert e.value.message == ErrorEnum.USER_ALREADY_EXISTS.message


async def test_send_signup_email_with_existing_verification(session: AsyncSession):
    """Send signup email with existing verification revokes the old one"""
    # given
    email = "test@test.com"
    email_backend = Mock(spec=EmailBackendBase)
    old_verification = EmailVerification.random(email=email, usage=VerificationUsage.SIGN_UP)
    session.add(old_verification)
    await session.flush()
    service = AuthService(session)

    # when
    await service.send_signup_email(email_backend, email)

    # then
    await session.refresh(old_verification)
    assert old_verification.is_revoked

    new_verification = await session.scalar(
        sa.select(EmailVerification).where(
            EmailVerification.email == email, EmailVerification.is_revoked.is_(False)
        )
    )
    assert new_verification != old_verification


async def test_handle_oauth2_when_cred_exists(session: AsyncSession):
    """OAuth2 handle works when credential exists"""
    # given
    user = await create_user(session, nickname="testuser")
    uid = "test_uid"
    cred = OAuthCredential(
        provider="test_provider",
        uid=uid,
        access_token="test_access_token",
        refresh_token="test_refresh_token",
        user_id=user.id,
    )
    session.add(cred)
    await session.flush()

    provider = "test_provider"
    token = OAuth2Token.model_validate(
        {
            "access_token": "test_access_token",
            "token_type": "test_token_type",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token",
            "scope": "test_scope",
        }
    )
    user_data = OAuth2UserData(uid=uid, email=user.email, photo="test_photo")
    service = AuthService(session)

    # when
    actual_user, refresh_token, is_new_user = await service.handle_oauth2_flow(
        provider, token, user_data
    )

    # then
    assert actual_user == user
    assert refresh_token is not None
    assert is_new_user is False


async def test_handle_oauth2_when_cred_and_user_does_not_exist(session: AsyncSession):
    """New user and cred is created when credential and user does not exist"""
    # given
    provider = "test_provider"
    token = OAuth2Token.model_validate(
        {
            "access_token": "test_access_token",
            "token_type": "test_token_type",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token",
            "scope": "test_scope",
        }
    )
    user_data = OAuth2UserData(uid="test_uid", email="testuser@test.com", photo="test_photo")
    service = AuthService(session)

    # when
    actual_user, refresh_token, is_new_user = await service.handle_oauth2_flow(
        provider, token, user_data
    )

    # then
    assert refresh_token is not None
    assert is_new_user is True

    expected_user = await session.scalar(sa.select(User).where(User.email == user_data.email))
    assert actual_user == expected_user


async def test_handle_oauth2_when_cred_does_not_exist_but_user_exists(session: AsyncSession):
    """New credential is created when credential does not exist but user exists"""
    # given
    user = await create_user(session, nickname="testuser")
    provider = "test_provider"
    token = OAuth2Token.model_validate(
        {
            "access_token": "test_access_token",
            "token_type": "test_token_type",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token",
            "scope": "test_scope",
        }
    )
    user_data = OAuth2UserData(uid="test_uid", email=user.email, photo="test_photo")
    service = AuthService(session)

    # when
    actual_user, refresh_token, is_new_user = await service.handle_oauth2_flow(
        provider, token, user_data
    )

    # then
    assert actual_user == user
    assert refresh_token is not None
    assert is_new_user is False

    expected_cred = await session.scalar(
        sa.select(OAuthCredential).where(
            OAuthCredential.provider == provider, OAuthCredential.user_id == user.id
        )
    )

    assert expected_cred is not None


async def test_verify_oauth_state_works(session: AsyncSession):
    """Verify oauth state works"""
    # given
    oauth_state = OAuthState.random()
    session.add(oauth_state)
    await session.flush()

    service = AuthService(session)

    # when
    res = await service.verify_oauth_state(oauth_state.state)

    # then
    assert res is None


async def test_verify_oauth_state_raises_error_with_invalid_state(session: AsyncSession):
    """Verify oauth state raises error with invalid state"""
    # given
    service = AuthService(session)

    # when & then
    with pytest.raises(PermissionDenied) as e:
        await service.verify_oauth_state("invalidstate")

    assert e.value.error_code == ErrorEnum.INVALID_OAUTH_STATE.code
    assert e.value.message == ErrorEnum.INVALID_OAUTH_STATE.message


async def create_user(
    session: AsyncSession, *, nickname: str, password: str | None = "password123!"
):
    user = User(
        email=f"{nickname}@test.com",
        nickname=nickname,
    )
    if password is not None:
        user.set_password(password)
    session.add(user)
    await session.flush()
    return user
