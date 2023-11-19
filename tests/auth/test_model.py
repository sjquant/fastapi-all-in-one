import datetime
import uuid

import pytest
import pytest_mock

from app.auth.constants import ErrorEnum, VerificationUsage
from app.auth.models import EmailVerification, RefreshToken
from app.core.config import config
from app.core.constants import DAY
from app.core.errors import UnauthorizedError
from app.user.models import User


def test_refresh_token_is_expired():
    """Refresh token is expired"""
    refresh_token = RefreshToken(
        expires_at=datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=1)
    )
    assert refresh_token.is_expired


def test_refresh_token_is_not_expired():
    """Refresh token is not expired"""
    refresh_token = RefreshToken(
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=1)
    )
    assert not refresh_token.is_expired


def test_refresh_toekn_is_stale(mocker: pytest_mock.MockerFixture):
    """Refresh token is stale"""
    mocker.patch.object(config, "refresh_token_stale_seconds", 7 * DAY)
    refresh_token = RefreshToken(
        created_at=datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=8)
    )
    assert refresh_token.is_stale


def test_refresh_token_is_not_stale(mocker: pytest_mock.MockerFixture):
    """Refresh token is not stale"""
    mocker.patch.object(config, "refresh_token_stale_seconds", 7 * DAY)
    refresh_token = RefreshToken(
        created_at=datetime.datetime.now(datetime.UTC) - datetime.timedelta(days=5)
    )
    assert not refresh_token.is_stale


def test_refresh_token_is_valid():
    """Refresh token is valid"""
    refresh_token = RefreshToken(
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=1),
        is_revoked=False,
    )
    assert refresh_token.is_valid


def test_refresh_token_is_not_valid():
    """Refresh token is not valid"""
    refresh_token = RefreshToken(
        expires_at=datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=1),
        is_revoked=False,
    )
    assert not refresh_token.is_valid


def test_refresh_token_validate_raises_error():
    """Refresh token validate raises error"""
    refresh_token = RefreshToken(
        expires_at=datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=1)
    )
    with pytest.raises(UnauthorizedError) as e:
        refresh_token.validate()

    assert e.value.error_code == ErrorEnum.INVALID_REFRESH_TOKEN.code
    assert e.value.message == ErrorEnum.INVALID_REFRESH_TOKEN.message


def test_refresh_token_validate_does_not_raise_error():
    """Refresh token validate does not raise error"""
    refresh_token = RefreshToken(
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=1)
    )
    refresh_token.validate()


def test_refresh_token_from_user_id():
    """RefreshToken model from user_id"""
    user_id = uuid.uuid4()
    refresh_token = RefreshToken.from_user_id(user_id)
    assert refresh_token.user_id == user_id
    assert refresh_token.token is not None
    assert refresh_token.expires_at > datetime.datetime.now(datetime.UTC)


def test_email_verification_is_expired():
    """Email verification is expired"""
    email_verification = EmailVerification(
        expires_at=datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=1)
    )
    assert email_verification.is_expired


def test_email_verification_is_not_expired():
    """Email verification is not expired"""
    email_verification = EmailVerification(
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=1)
    )
    assert not email_verification.is_expired


def test_email_verification_is_valid():
    """Email verification is valid"""
    email_verification = EmailVerification(
        expires_at=datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=1),
        is_revoked=False,
    )
    assert email_verification.is_valid


def test_email_verification_is_not_valid():
    """Email verification is not valid"""
    email_verification = EmailVerification(
        expires_at=datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=1),
        is_revoked=False,
    )
    assert not email_verification.is_valid


def test_email_verification_from_user():
    """Email verification from user"""
    user = User(id=uuid.uuid4(), email="test@test.com")
    email_verification = EmailVerification.from_user(user, VerificationUsage.SIGN_UP)
    assert email_verification.email == user.email
    assert email_verification.user_id == user.id
    assert email_verification.usage == VerificationUsage.SIGN_UP
    assert email_verification.code is not None
    assert email_verification.expires_at > datetime.datetime.now(datetime.UTC)
