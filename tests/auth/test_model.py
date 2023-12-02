import datetime
import uuid

import pytest_mock

from app.auth.constants import VerificationUsage
from app.auth.models import EmailVerification, RefreshToken
from app.core.config import config
from app.core.constants import DAY


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


def test_email_verification_random():
    """Email verification with random code"""
    res1 = EmailVerification.random(email="test@test.com", usage=VerificationUsage.SIGN_UP)
    res2 = EmailVerification.random(email="test@test.com", usage=VerificationUsage.SIGN_UP)

    assert res1.code != res2.code
