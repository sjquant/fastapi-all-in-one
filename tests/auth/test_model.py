import datetime

import pytest
import pytest_mock

from app.auth.constants import ErrorEnum
from app.auth.models import RefreshToken
from app.core.config import config
from app.core.constants import DAY
from app.core.errors import UnauthorizedError


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
