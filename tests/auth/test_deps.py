import uuid

import pytest
import pytest_mock
from fastapi.security import HTTPAuthorizationCredentials
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.constants import ErrorEnum
from app.auth.deps import current_user, require_auth
from app.core.config import config
from app.core.errors import PermissionDenied, UnauthorizedError
from app.user.models import User


async def test_current_user_returns_anonymous_user_if_no_credentials(
    mocker: pytest_mock.MockFixture,
):
    """Returns an anonymous user if no credentials are provided"""
    session = mocker.Mock(spec=AsyncSession)
    user = await current_user(session, credentials=None)
    assert user.is_anonymous


async def test_raises_unauthorized_error_if_invalid_token(
    mocker: pytest_mock.MockFixture,
):
    """Raises an unauthorized error if the token is invalid"""
    session = mocker.Mock(spec=AsyncSession)
    with pytest.raises(UnauthorizedError) as e:
        await current_user(
            session,
            credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid"),
        )

    assert e.value.error_code == ErrorEnum.INVALID_CREDENTIALS.code
    assert e.value.message == ErrorEnum.INVALID_CREDENTIALS.message


async def test_raises_unauthorized_error_if_user_not_found(
    mocker: pytest_mock.MockFixture,
):
    """Raises an unauthorized error if the user is not found"""
    session = mocker.Mock(spec=AsyncSession)
    session.get.return_value = None  # type: ignore

    token = jwt.encode(
        {"user_id": str(uuid.uuid4())}, config.jwt_secret_key, algorithm=config.jwt_algorithm
    )

    with pytest.raises(UnauthorizedError) as e:
        await current_user(
            session,
            credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=token),
        )

    assert e.value.error_code == ErrorEnum.USER_NOT_FOUND.code
    assert e.value.message == ErrorEnum.USER_NOT_FOUND.message


async def test_returns_user_if_valid_token(session: AsyncSession):
    """Returns the user if the token is valid"""

    # given
    user_id = uuid.uuid4()
    expected_user = User(id=user_id, email="test@test.com", nickname="test")
    session.add(expected_user)
    await session.flush()

    token = jwt.encode(
        {"user_id": str(user_id)}, config.jwt_secret_key, algorithm=config.jwt_algorithm
    )

    # when
    actual_user = await current_user(
        session,
        credentials=HTTPAuthorizationCredentials(scheme="Bearer", credentials=token),
    )

    # then
    assert expected_user.id == actual_user.id


async def test_require_auth_raises_permission_error_if_user_not_authenticated():
    """Raises a permission error if the user is not authenticated"""
    user = User.anonymous()

    with pytest.raises(PermissionDenied) as e:
        require_auth()(user)

    assert e.value.error_code == ErrorEnum.USER_NOT_AUTHENTICATED.code
    assert e.value.message == ErrorEnum.USER_NOT_AUTHENTICATED.message


async def test_require_auth_does_not_raise_permission_error_if_user_authenticated():
    """Does not raise a permission error if the user is authenticated"""
    user = User(id=uuid.uuid4(), email="test@test.com", nickname="test")

    res = require_auth()(user)

    assert res is None
