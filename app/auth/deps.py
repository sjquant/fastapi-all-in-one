from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt
from jose.exceptions import JWTError

from app.auth.constants import ErrorEnum
from app.core.config import config
from app.core.deps import SessionDep
from app.core.errors import UnauthorizedError
from app.user.models import User


async def current_user(
    session: SessionDep,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None, Depends(HTTPBearer(auto_error=False))
    ] = None,
) -> User:
    """
    Returns the current authenticated user.

    Args:
        session: The dependency for the database session.
        credentials: The credentials for the current user.

    Raises:
        UnauthorizedError: If the credentials are invalid or the user is not found.

    Returns:
        User: The current authenticated user.
    """
    if credentials is None:
        return User.anonymous()

    token = credentials.credentials
    try:
        res = jwt.decode(token, config.jwt_secret_key, algorithms=[config.jwt_algorithm])
        user_id = res["user_id"]
    except (KeyError, JWTError):
        raise UnauthorizedError(ErrorEnum.INVALID_CREDENTIALS)

    user = await session.get(User, user_id)

    if user is None:
        raise UnauthorizedError(ErrorEnum.USER_NOT_FOUND)
    return user


CurrentUserDep = Annotated[User, Depends(current_user)]
