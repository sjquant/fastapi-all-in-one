from collections.abc import Callable
from typing import Annotated

import jwt
from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWTError

from app.auth.constants import ErrorEnum
from app.core.config import config
from app.core.deps import SessionDep
from app.core.errors import PermissionDenied, UnauthorizedError
from app.core.oauth2.apple import AppleOAuth2
from app.core.oauth2.base import OAuth2Base
from app.core.oauth2.google import GoogleOAuth2
from app.core.oauth2.kakao import KakaoOAuth2
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
    except (KeyError, PyJWTError):
        raise UnauthorizedError(ErrorEnum.INVALID_CREDENTIALS)

    user = await session.get(User, user_id)

    if user is None:
        raise UnauthorizedError(ErrorEnum.USER_NOT_FOUND)
    return user


CurrentUserDep = Annotated[User, Depends(current_user)]


def require_auth() -> Callable[[CurrentUserDep], None]:
    def _require_auth(user: CurrentUserDep) -> None:
        if not user.is_authenticated:
            raise PermissionDenied(ErrorEnum.USER_NOT_AUTHENTICATED)

    return _require_auth


def oauth_provider(provider: str) -> OAuth2Base:
    match provider:
        case "google":
            return GoogleOAuth2(
                client_id=config.google_client_id,
                client_secret=config.google_client_secret,
                redirect_uri=config.google_redirect_uri,
            )
        case "apple":
            return AppleOAuth2(
                client_id=config.apple_client_id,
                team_id=config.apple_team_id,
                key_id=config.apple_key_id,
                private_key=config.apple_private_key,
                redirect_uri=config.apple_redirect_uri,
            )
        case "kakao":
            return KakaoOAuth2(
                client_id=config.kakao_client_id,
                client_secret=config.kakao_client_secret,
                redirect_uri=config.kakao_redirect_uri,
            )
        case _:
            raise ValueError("Invalid OAuth provider")


OAuth2ProviderDep = Annotated[OAuth2Base, Depends(oauth_provider)]
