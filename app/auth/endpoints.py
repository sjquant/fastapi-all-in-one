import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Cookie, Response
from jose import jwt

from app.auth.constants import ErrorEnum
from app.auth.deps import CurrentUserDep
from app.auth.dto import (
    AccessTokenResponse,
    AuthenticatedUser,
    SignInEmailSchema,
    SignInResponse,
    SignUpEmailSchema,
)
from app.auth.service import AuthService
from app.core.config import config
from app.core.deps import SessionDep
from app.core.errors import UnauthorizedError

router = APIRouter()


@router.post("/sign-in/email")
async def sign_in_by_email(response: Response, session: SessionDep, data: SignInEmailSchema):
    auth_service = AuthService(session)
    user, refresh_token = await auth_service.sign_in_by_email(data.email, data.password)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token.token,
        httponly=True,
        secure=config.env == "prod",
        samesite="lax",
    )
    access_token = generate_access_token(user.id)

    return SignInResponse(access_token=access_token, user=AuthenticatedUser.model_validate(user))


@router.post("/sign-up/email")
async def sign_up_by_email(response: Response, session: SessionDep, data: SignUpEmailSchema):
    auth_service = AuthService(session)
    user, refresh_token = await auth_service.sign_up_by_email(
        data.email, data.password, data.nickname
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token.token,
        httponly=True,
        secure=config.env == "prod",
        samesite="lax",
    )
    access_token = generate_access_token(user.id)

    return SignInResponse(access_token=access_token, user=AuthenticatedUser.model_validate(user))


@router.post("/refresh-token")
async def refresh_token(
    response: Response,
    session: SessionDep,
    user: CurrentUserDep,
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    auth_service = AuthService(session)

    if refresh_token is None:
        raise UnauthorizedError(ErrorEnum.NO_REFRESH_TOKEN)

    new_refresh_token = await auth_service.renew_refresh_token_if_needed(user.id, refresh_token)

    if new_refresh_token:
        response.set_cookie(
            key="refresh_token",
            value=new_refresh_token.token,
            httponly=True,
            secure=config.env == "prod",
            samesite="lax",
        )

    access_token = generate_access_token(user.id)

    return AccessTokenResponse(access_token=access_token)


def generate_access_token(user_id: UUID):
    nbf = datetime.datetime.utcnow().timestamp()
    payload = {
        "iss": config.jwt_issuer,
        "sub": str(user_id),
        "nbf": nbf,
        "exp": nbf + config.jwt_expires_seconds,
    }

    return jwt.encode(payload, config.jwt_secret_key, algorithm=config.jwt_algorithm)
