import datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Cookie, Depends, Response
from jose import jwt

from app.auth.constants import ErrorEnum, VerificationUsage
from app.auth.deps import require_auth
from app.auth.dto import (
    AccessTokenResponse,
    AuthenticatedUser,
    SignInEmailSchema,
    SignInResponse,
    SignUpEmailSchema,
    VerifyEmailSchema,
)
from app.auth.service import AuthService
from app.core.config import config
from app.core.deps import SessionDep
from app.core.errors import ValidationError

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
    refresh_token: Annotated[str | None, Cookie()] = None,
):
    auth_service = AuthService(session)

    if refresh_token is None:
        raise ValidationError(ErrorEnum.NO_REFRESH_TOKEN)

    refresh_token_model, is_renewed = await auth_service.renew_refresh_token_if_needed(
        refresh_token
    )

    if is_renewed:
        response.set_cookie(
            key="refresh_token",
            value=refresh_token_model.token,
            httponly=True,
            secure=config.env == "prod",
            samesite="lax",
        )

    access_token = generate_access_token(refresh_token_model.user_id)

    return AccessTokenResponse(access_token=access_token)


@router.post("/verify-email", dependencies=[Depends(require_auth())])
async def verify_email(session: SessionDep, data: VerifyEmailSchema):
    auth_service = AuthService(session=session)

    await auth_service.verify_email(
        email=data.email,
        code=data.code,
        usage=VerificationUsage.SIGN_UP,
    )


def generate_access_token(user_id: UUID):
    nbf = datetime.datetime.utcnow().timestamp()
    payload = {
        "iss": config.jwt_issuer,
        "sub": str(user_id),
        "nbf": nbf,
        "exp": nbf + config.jwt_expires_seconds,
    }

    return jwt.encode(payload, config.jwt_secret_key, algorithm=config.jwt_algorithm)
