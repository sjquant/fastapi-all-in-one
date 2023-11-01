import datetime
from uuid import UUID

from fastapi import APIRouter, Response
from jose import jwt

from app.auth.deps import AuthServiceDep
from app.auth.dto import AuthenticatedUser, SignInEmailSchema, SignInResponse, SignUpEmailSchema
from app.core.config import config

router = APIRouter()


@router.post("/sign-in/email")
async def sign_in_by_email(
    response: Response, auth_service: AuthServiceDep, data: SignInEmailSchema
):
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
async def sign_up_by_email(
    response: Response, auth_service: AuthServiceDep, data: SignUpEmailSchema
):
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


def generate_access_token(user_id: UUID):
    nbf = datetime.datetime.utcnow().timestamp()
    payload = {
        "iss": config.jwt_issuer,
        "sub": str(user_id),
        "nbf": nbf,
        "exp": nbf + config.jwt_expires_seconds,
    }

    return jwt.encode(payload, config.jwt_secret_key, algorithm=config.jwt_algorithm)
