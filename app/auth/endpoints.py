import datetime
from typing import Annotated
from uuid import UUID

import jwt
from fastapi import APIRouter, Body, Cookie, Request, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import EmailStr

from app.auth.constants import ErrorEnum, OAuth2FlowEvent
from app.auth.deps import OAuth2ProviderDep, OAuth2UserDataDep
from app.auth.dto import (
    AccessTokenResponse,
    AuthenticatedUser,
    SendSignupEmailResponse,
    SignInEmailSchema,
    SignInResponse,
    SignUpEmailSchema,
)
from app.auth.service import AuthService
from app.core.config import config
from app.core.deps import EmailBackendDep, SessionDep
from app.core.errors import ValidationError

router = APIRouter(tags=["auth"])
templates = Jinja2Templates(directory="app/auth/templates")


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
        email=data.email, code=data.code, nickname=data.nickname, state=data.state
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


@router.post("/get-signup-status")
async def get_signup_status(
    session: SessionDep,
    email: Annotated[EmailStr, Body(..., embed=True)],
):
    auth_service = AuthService(session)
    res = await auth_service.get_signup_status(email)

    return res


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


@router.post("/send-signup-email")
async def send_signup_email(
    session: SessionDep,
    email_backend: EmailBackendDep,
    email: Annotated[EmailStr, Body(..., embed=True)],
):
    auth_service = AuthService(session)
    state = await auth_service.send_signup_email(email_backend, email)
    return SendSignupEmailResponse(state=state)


def generate_access_token(user_id: UUID):
    nbf = datetime.datetime.utcnow().timestamp()
    payload = {
        "iss": config.jwt_issuer,
        "sub": str(user_id),
        "nbf": nbf,
        "exp": nbf + config.jwt_expires_seconds,
    }

    return jwt.encode(payload, config.jwt_secret_key, algorithm=config.jwt_algorithm)


@router.post("/oauth2/{provider}/get-authorization-url")
async def get_oauth2_authorization_url(
    oauth_provider: OAuth2ProviderDep,
):
    return {"url": oauth_provider.get_authorization_url()}


@router.get("/oauth2/{provider}/callback", response_class=HTMLResponse)
async def oauth2_callback(
    request: Request,
    provider: str,
    oauth_provider: OAuth2ProviderDep,
    session: SessionDep,
    user_data: OAuth2UserDataDep,
):
    """
    - Log in if the user is already registered
    - Sign up if the user is not registered
    """
    auth_service = AuthService(session)
    token = await oauth_provider.exchange_token(request.query_params["code"])
    user, refresh_token, is_new_user = await auth_service.handle_oauth2_flow(
        provider, token, user_data
    )
    access_token = generate_access_token(user.id)
    response = templates.TemplateResponse(  # type: ignore
        "oauth2-signin.html",
        context={
            "request": request,
            "event": OAuth2FlowEvent.SUCCESS,
            "access_token": access_token,
            "user_id": user.id,
            "is_new_user": is_new_user,
        },
    )
    response.set_cookie(
        key="refresh_token",
        value=refresh_token.token,
        httponly=True,
        secure=config.env == "prod",
        samesite="lax",
    )

    return response
