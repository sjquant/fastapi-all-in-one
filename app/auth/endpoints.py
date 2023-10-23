import datetime
import secrets
from uuid import UUID

import sqlalchemy as sa
from fastapi import APIRouter, Response
from jose import jwt

from app.auth.constants import ErrorEnum
from app.auth.dto import AuthenticatedUser, SignInResponse, SignInSchema
from app.auth.models import RefreshToken
from app.core.config import config
from app.core.deps import SessionDep
from app.core.errors import NotFoundError, ValidationError
from app.user.models import User

router = APIRouter()


@router.post("/sign-in/email")
async def sign_in(response: Response, session: SessionDep, data: SignInSchema):
    res = await session.execute(sa.select(User).where(User.email == data.email))
    user = res.scalar_one_or_none()

    if user is None:
        raise NotFoundError(ErrorEnum.USER_NOT_FOUND)

    if not user.verify_password(data.password):
        raise ValidationError(ErrorEnum.PASSWORD_DOES_NOT_MATCH)

    user.last_logged_in = datetime.datetime.now(tz=datetime.UTC)
    refresh_token_model = RefreshToken(
        user_id=user.id,
        expires_at=datetime.datetime.now() + datetime.timedelta(days=7),
        token=secrets.token_urlsafe(32),
    )
    access_token = create_access_token(user.id)
    session.add(refresh_token_model)

    await session.commit()

    response.set_cookie(
        key="refresh_token",
        value=refresh_token_model.token,
        httponly=True,
        secure=config.env == "prod",
        samesite="lax",
    )

    return SignInResponse(access_token=access_token, user=AuthenticatedUser.model_validate(user))


def create_access_token(user_id: UUID):
    nbf = datetime.datetime.utcnow().timestamp()
    payload = {
        "iss": config.jwt_issuer,
        "sub": str(user_id),
        "nbf": nbf,
        "exp": nbf + config.jwt_expires_seconds,
    }

    return jwt.encode(payload, config.jwt_secret_key, algorithm=config.jwt_algorithm)
