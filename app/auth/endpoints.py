import datetime

import sqlalchemy as sa
from fastapi import APIRouter

from app.auth.dto import AuthenticatedUser, SignInSchema
from app.core.deps import SessionDep
from app.user.models import User

router = APIRouter()


@router.post("/sign-in/email")
async def sign_in(session: SessionDep, data: SignInSchema) -> AuthenticatedUser:
    res = await session.execute(sa.select(User).where(User.email == data.email))
    user = res.scalar_one_or_none()

    if user is None:
        raise Exception("User not found")

    if not user.verify_password(data.password):
        raise Exception("Password not match")

    user.last_logged_in = datetime.datetime.now(tz=datetime.UTC)

    return AuthenticatedUser.model_validate(user)
