import datetime

import sqlalchemy as sa
from fastapi import APIRouter

from app.auth.constants import ErrorEnum
from app.auth.dto import AuthenticatedUser, SignInSchema
from app.core.deps import SessionDep
from app.core.errors import NotFoundError
from app.user.models import User

router = APIRouter()


@router.post("/sign-in/email", response_model=AuthenticatedUser)
async def sign_in(session: SessionDep, data: SignInSchema):
    res = await session.execute(sa.select(User).where(User.email == data.email))
    user = res.scalar_one_or_none()

    if user is None:
        raise NotFoundError(ErrorEnum.USER_NOT_FOUND)

    if not user.verify_password(data.password):
        raise Exception("Password not match")

    user.last_logged_in = datetime.datetime.now(tz=datetime.UTC)

    await session.flush()

    return user
