from functools import cache
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import config
from app.core.db import DB
from app.core.email import DebugEmailBackend, EmailBackendBase


@cache
def db():
    return DB(str(config.db_url))


def email_backend():
    return DebugEmailBackend()


async def session(request: Request, db: Annotated[DB, Depends(db)]):
    async with db.session() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(session)]
EmailBackendDep = Annotated[EmailBackendBase, Depends(email_backend)]
