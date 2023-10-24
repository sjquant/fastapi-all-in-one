from functools import cache
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import config
from app.core.db import DB


@cache
def db():
    return DB(str(config.db_url))


async def session(request: Request, db: Annotated[DB, Depends(db)]):
    async with db.session() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(session)]
