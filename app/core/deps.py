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
        # request.state에 session을 저장해, middleware에서 commit할 수 있도록 합니다.
        request.state.session = session
        yield session
        await session.close()


SessionDep = Annotated[AsyncSession, Depends(session)]
