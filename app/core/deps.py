from asyncio import current_task
from functools import cache
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_scoped_session,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import config
from app.core.email import DebugEmailBackend, EmailBackendBase


def email_backend():
    return DebugEmailBackend()


@cache
def engine():
    return create_async_engine(
        str(config.db_url),
        echo=False,
        pool_size=config.db_pool_size,
        max_overflow=config.db_pool_max_overflow,
    )


async def session(
    request: Request, engine: Annotated[AsyncEngine, Depends(engine)]
) -> AsyncSession:
    session_maker = async_scoped_session(
        async_sessionmaker(
            autoflush=False,
            expire_on_commit=False,
            class_=AsyncSession,
            bind=engine,
        ),
        scopefunc=current_task,
    )
    session = session_maker()
    request.state.session = session
    return session


SessionDep = Annotated[AsyncSession, Depends(session)]
EmailBackendDep = Annotated[EmailBackendBase, Depends(email_backend)]
