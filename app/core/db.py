from __future__ import annotations

from asyncio import current_task
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_scoped_session,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import config


class DB:
    def __init__(self, db_url: str) -> None:
        self._engine = create_async_engine(
            db_url,
            echo=False,
            pool_size=config.db_pool_size,
            max_overflow=config.db_pool_max_overflow,
        )
        self._session_factory = async_scoped_session(
            async_sessionmaker(
                autoflush=False,
                class_=AsyncSession,
                bind=self._engine,
            ),
            scopefunc=current_task,
        )

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        session: AsyncSession = self._session_factory()
        try:
            yield session
            # flush()는 DB로직 실패 시 rollback()을 실행하지 않아
            # session.is_active로 상태를 확인 후 명시적으로 사용해줘야 합니다.
            if session.is_active:
                await session.commit()
            else:
                await session.rollback()
        except Exception:
            await session.rollback()
            raise
        finally:
            await self._session_factory.remove()
