from __future__ import annotations

import datetime
import uuid
from asyncio import current_task
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as pg
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_scoped_session,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import CHAR, TypeDecorator

from app.core.config import config


class DB:
    def __init__(self, db_url: str | sa.URL):
        self._engine = create_async_engine(
            db_url,
            echo=False,
            pool_size=config.db_pool_size,
            max_overflow=config.db_pool_max_overflow,
        )
        self._session_factory = async_scoped_session(
            async_sessionmaker(
                autoflush=False,
                expire_on_commit=False,
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
        finally:
            await session.close()
            await self._session_factory.remove()


UUIDTypeDecorator = TypeDecorator[uuid.UUID]


class GUID(UUIDTypeDecorator):
    """Platform-independent GUID type.
    Uses PostgreSQL's UUID type, otherwise uses
    CHAR(32), storing as stringified hex values.
    """

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect: sa.engine.interfaces.Dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(pg.UUID())
        else:
            return dialect.type_descriptor(CHAR(32))

    def process_bind_param(
        self, value: Any | None, dialect: sa.engine.interfaces.Dialect
    ) -> str | None:
        if value is None:
            return value
        elif dialect.name == "postgresql":
            return str(value)
        else:
            if not isinstance(value, uuid.UUID):
                return "%.32x" % uuid.UUID(value).int
            else:
                # hexstring
                return "%.32x" % value.int

    def process_result_value(
        self, value: Any | None, dialect: sa.engine.interfaces.Dialect
    ) -> None | uuid.UUID:
        if value is None:
            return value
        else:
            return uuid.UUID(str(value))


class Base(DeclarativeBase):
    __abstract__ = True

    type_annotation_map = {
        uuid.UUID: GUID,
    }


class Model(Base):
    __abstract__ = True

    id: Mapped[uuid.UUID] = mapped_column(
        GUID(), primary_key=True, default=uuid.uuid4, unique=True, nullable=False
    )


class TimestampMixin(Base):
    __abstract__ = True

    created_at: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime(timezone=True), default=lambda: datetime.datetime.now(tz=datetime.UTC)
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        sa.DateTime(timezone=True),
        default=lambda: datetime.datetime.now(tz=datetime.UTC),
        onupdate=lambda: datetime.datetime.now(tz=datetime.UTC),
    )
