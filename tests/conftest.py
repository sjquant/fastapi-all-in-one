import asyncio
from asyncio import current_task
from collections.abc import AsyncGenerator, AsyncIterator, Iterator

import pytest
import sqlalchemy as sa
from httpx import AsyncClient
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_scoped_session,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy_utils import create_database, drop_database  # type: ignore

from app.core.config import config
from app.core.db import Base
from app.core.deps import session as session_dep
from app.main import app


@pytest.fixture(scope="session")
def event_loop() -> Iterator[asyncio.AbstractEventLoop]:
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
def database():
    engine = sa.create_engine(str(config.db_url).replace("+asyncpg", ""))
    try:
        create_database(engine.url)
    except ProgrammingError:
        pass
    Base.metadata.create_all(engine)
    yield
    drop_database(engine.url)
    engine.dispose()


@pytest.fixture(autouse=True, scope="session")
async def engine() -> AsyncGenerator[AsyncEngine, None]:
    engine = create_async_engine(str(config.db_url))
    yield engine
    await engine.dispose()


@pytest.fixture
async def session(engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    # See https://docs.sqlalchemy.org/en/14/orm/session_transaction.html#joining-a-session-into-an-external-transaction-such-as-for-test-suites
    # for more information about this fixture

    conn = await engine.connect()
    trans = await conn.begin_nested()
    session = async_scoped_session(
        async_sessionmaker(
            autoflush=False,
            expire_on_commit=False,
            class_=AsyncSession,
            bind=conn,
        ),
        scopefunc=current_task,
    )()

    app.dependency_overrides[session_dep] = lambda: session

    yield session

    await trans.rollback()
    await conn.close()


@pytest.fixture
async def client(session: AsyncSession) -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        app=app,
        base_url="http://test",
        headers={"Content-Type": "application/json"},
    ) as client:
        yield client
