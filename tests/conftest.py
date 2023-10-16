import asyncio
from collections.abc import AsyncGenerator, Iterator
from collections.abc import AsyncIterator

import pytest
import sqlalchemy as sa
from httpx import AsyncClient
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy_utils import create_database, drop_database  # type: ignore

from app.core.config import config
from app.core.db import DB, Base
from app.main import app


@pytest.fixture(scope="session")
def event_loop() -> Iterator[asyncio.AbstractEventLoop]:
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
def create_test_database():
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
async def session() -> AsyncGenerator[AsyncSession, None]:
    db = DB(str(config.db_url))
    async with db.session() as session:
        yield session


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    async with AsyncClient(
        app=app,
        base_url="http://test",
        headers={"Content-Type": "application/json"},
    ) as client:
        yield client
