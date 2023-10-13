import asyncio
from collections.abc import AsyncGenerator, Iterator

import pytest
import sqlalchemy as sa
from psycopg2 import ProgrammingError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy_utils import create_database, drop_database  # type: ignore

from app.core.config import config
from app.core.db import DB, Base


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
        Base.metadata.drop_all(engine)
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
