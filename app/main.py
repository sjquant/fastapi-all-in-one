from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

app = FastAPI()


@app.middleware("http")
async def db_session_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """
    Middleware that manages database sessions for each request.
    """
    try:
        response = await call_next(request)
        if hasattr(request.state, "session"):
            session: AsyncSession = request.state.session
            if session.is_active:
                await session.commit()
    except Exception:
        if hasattr(request.state, "session"):
            session: AsyncSession = request.state.session
            await session.rollback()
        return Response("Internal server error", status_code=500)
    return response


@app.get("/ping")
async def pong():
    return {"ping": "pong"}
