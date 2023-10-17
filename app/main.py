from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.endpoints import router as auth_router

app = FastAPI()

app.include_router(auth_router, prefix="/auth", tags=["auth"])


@app.middleware("http")
async def db_session_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """
    Middleware that manages database sessions for each request.
    """
    response = Response("Internal server error", status_code=500)
    try:
        response = await call_next(request)
        if hasattr(request.state, "session"):
            session: AsyncSession = request.state.session
            if session.is_active:
                await session.commit()
    finally:
        if hasattr(request.state, "session"):
            session: AsyncSession = request.state.session
            await session.close()
    return response


@app.get("/ping")
async def pong():
    return {"ping": "pong"}
