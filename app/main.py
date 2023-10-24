from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.auth.endpoints import router as auth_router
from app.core.errors import HttpError

app = FastAPI()

app.include_router(auth_router, prefix="/auth", tags=["auth"])


@app.get("/ping")
async def pong():
    return {"ping": "pong"}


@app.exception_handler(HttpError)
def handle_http_error(request: Request, exc: HttpError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": exc.error_code, "message": exc.message},
    )
