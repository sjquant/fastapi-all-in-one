from fastapi import FastAPI

from app.auth.endpoints import router as auth_router

app = FastAPI()

app.include_router(auth_router, prefix="/auth", tags=["auth"])


@app.get("/ping")
async def pong():
    return {"ping": "pong"}
