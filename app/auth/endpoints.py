from fastapi import APIRouter

from app.auth.dto import SignInSchema, SignUpSchema

router = APIRouter()


@router.post("/sign-up")
async def sign_up(data: SignUpSchema): ...


@router.post("/sign-in")
async def sign_in(data: SignInSchema): ...
