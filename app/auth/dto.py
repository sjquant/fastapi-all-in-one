from pydantic import BaseModel


class SignUpSchema(BaseModel):
    email: str
    password: str
    nickname: str


class SignInSchema(BaseModel):
    email: str
    password: str
