import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SignUpSchema(BaseModel):
    email: str
    password: str
    nickname: str


class SignInSchema(BaseModel):
    email: str = Field(description="User email", examples=["example@example.com"])
    password: str = Field(description="User password", examples=["password"])


class AuthenticatedUser(BaseModel):
    id: UUID = Field(description="User ID", examples=["xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"])
    email: str = Field(description="User email", examples=["example@example.com"])
    nickname: str = Field(description="User nickname", examples=["example"])
    last_logged_in: datetime.datetime = Field(
        description="Last logged in", examples=["2021-01-01T00:00:00+00:00"]
    )

    model_config = ConfigDict(from_attributes=True)


class SignInResponse(BaseModel):
    access_token: str = Field(
        description="Access token", examples=["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
    )
    user: AuthenticatedUser
