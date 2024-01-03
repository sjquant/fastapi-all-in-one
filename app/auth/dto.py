import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class SignUpEmailSchema(BaseModel):
    email: str = Field(description="User email", examples=["example@example.com"])
    code: str = Field(description="Verification code", examples=["ABCD1234"])
    state: str = Field(
        description="State to prevent csrf and replay attacks", examples=["xxxxxxxxxxxx"]
    )
    nickname: str = Field(description="User nickname", examples=["example"])


class SignInEmailSchema(BaseModel):
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


class OAuth2UserData(BaseModel):
    uid: str = Field(description="Unique User ID", examples=["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"])
    email: str = Field(description="User email", examples=["examle@example.com"])
    photo: str | None = Field(
        description="User photo", examples=["https://example.com/photo.jpg"], default=None
    )


class VerifyEmailSchema(BaseModel):
    email: str = Field(description="User email", examples=["example@example.com"])
    code: str = Field(description="Verification code", examples=["ABCD1234"])


class SignInResponse(BaseModel):
    access_token: str = Field(
        description="Access token", examples=["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
    )
    user: AuthenticatedUser


class AccessTokenResponse(BaseModel):
    access_token: str = Field(
        description="Access token", examples=["xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"]
    )


class SignupStatus(BaseModel):
    has_account: bool = Field(
        description="Whether a specified email is signed up or not", examples=[True]
    )
    has_password: bool = Field(
        description="Whether a specified email has password or not", examples=[True]
    )


class SendSignupEmailResponse(BaseModel):
    state: str = Field(
        description="State to prevent csrf and replay attacks", examples=["xxxxxxxxxxxx"]
    )
