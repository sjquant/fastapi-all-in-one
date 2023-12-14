import time
from abc import ABC, abstractmethod, abstractproperty
from typing import Any, cast

from httpx import AsyncClient
from pydantic import BaseModel, model_validator


class OAuth2Token(BaseModel):
    access_token: str
    token_type: str
    expires_at: int | None = None
    refresh_token: str | None = None
    scope: str | None = None
    id_token: str | None = None

    @model_validator(mode="before")
    @classmethod
    def set_expires_at(cls, data: Any) -> Any:
        if isinstance(data, dict) and "expires_in" in data:
            data["expires_at"] = int(time.time()) + int(data.pop("expires_in"))  # type: ignore

        return cast(Any, data)


class OAuth2Base(ABC):
    def __init__(self, *, client_id: str, client_secret: str, redirect_uri: str):
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri

    async def exchange_token(self, code: str) -> OAuth2Token:
        """
        Exchanges the authorization code for an access token.

        Args:
            code: The authorization code received from the authorization server.
        """
        client = AsyncClient()
        res = await client.post(
            self.access_token_url,
            json={
                "grant_type": "authorization_code",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "redirect_uri": self._redirect_uri,
                "code": code,
            },
        )
        return OAuth2Token(**res.json())

    @abstractmethod
    async def get_user_data(self, token: str) -> Any:
        """
        Retrieve user data using the provided OAuth2 token.

        Args:
            token: The OAuth2 token.

        Returns:
            The user data
        """
        ...

    @abstractproperty
    def access_token_url(self) -> str: ...
