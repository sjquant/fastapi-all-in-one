import secrets
import time
from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar, cast
from urllib.parse import urlencode

from httpx import AsyncClient
from pydantic import BaseModel, model_validator

T = TypeVar("T")


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


class OAuth2Base(ABC, Generic[T]):
    def __init__(
        self,
        *,
        authorize_endpoint: str,
        access_token_endpoint: str,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str] | None = None,
    ):
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._authorize_endpoint = authorize_endpoint
        self._access_token_endpoint = access_token_endpoint
        self._scopes = scopes

    def get_authorization_url(
        self, state: str | None = None, extra_params: dict[str, str] = {}
    ) -> str:
        """
        Returns the authorization url.

        Args:
            state: The state parameter.

        Returns:
            The authorization url.
        """
        state = state or secrets.token_urlsafe(32)
        params = {
            "response_type": "code",
            "client_id": self._client_id,
            "redirect_uri": self._redirect_uri,
            "state": state,
            **extra_params,
        }
        if self._scopes:
            params["scope"] = " ".join(self._scopes)

        return f"{self._authorize_endpoint}?{urlencode(params)}"

    async def exchange_token(self, code: str) -> OAuth2Token:
        """
        Exchanges the authorization code for an access token.

        Args:
            code: The authorization code received from the authorization server.
        """
        client = AsyncClient()
        res = await client.post(
            self._access_token_endpoint,
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
    async def get_user_data(self, token: OAuth2Token) -> T:
        """
        Retrieve user data using the provided OAuth2 token.

        Args:
            token: The OAuth2 token.

        Returns:
            The user data
        """
        ...
