import json
import time

import jwt
from httpx import AsyncClient
from jwt.algorithms import RSAAlgorithm
from pydantic import BaseModel

from app.core.oauth2.base import OAuth2Base, OAuth2Token


class AppleUser(BaseModel):
    first_name: str
    last_name: str
    email: str


class AppleOAuth2(OAuth2Base[AppleUser]):
    """
    See https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
    """

    def __init__(
        self,
        *,
        client_id: str,
        team_id: str,
        key_id: str,
        private_key: str,
        redirect_uri: str,
    ):
        self._client_id = client_id
        self._team_id = team_id
        self._key_id = key_id
        self._private_key = private_key
        self._redirect_uri = redirect_uri
        self._client_secret = self._get_client_secret()
        super().__init__(
            access_token_endpoint="https://appleid.apple.com/auth/token",
            authorize_endpoint="https://appleid.apple.com/auth/authorize",
            client_id=client_id,
            client_secret=self._client_secret,
            redirect_uri=redirect_uri,
        )

    def _get_client_secret(self) -> str:
        now = int(time.time())
        payload = {
            "iss": self._team_id,
            "iat": now,
            "exp": now + 1800,
            "aud": "https://appleid.apple.com",
            "sub": self._client_id,
        }
        headers = {
            "kid": self._key_id,
        }

        return jwt.encode(payload, self._private_key, algorithm="ES256", headers=headers)

    async def get_user_data(self, token: OAuth2Token):
        kid: str = jwt.get_unverified_header(token.access_token)["kid"]
        public_key = await self._get_public_key(kid)
        data = jwt.decode(
            token.access_token,
            key=public_key,  # type: ignore
            audience=self._client_id,
            algorithms=["RS256"],
        )
        return AppleUser(
            first_name=data["name"].get("firstName", ""),
            last_name=data["name"].get("lastName", ""),
            email=data["email"],
        )

    async def _get_public_key(self, kid: str):
        client = AsyncClient()
        res = await client.get(
            "https://appleid.apple.com/auth/keys",
        )
        keys = res.json()["keys"]

        return RSAAlgorithm.from_jwk(
            json.dumps(
                [key for key in keys if key["kid"] == kid][0],
            )
        )
