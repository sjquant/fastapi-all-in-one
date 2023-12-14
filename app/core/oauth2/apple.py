import time

from jose import jwt
from pydantic import BaseModel

from app.core.oauth2.base import OAuth2Base


class AppleUser(BaseModel):
    name: str
    email: str


class AppleOAuth2(OAuth2Base):
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
            client_id=client_id,
            client_secret=self._client_secret,
            redirect_uri=redirect_uri,
        )

    @property
    def access_token_url(self) -> str:
        return "https://appleid.apple.com/auth/token"

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
