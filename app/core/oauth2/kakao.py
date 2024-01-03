from httpx import AsyncClient
from pydantic import BaseModel

from app.core.oauth2.base import OAuth2Base, OAuth2Token


class KakaoUser(BaseModel):
    id: int
    name: str
    picture: str
    email: str
    email_valid: bool
    email_verified: bool


class KakaoOAuth2(OAuth2Base[KakaoUser]):
    """
    See https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api#request-token
    """

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
    ):
        super().__init__(
            access_token_endpoint="https://kauth.kakao.com/oauth/token",
            authorize_endpoint="https://kauth.kakao.com/oauth/authorize",
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
        )

    async def get_user_data(self, token: OAuth2Token) -> KakaoUser:
        client = AsyncClient()
        res = await client.get(
            "https://kapi.kakao.com/v2/user/me",
            headers={
                "Authorization": f"Bearer {token.access_token}",
            },
        )
        data = res.json()
        return KakaoUser(
            id=data["id"],
            name=data["kakao_account"]["profile"]["nickname"],
            picture=data["kakao_account"]["profile"]["profile_image_url"],
            email=data["kakao_account"]["email"],
            email_valid=data["kakao_account"]["is_email_valid"],
            email_verified=data["kakao_account"]["is_email_verified"],
        )
