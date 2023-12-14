from httpx import AsyncClient
from pydantic import BaseModel

from app.core.oauth2.base import OAuth2Base


class KakaoUser(BaseModel):
    id: int
    name: str
    pricture: str
    email: str
    email_valid: bool
    email_verified: bool


class KakaoOAuth2(OAuth2Base):
    """
    See https://developers.kakao.com/docs/latest/ko/kakaologin/rest-api#request-token
    """

    @property
    def access_token_url(self) -> str:
        return "https://kauth.kakao.com/oauth/token"

    async def get_user_data(self, token: str) -> KakaoUser:
        client = AsyncClient()
        res = await client.get(
            "https://kapi.kakao.com/v2/user/me",
            headers={
                "Authorization": f"Bearer {token}",
            },
        )
        data = res.json()
        return KakaoUser(
            id=data["id"],
            name=data["kakao_account"]["profile"]["nickname"],
            pricture=data["kakao_account"]["profile"]["profile_image_url"],
            email=data["kakao_account"]["email"],
            email_valid=data["kakao_account"]["is_email_valid"],
            email_verified=data["kakao_account"]["is_email_verified"],
        )
