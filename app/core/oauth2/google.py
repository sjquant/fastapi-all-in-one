from httpx import AsyncClient
from pydantic import BaseModel

from app.core.oauth2.base import OAuth2Base, OAuth2Token


class GoogleUser(BaseModel):
    id: str
    subject: str
    issuer: str
    name: str
    picture: str
    email: str
    verified_email: bool
    email_verified: bool
    hosted_domain: str


class GoogleOAuth2(OAuth2Base):
    """
    See https://developers.google.com/identity/protocols/oauth2/web-server#httprest_1
    """

    @property
    def access_token_url(self) -> str:
        return "https://accounts.google.com/o/oauth2/token"

    async def get_user_data(self, token: OAuth2Token) -> GoogleUser:
        client = AsyncClient()
        res = await client.get(
            "https://www.googleapis.com/oauth2/v3/tokeninfo",
            headers={
                "Authorization": f"Bearer {token.access_token}",
            },
        )
        data = res.json()
        return GoogleUser(
            id=data["sub"],
            subject=data["sub"],
            issuer=data["iss"],
            name=data["name"],
            picture=data["picture"],
            email=data["email"],
            verified_email=data["verified_email"],
            email_verified=bool(data["verified_email"] or data["email_verified"]),
            hosted_domain=data["hd"],
        )
