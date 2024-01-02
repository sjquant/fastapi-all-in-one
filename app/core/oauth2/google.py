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


class GoogleOAuth2(OAuth2Base[GoogleUser]):
    """
    See https://developers.google.com/identity/protocols/oauth2/web-server#httprest_1
    """

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scopes: list[str] = [
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/userinfo.email",
        ],
    ):
        super().__init__(
            access_token_endpoint="https://accounts.google.com/o/oauth2/token",
            authorize_endpoint="https://accounts.google.com/o/oauth2/v2/auth",
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            scopes=scopes,
        )

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
