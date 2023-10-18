from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dto import AuthenticatedUser, SignInResponse
from app.user.models import User


async def test_signin_by_email(client: AsyncClient, session: AsyncSession) -> None:
    # given
    user = User(
        email="testuser@test.com",
        nickname="testuser",
    )
    user.set_password("password123!")
    session.add(user)
    await session.commit()

    # when
    response = await client.post(
        "/auth/sign-in/email",
        json={
            "email": "testuser@test.com",
            "password": "password123!",
        },
    )
    await session.refresh(user)

    # then
    assert response.status_code == 200
    data = response.json()
    assert SignInResponse(**data) == SignInResponse(
        access_token=data["access_token"], user=AuthenticatedUser.model_validate(user)
    )
