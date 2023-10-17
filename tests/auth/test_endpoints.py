from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dto import AuthenticatedUser
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

    # then
    await session.refresh(user)
    assert response.status_code == 200
    assert AuthenticatedUser(**response.json()) == AuthenticatedUser.model_validate(user)
