import datetime
import re
from uuid import UUID

import bcrypt
import sqlalchemy as sa
from jose import jwt
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.config import config
from app.core.db import Model, TimestampMixin


class User(Model, TimestampMixin):
    __tablename__ = "user__users"

    email: Mapped[str] = mapped_column(sa.String, unique=True, index=True, nullable=False)
    nickname: Mapped[str] = mapped_column(sa.String(12), unique=True, index=True, nullable=False)
    photo: Mapped[str] = mapped_column(sa.String, nullable=False, default="")
    hashed_password: Mapped[str] = mapped_column(sa.String, nullable=True)
    last_logged_in: Mapped[datetime.datetime] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=True
    )

    @staticmethod
    def anonymous():
        return User(
            id=UUID(int=0),
            email="anon@anon.anon",
            nickname=None,
            photo=None,
            hashed_password=None,
        )

    @property
    def is_anonymous(self):
        return self.id.int == 0

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")

    def set_password(self, password: str):
        assert len(password) >= config.password_min_length
        # It must contain at least one letter, one number, and one special character
        assert re.match(r"^(?=.*[a-zA-Z])(?=.*[^a-zA-Z0-9])(?=.*[0-9]).+$", password)

        self.hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )

    def create_access_token(self):
        nbf = datetime.datetime.utcnow().timestamp()
        payload = {
            "iss": config.jwt_issuer,
            "sub": str(self.id),
            "nbf": nbf,
            "exp": nbf + config.jwt_expires_seconds,
        }

        return jwt.encode(payload, config.jwt_secret_key, algorithm=config.jwt_algorithm)

    def set_unusable_password(self):
        self.hashed_password = None

    def verify_password(self, password: str):
        return bcrypt.checkpw(password.encode("utf-8"), self.hashed_password.encode("utf-8"))

    @validates("email")
    def validate_email(self, key: str, email: str):
        assert re.match(r"[^@]+@[^@]+\.[^@]+", email)
        return email
