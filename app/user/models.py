import datetime
import re

import bcrypt
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.config import config
from app.core.db import Model


class User(Model):
    __tablename__ = "user__users"

    username: Mapped[str] = mapped_column(sa.String(12), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(sa.String, unique=True, index=True, nullable=False)
    photo: Mapped[str] = mapped_column(sa.String, nullable=False, default="")
    hashed_password: Mapped[str] = mapped_column(sa.String, nullable=True)
    last_logged_in: Mapped[datetime.datetime] = mapped_column(
        sa.TIMESTAMP(timezone=True), nullable=True
    )

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")

    def set_password(self, password: str):
        assert len(password) >= config.password_min_length
        # 영문, 숫자, 특수문자가 각각 1개 이상 포함되어야 합니다
        assert re.match(r"^(?=.*[a-zA-Z])(?=.*[^a-zA-Z0-9])(?=.*[0-9]).+$", password)

        self.hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )

    def set_unusable_password(self):
        self.hashed_password = None

    def verify_password(self, password: str):
        return bcrypt.checkpw(password.encode("utf-8"), self.hashed_password.encode("utf-8"))

    @validates("email")
    def validate_email(self, key: str, email: str):
        assert re.match(r"[^@]+@[^@]+\.[^@]+", email)
        return email
