import datetime
import re
from uuid import UUID

import bcrypt
import sqlalchemy as sa
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.core.config import config
from app.core.db import Model, TimestampMixin
from app.core.errors import ValidationError
from app.core.utils import is_valid_email
from app.user.constants import ErrorEnum


class User(Model, TimestampMixin):
    __tablename__ = "user__users"

    email: Mapped[str] = mapped_column(sa.String, unique=True, index=True, nullable=False)
    nickname: Mapped[str] = mapped_column(sa.String(12), unique=True, index=True, nullable=False)
    photo: Mapped[str] = mapped_column(sa.String, nullable=False, default="")
    hashed_password: Mapped[str | None] = mapped_column(sa.String, nullable=True)
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
    def is_authenticated(self):
        return not self.is_anonymous

    @property
    def password(self):
        raise AttributeError("Password is not a readable attribute")

    def set_password(self, password: str):
        if len(password) < config.password_min_length:
            raise ValidationError(
                ErrorEnum.PASSWORD_TOO_SHORT.dynamic_message(length=config.password_min_length)
            )
        if not re.match(r"^(?=.*[a-zA-Z])(?=.*[^a-zA-Z0-9])(?=.*[0-9]).+$", password):
            raise ValidationError(ErrorEnum.PASSWORD_TOO_SIMPLE)

        self.hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode(
            "utf-8"
        )

    def verify_password(self, password: str):
        if self.hashed_password is None:
            return False
        return bcrypt.checkpw(password.encode("utf-8"), self.hashed_password.encode("utf-8"))

    @validates("email")
    def validate_email(self, key: str, email: str):
        if not is_valid_email(email):
            raise ValidationError(ErrorEnum.INVALID_EMAIL)
        return email
