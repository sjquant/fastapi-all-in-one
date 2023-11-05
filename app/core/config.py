from typing import Literal

from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.constants import DAY, MINUTE


class Config(BaseSettings):
    env: Literal["dev", "test", "staging", "prod"]
    db_url: PostgresDsn
    db_pool_size: int
    db_pool_max_overflow: int
    password_min_length: int = 8
    jwt_secret_key: str
    jwt_issuer: str
    jwt_algorithm: str = "HS256"
    jwt_expires_seconds: int = 30 * MINUTE
    refresh_token_expires_seconds: int = 30 * DAY  # Refresh token expires after this
    refresh_token_stale_seconds: int = 7 * DAY  # Refresh token renewed if older than this

    model_config = SettingsConfigDict(env_file=".env")


config = Config()  # pyright: ignore
