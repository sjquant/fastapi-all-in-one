from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.constants import MINUTE


class Config(BaseSettings):
    env: str
    db_url: PostgresDsn
    db_pool_size: int
    db_pool_max_overflow: int
    password_min_length: int = 8
    model_config = SettingsConfigDict(env_file=".env")

    jwt_secret_key: str
    jwt_issuer: str
    jwt_algorithm: str = "HS256"
    jwt_expires_seconds: int = 30 * MINUTE


config = Config()  # pyright: ignore
