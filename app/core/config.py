from typing import Literal

from pydantic import EmailStr, PostgresDsn
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
    email_verificaton_token_expires_seconds: int = 30 * MINUTE
    email_verification_code_length: int = 8
    email_sender: EmailStr
    oauth_state_expires_seconds: int = 10 * MINUTE

    google_client_id: str = ""
    google_client_secret: str = ""
    google_redirect_uri: str = ""
    kakao_client_id: str = ""
    kakao_client_secret: str = ""
    kakao_redirect_uri: str = ""
    apple_client_id: str = ""
    apple_team_id: str = ""
    apple_key_id: str = ""
    apple_private_key: str = ""
    apple_redirect_uri: str = ""

    model_config = SettingsConfigDict(env_file=".env")


config = Config()  # pyright: ignore
