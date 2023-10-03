from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Config(BaseSettings):
    env: str
    db_url: PostgresDsn
    db_pool_size: int
    db_pool_max_overflow: int

    model_config = SettingsConfigDict(env_file=".env")


config = Config()  # pyright: ignore
