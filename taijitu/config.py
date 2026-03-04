# taijitu/config.py
# Central configuration — reads from .env file

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):

    # APP
    app_env: str = Field(default="development")
    log_level: str = Field(default="INFO")
    secret_key: str = Field(default="change_in_production")

    # OLLAMA
    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3.2")

    # DATABASE
    postgres_host: str = Field(default="localhost")
    postgres_port: int = Field(default=5432)
    postgres_db: str = Field(default="taijitu")
    postgres_user: str = Field(default="taijitu")
    postgres_password: str = Field(default="taijitu_secure_2026")

    # REDIS
    redis_url: str = Field(default="redis://localhost:6379/0")

    # TELEGRAM
    telegram_alert_token: str = Field(default="")
    telegram_command_token: str = Field(default="")
    telegram_chat_id: str = Field(default="")
    telegram_allowed_user_id: str = Field(default="")

    @property
    def database_url(self) -> str:
        return f"postgresql://{self.postgres_user}:{self.postgres_password}@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": False}


settings = Settings()