# taijitu/config.py
# Central configuration — reads from .env file
# Every setting in TAIJITU comes from here

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """
    TAIJITU Configuration
    All values loaded from .env file automatically
    """

    # ── APP ───────────────────────────────────────────
    app_env: str = Field(default="development")
    log_level: str = Field(default="INFO")
    secret_key: str = Field(default="change_in_production")

    # ── OLLAMA (Local AI — no API key needed) ─────────
    ollama_base_url: str = Field(default="http://localhost:11434")
    ollama_model: str = Field(default="llama3.2")

    # ── DATABASE ──────────────────────────────────────
    postgres_host: str = Field(default="localhost")
    postgres_port: int = Field(default=5432)
    postgres_db: str = Field(default="taijitu")
    postgres_user: str = Field(default="taijitu")
    postgres_password: str = Field(default="taijitu_secure_2026")

    # ── REDIS ─────────────────────────────────────────
    redis_url: str = Field(default="redis://localhost:6379/0")

    # ── TELEGRAM ──────────────────────────────────────
    telegram_alert_token: str = Field(default="")
    telegram_command_token: str = Field(default="")
    telegram_chat_id: str = Field(default="")
    telegram_allowed_user_id: str = Field(default="")

    # ── COMPUTED PROPERTIES ───────────────────────────
    @property
    def database_url(self) -> str:
        """Full PostgreSQL connection string"""
        return (
            f"postgresql://{self.postgres_user}:"
            f"{self.postgres_password}@"
            f"{self.postgres_host}:"
            f"{self.postgres_port}/"