from __future__ import annotations

from pydantic_settings import BaseSettings
from pydantic import field_validator
from typing import Set, Optional


class Settings(BaseSettings):
    bot_token: str
    admin_ids: Set[int]
    channel_id: str
    db_path: str = "podslushka.db"
    database_url: Optional[str] = None
    # Telegram itself limits individual text messages; the bot does not impose
    # an additional minimum so users may submit even a single character.
    min_text_len: int = 0
    cooldown_seconds: int = 30
    max_posts_per_hour: int = 5
    media_group_timeout: float = 3.0
    queue_alert_threshold: int = 20
    backup_chat_id: Optional[int] = None
    dashboard_sync_url: Optional[str] = None
    dashboard_sync_secret: Optional[str] = None

    @field_validator("admin_ids", mode="before")
    @classmethod
    def _parse_admin_ids(cls, v):
        if isinstance(v, int):
            return {v}
        if isinstance(v, str):
            return {int(x.strip()) for x in v.split(",") if x.strip()}
        return v

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


def load_settings() -> Settings:
    return Settings()
