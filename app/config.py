from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Zircon FRT"
    secret_key: str = "change-me-in-production-min-32-chars!!"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440

    database_url: str = "sqlite+aiosqlite:///./data/db/zircon.db"
    whoosh_index_dir: str = "./data/index"
    uploads_dir: str = "./data/uploads"
    monitored_dir: str = "./data/monitored"
    deep_search_dir: str = "deep_search_data"

    http_port: int = 8181
    https_port: int = 8443

    encryption_key: str = ""

    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    telegram_bot_token: str = ""

    class Config:
        env_file = ".env"
        env_prefix = "ZIRCON_"


settings = Settings()
