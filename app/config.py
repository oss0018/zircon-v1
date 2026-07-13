from pydantic import Field, AliasChoices
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ------------------------------------------------------------------ #
    # Core                                                                 #
    # ------------------------------------------------------------------ #
    app_name: str = "Zircon FRT"
    secret_key: str = "change-me-in-production-min-32-chars!!"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 1440

    # ------------------------------------------------------------------ #
    # Database / storage                                                   #
    # ------------------------------------------------------------------ #
    database_url: str = "sqlite+aiosqlite:///./data/db/zircon.db"
    whoosh_index_dir: str = "./data/index"
    uploads_dir: str = "./data/uploads"
    monitored_dir: str = "./data/monitored"
    vulnscan_reports_dir: str = "./data/vulnscan_reports"
    deep_search_dir: str = "deep_search_data"
    deep_search_staging_dir: str = "/tmp/ds_staging"
    elasticsearch_url: str = ""
    elasticsearch_username: str = ""
    elasticsearch_password: str = ""

    # ------------------------------------------------------------------ #
    # Network                                                              #
    # ------------------------------------------------------------------ #
    http_port: int = 8181
    https_port: int = 8443

    # ------------------------------------------------------------------ #
    # Security / encryption                                                #
    # ------------------------------------------------------------------ #
    encryption_key: str = ""

    # ------------------------------------------------------------------ #
    # SMTP                                                                 #
    # ------------------------------------------------------------------ #
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""

    # ------------------------------------------------------------------ #
    # Integrations (all use ZIRCON_ prefix)                               #
    # ------------------------------------------------------------------ #
    telegram_bot_token: str = ""
    urlscan_api_key: str = ""
    slack_webhook_url: str = ""

    # ------------------------------------------------------------------ #
    # Deep Search — storage-credential vault                               #
    # These vars are NOT prefixed with ZIRCON_ in the .env file.          #
    # ------------------------------------------------------------------ #
    ds_credential_kek: str = Field(
        default="",
        validation_alias=AliasChoices("DS_CREDENTIAL_KEK", "ZIRCON_DS_CREDENTIAL_KEK"),
    )
    deep_search_local_mount: str = Field(
        default="/mnt/local_dumps",
        validation_alias=AliasChoices("DEEP_SEARCH_LOCAL_MOUNT", "ZIRCON_DEEP_SEARCH_LOCAL_MOUNT"),
    )

    # ------------------------------------------------------------------ #
    # Social Listening — Reddit                                            #
    # ------------------------------------------------------------------ #
    reddit_client_id: str = Field(
        default="",
        validation_alias=AliasChoices("REDDIT_CLIENT_ID", "ZIRCON_REDDIT_CLIENT_ID"),
    )
    reddit_client_secret: str = Field(
        default="",
        validation_alias=AliasChoices("REDDIT_CLIENT_SECRET", "ZIRCON_REDDIT_CLIENT_SECRET"),
    )
    reddit_user_agent: str = Field(
        default="zircon-social-listening/1.0",
        validation_alias=AliasChoices("REDDIT_USER_AGENT", "ZIRCON_REDDIT_USER_AGENT"),
    )

    # ------------------------------------------------------------------ #
    # Social Listening — Telegram (MTProto / Telethon)                    #
    # ------------------------------------------------------------------ #
    telegram_api_id: str = Field(
        default="",
        validation_alias=AliasChoices("TELEGRAM_API_ID", "ZIRCON_TELEGRAM_API_ID"),
    )
    telegram_api_hash: str = Field(
        default="",
        validation_alias=AliasChoices("TELEGRAM_API_HASH", "ZIRCON_TELEGRAM_API_HASH"),
    )
    telegram_session_string: str = Field(
        default="",
        validation_alias=AliasChoices("TELEGRAM_SESSION_STRING", "ZIRCON_TELEGRAM_SESSION_STRING"),
    )

    # ------------------------------------------------------------------ #
    # Social Listening — Twitter / X                                       #
    # ------------------------------------------------------------------ #
    twitter_bearer_token: str = Field(
        default="",
        validation_alias=AliasChoices("TWITTER_BEARER_TOKEN", "ZIRCON_TWITTER_BEARER_TOKEN"),
    )

    # ------------------------------------------------------------------ #
    # Impersonation Monitoring                                             #
    # ------------------------------------------------------------------ #
    hibp_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("HIBP_API_KEY", "ZIRCON_HIBP_API_KEY"),
    )
    apify_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("APIFY_API_KEY", "ZIRCON_APIFY_API_KEY"),
    )
    facebook_apify_actor: str = Field(
        default="",
        validation_alias=AliasChoices("FACEBOOK_APIFY_ACTOR", "ZIRCON_FACEBOOK_APIFY_ACTOR"),
    )
    vk_service_token: str = Field(
        default="",
        validation_alias=AliasChoices("VK_SERVICE_TOKEN", "ZIRCON_VK_SERVICE_TOKEN"),
    )
    pagerduty_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("PAGERDUTY_API_KEY", "ZIRCON_PAGERDUTY_API_KEY"),
    )
    pagerduty_service_id: str = Field(
        default="",
        validation_alias=AliasChoices("PAGERDUTY_SERVICE_ID", "ZIRCON_PAGERDUTY_SERVICE_ID"),
    )

    # ------------------------------------------------------------------ #
    # CTI / Celery                                                         #
    # ------------------------------------------------------------------ #
    cti_celery_broker_url: str = Field(
        default="redis://localhost:6379/1",
        validation_alias=AliasChoices("CTI_CELERY_BROKER_URL", "ZIRCON_CTI_CELERY_BROKER_URL"),
    )
    cti_celery_result_backend: str = Field(
        default="redis://localhost:6379/1",
        validation_alias=AliasChoices("CTI_CELERY_RESULT_BACKEND", "ZIRCON_CTI_CELERY_RESULT_BACKEND"),
    )
    cti_threatfox_interval_minutes: int = Field(
        default=15,
        validation_alias=AliasChoices(
            "CTI_THREATFOX_INTERVAL_MINUTES", "ZIRCON_CTI_THREATFOX_INTERVAL_MINUTES"
        ),
    )
    cti_urlhaus_interval_minutes: int = Field(
        default=15,
        validation_alias=AliasChoices(
            "CTI_URLHAUS_INTERVAL_MINUTES", "ZIRCON_CTI_URLHAUS_INTERVAL_MINUTES"
        ),
    )
    cti_malwarebazaar_interval_minutes: int = Field(
        default=15,
        validation_alias=AliasChoices(
            "CTI_MALWAREBAZAAR_INTERVAL_MINUTES", "ZIRCON_CTI_MALWAREBAZAAR_INTERVAL_MINUTES"
        ),
    )
    cti_feodo_interval_minutes: int = Field(
        default=30,
        validation_alias=AliasChoices(
            "CTI_FEODO_INTERVAL_MINUTES", "ZIRCON_CTI_FEODO_INTERVAL_MINUTES"
        ),
    )
    cti_otx_interval_minutes: int = Field(
        default=15,
        validation_alias=AliasChoices("CTI_OTX_INTERVAL_MINUTES", "ZIRCON_CTI_OTX_INTERVAL_MINUTES"),
    )
    cti_cisa_kev_interval_minutes: int = Field(
        default=60,
        validation_alias=AliasChoices(
            "CTI_CISA_KEV_INTERVAL_MINUTES", "ZIRCON_CTI_CISA_KEV_INTERVAL_MINUTES"
        ),
    )
    cti_epss_interval_minutes: int = Field(
        default=60,
        validation_alias=AliasChoices(
            "CTI_EPSS_INTERVAL_MINUTES", "ZIRCON_CTI_EPSS_INTERVAL_MINUTES"
        ),
    )
    cti_attack_sync_interval_minutes: int = Field(
        default=720,
        validation_alias=AliasChoices(
            "CTI_ATTACK_SYNC_INTERVAL_MINUTES", "ZIRCON_CTI_ATTACK_SYNC_INTERVAL_MINUTES"
        ),
    )
    cti_telegram_interval_minutes: int = Field(
        default=5,
        validation_alias=AliasChoices(
            "CTI_TELEGRAM_INTERVAL_MINUTES", "ZIRCON_CTI_TELEGRAM_INTERVAL_MINUTES"
        ),
    )
    cti_twitter_interval_minutes: int = Field(
        default=10,
        validation_alias=AliasChoices(
            "CTI_TWITTER_INTERVAL_MINUTES", "ZIRCON_CTI_TWITTER_INTERVAL_MINUTES"
        ),
    )
    cti_alert_email: str = Field(
        default="",
        validation_alias=AliasChoices("CTI_ALERT_EMAIL", "ZIRCON_CTI_ALERT_EMAIL"),
    )
    cti_alert_telegram: str = Field(
        default="",
        validation_alias=AliasChoices("CTI_ALERT_TELEGRAM", "ZIRCON_CTI_ALERT_TELEGRAM"),
    )

    # ------------------------------------------------------------------ #
    # CTI enrichment APIs                                                  #
    # ------------------------------------------------------------------ #
    virustotal_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("VIRUSTOTAL_API_KEY", "ZIRCON_VIRUSTOTAL_API_KEY"),
    )
    greynoise_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("GREYNOISE_API_KEY", "ZIRCON_GREYNOISE_API_KEY"),
    )
    abuseipdb_api_key: str = Field(
        default="",
        validation_alias=AliasChoices("ABUSEIPDB_API_KEY", "ZIRCON_ABUSEIPDB_API_KEY"),
    )
    maxmind_geoip_db_path: str = Field(
        default="./data/geoip/GeoLite2-City.mmdb",
        validation_alias=AliasChoices("MAXMIND_GEOIP_DB_PATH", "ZIRCON_MAXMIND_GEOIP_DB_PATH"),
    )
    whois_timeout_seconds: int = Field(
        default=10,
        validation_alias=AliasChoices("WHOIS_TIMEOUT_SECONDS", "ZIRCON_WHOIS_TIMEOUT_SECONDS"),
    )

    # ------------------------------------------------------------------ #
    # Microsoft Sentinel connector                                         #
    # ------------------------------------------------------------------ #
    sentinel_workspace_id: str = Field(
        default="",
        validation_alias=AliasChoices("SENTINEL_WORKSPACE_ID", "ZIRCON_SENTINEL_WORKSPACE_ID"),
    )
    sentinel_shared_key: str = Field(
        default="",
        validation_alias=AliasChoices("SENTINEL_SHARED_KEY", "ZIRCON_SENTINEL_SHARED_KEY"),
    )
    sentinel_log_type: str = Field(
        default="ZirconCTI",
        validation_alias=AliasChoices("SENTINEL_LOG_TYPE", "ZIRCON_SENTINEL_LOG_TYPE"),
    )

    class Config:
        env_file = ".env"
        env_prefix = "ZIRCON_"
        # Ignore any env vars that have no matching field so that future
        # additions to .env do not crash the application on startup.
        extra = "ignore"
        # Allow fields that carry a validation_alias to also be addressed
        # by their Python name (e.g. in tests or direct instantiation).
        populate_by_name = True


settings = Settings()
