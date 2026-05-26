import logging
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import settings
from pathlib import Path

logger = logging.getLogger(__name__)

Path("data/db").mkdir(parents=True, exist_ok=True)

_is_sqlite = settings.database_url.startswith("sqlite")
_connect_args = {"check_same_thread": False, "timeout": 30} if _is_sqlite else {}

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    connect_args=_connect_args,
)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)

if _is_sqlite:
    from sqlalchemy import event as _sa_event

    @_sa_event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragmas(dbapi_conn, _record):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA cache_size=10000")
        cur.execute("PRAGMA temp_store=MEMORY")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.close()


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


def _migrate_brand_alerts(conn) -> None:
    """Add new columns to brand_alerts table if they are missing (SQLite ALTER TABLE)."""
    from sqlalchemy import inspect, text
    from typing import Dict

    # Whitelist of allowed new column definitions (col_name → SQL type).
    # All values are hardcoded — no user input reaches this function.
    ALLOWED_NEW_COLS: Dict[str, str] = {
        "ip": "VARCHAR(64)",
        "http_status": "INTEGER",
        "ssl_valid": "BOOLEAN",
        "page_title": "VARCHAR(512)",
        "similarity_pct": "FLOAT",
        "alive": "BOOLEAN",
        "checked_at": "DATETIME",
    }

    try:
        inspector = inspect(conn)
        tables = inspector.get_table_names()
        if "brand_alerts" not in tables:
            return
        existing_cols = {c["name"] for c in inspector.get_columns("brand_alerts")}
        for col_name, col_type in ALLOWED_NEW_COLS.items():
            if col_name not in existing_cols:
                # Both col_name and col_type are from a hardcoded whitelist above
                conn.execute(
                    text(f"ALTER TABLE brand_alerts ADD COLUMN {col_name} {col_type}")
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate brand_alerts: %s", exc)


def _migrate_owned_domains(conn) -> None:
    """Add brand_id column to owned_domains table if it is missing."""
    from sqlalchemy import inspect, text

    try:
        inspector = inspect(conn)
        tables = inspector.get_table_names()
        if "owned_domains" not in tables:
            return
        existing_cols = {c["name"] for c in inspector.get_columns("owned_domains")}
        if "brand_id" not in existing_cols:
            conn.execute(
                text("ALTER TABLE owned_domains ADD COLUMN brand_id INTEGER REFERENCES brands(id)")
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate owned_domains: %s", exc)


def _migrate_brands(conn) -> None:
    """Add per-brand generate settings columns to brands table if they are missing."""
    from sqlalchemy import inspect, text
    from typing import Dict

    ALLOWED_NEW_COLS: Dict[str, str] = {
        "generate_mode": "VARCHAR(20) DEFAULT 'domain'",
        "generate_limit": "INTEGER DEFAULT 1000",
    }

    try:
        inspector = inspect(conn)
        tables = inspector.get_table_names()
        if "brands" not in tables:
            return
        existing_cols = {c["name"] for c in inspector.get_columns("brands")}
        for col_name, col_type in ALLOWED_NEW_COLS.items():
            if col_name not in existing_cols:
                # Both col_name and col_type are from a hardcoded whitelist above
                conn.execute(
                    text(f"ALTER TABLE brands ADD COLUMN {col_name} {col_type}")
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate brands: %s", exc)


def _migrate_storage_sources(conn) -> None:
    """Ensure storage_sources and storage_file_catalog tables have all required columns."""
    from sqlalchemy import inspect, text
    from typing import Dict

    # Columns that may be added in future schema updates (whitelist)
    SOURCE_COLS: Dict[str, str] = {
        "last_run_errors": "INTEGER DEFAULT 0",
        "last_run_error_msg": "TEXT DEFAULT ''",
        "updated_at": "DATETIME",
    }
    CATALOG_COLS: Dict[str, str] = {
        "updated_at": "DATETIME",
    }

    try:
        inspector = inspect(conn)
        tables = inspector.get_table_names()

        if "storage_sources" in tables:
            existing = {c["name"] for c in inspector.get_columns("storage_sources")}
            for col_name, col_type in SOURCE_COLS.items():
                if col_name not in existing:
                    conn.execute(
                        text(f"ALTER TABLE storage_sources ADD COLUMN {col_name} {col_type}")
                    )

        if "storage_file_catalog" in tables:
            existing = {c["name"] for c in inspector.get_columns("storage_file_catalog")}
            for col_name, col_type in CATALOG_COLS.items():
                if col_name not in existing:
                    conn.execute(
                        text(f"ALTER TABLE storage_file_catalog ADD COLUMN {col_name} {col_type}")
                    )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate storage tables: %s", exc)


def _migrate_integrations(conn) -> None:
    """Add base_url column to integrations table if it is missing."""
    from sqlalchemy import inspect, text

    try:
        inspector = inspect(conn)
        tables = inspector.get_table_names()
        if "integrations" not in tables:
            return
        existing_cols = {c["name"] for c in inspector.get_columns("integrations")}
        if "base_url" not in existing_cols:
            conn.execute(
                text("ALTER TABLE integrations ADD COLUMN base_url VARCHAR(512) DEFAULT ''")
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate integrations: %s", exc)


def _migrate_monitoring(conn) -> None:
    """Ensure monitoring tables have the newer runs/findings schema."""
    from sqlalchemy import inspect, text

    JOB_COLS: dict[str, str] = {}
    RUN_COLS: dict[str, str] = {
        "findings_count": "INTEGER DEFAULT 0",
        "preview_count": "INTEGER DEFAULT 0",
        "summary_json": "TEXT DEFAULT '{}'",
        "error_message": "TEXT DEFAULT ''",
        "trigger_type": "VARCHAR(20) DEFAULT 'manual'",
        "status": "VARCHAR(20) DEFAULT 'running'",
        "started_at": "DATETIME",
        "completed_at": "DATETIME",
    }
    FINDING_COLS: dict[str, str] = {
        "check_type": "VARCHAR(50)",
        "matched_target": "VARCHAR(512)",
        "source": "VARCHAR(512) DEFAULT ''",
        "evidence_json": "TEXT DEFAULT '{}'",
        "status": "VARCHAR(20) DEFAULT 'new'",
        "fingerprint": "VARCHAR(128) DEFAULT ''",
        "first_seen": "DATETIME",
        "last_seen": "DATETIME",
        "created_at": "DATETIME",
    }

    try:
        inspector = inspect(conn)
        tables = inspector.get_table_names()

        if "monitoring_jobs" in tables:
            existing = {c["name"] for c in inspector.get_columns("monitoring_jobs")}
            for col_name, col_type in JOB_COLS.items():
                if col_name not in existing:
                    conn.execute(text(f"ALTER TABLE monitoring_jobs ADD COLUMN {col_name} {col_type}"))

        if "monitoring_runs" in tables:
            existing = {c["name"] for c in inspector.get_columns("monitoring_runs")}
            for col_name, col_type in RUN_COLS.items():
                if col_name not in existing:
                    conn.execute(text(f"ALTER TABLE monitoring_runs ADD COLUMN {col_name} {col_type}"))

        if "monitoring_findings" in tables:
            existing = {c["name"] for c in inspector.get_columns("monitoring_findings")}
            for col_name, col_type in FINDING_COLS.items():
                if col_name not in existing:
                    conn.execute(text(f"ALTER TABLE monitoring_findings ADD COLUMN {col_name} {col_type}"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate monitoring tables: %s", exc)


def _migrate_lookalike_rules(conn) -> None:
    """Add alert_threshold column to lookalike_rules if it is missing."""
    from sqlalchemy import inspect, text

    try:
        inspector = inspect(conn)
        tables = inspector.get_table_names()
        if "lookalike_rules" not in tables:
            return
        existing_cols = {c["name"] for c in inspector.get_columns("lookalike_rules")}
        if "alert_threshold" not in existing_cols:
            conn.execute(
                text("ALTER TABLE lookalike_rules ADD COLUMN alert_threshold INTEGER DEFAULT 50")
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate lookalike_rules: %s", exc)


async def init_db():
    from app import models  # noqa: F401
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Add new columns to existing brand_alerts tables (non-destructive migration)
        await conn.run_sync(_migrate_brand_alerts)
        # Add brand_id to owned_domains if upgrading from older version
        await conn.run_sync(_migrate_owned_domains)
        # Add per-brand generate settings to brands if upgrading from older version
        await conn.run_sync(_migrate_brands)
        # Add storage_sources and storage_file_catalog tables (no-op if they already exist)
        # create_all handles this; migration below handles columns added later
        await conn.run_sync(_migrate_storage_sources)
        # Add base_url to integrations if upgrading from older version
        await conn.run_sync(_migrate_integrations)
        # Add monitoring runs/findings tables/columns if upgrading from older version
        await conn.run_sync(_migrate_monitoring)
        # Add alert threshold to lookalike rules if upgrading from older version
        await conn.run_sync(_migrate_lookalike_rules)
