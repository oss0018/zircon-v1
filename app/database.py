from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from app.config import settings
from pathlib import Path

Path("data/db").mkdir(parents=True, exist_ok=True)

engine = create_async_engine(settings.database_url, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


def _migrate_brand_alerts(conn) -> None:
    """Add new columns to brand_alerts table if they are missing (SQLite ALTER TABLE)."""
    from sqlalchemy import inspect, text

    # Whitelist of allowed new column definitions (col_name → SQL type).
    # All values are hardcoded — no user input reaches this function.
    ALLOWED_NEW_COLS: dict[str, str] = {
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
        print(f"[db-migrate] Warning: could not migrate brand_alerts — {exc}")


async def init_db():
    from app import models  # noqa: F401
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Add new columns to existing brand_alerts tables (non-destructive migration)
        await conn.run_sync(_migrate_brand_alerts)
