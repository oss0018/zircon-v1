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
    """Add newer watch/alert columns to lookalike_rules if missing."""
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
        if "watch_mode_enabled" not in existing_cols:
            conn.execute(
                text("ALTER TABLE lookalike_rules ADD COLUMN watch_mode_enabled BOOLEAN DEFAULT 0")
            )
        if "watch_feed_source" not in existing_cols:
            conn.execute(
                text("ALTER TABLE lookalike_rules ADD COLUMN watch_feed_source VARCHAR(50) DEFAULT 'whoisds'")
            )
        if "watch_last_run_at" not in existing_cols:
            conn.execute(
                text("ALTER TABLE lookalike_rules ADD COLUMN watch_last_run_at DATETIME")
            )
        if "watch_alert_email" not in existing_cols:
            conn.execute(
                text("ALTER TABLE lookalike_rules ADD COLUMN watch_alert_email TEXT DEFAULT ''")
            )
        if "watch_alert_telegram" not in existing_cols:
            conn.execute(
                text("ALTER TABLE lookalike_rules ADD COLUMN watch_alert_telegram TEXT DEFAULT ''")
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate lookalike_rules: %s", exc)


def _migrate_lookalike_domains(conn) -> None:
    """Ensure lookalike_domains has all enrichment/threat columns on upgrades."""
    from sqlalchemy import inspect, text
    from typing import Dict

    ALLOWED_NEW_COLS: Dict[str, str] = {
        "server_header": "VARCHAR(256)",
        "redirect_detected": "BOOLEAN",
        "redirects_to_legitimate": "BOOLEAN",
        "brand_in_title": "BOOLEAN",
        "phishing_keywords_in_title": "BOOLEAN",
        "ssl_valid": "BOOLEAN",
        "ssl_issuer": "VARCHAR(256)",
        "ssl_uses_lets_encrypt": "BOOLEAN",
        "ssl_cert_age_days": "INTEGER",
        "ssl_is_self_signed": "BOOLEAN",
        "country_code": "VARCHAR(5)",
        "asn": "VARCHAR(50)",
        "org": "VARCHAR(256)",
        "is_high_risk_country": "BOOLEAN",
        "registrar": "VARCHAR(256)",
        "domain_age_days": "INTEGER",
        "whois_privacy": "BOOLEAN",
        "registrant_org": "VARCHAR(256)",
        "creation_date": "DATETIME",
        "expiry_date": "DATETIME",
        "vt_malicious": "INTEGER",
        "vt_suspicious": "INTEGER",
        "vt_harmless": "INTEGER",
        "vt_undetected": "INTEGER",
        "vt_engines": "TEXT",
        "vt_community_score": "INTEGER",
        "vt_last_analysis_date": "DATETIME",
        "screenshot_url": "TEXT",
        "urlscan_uuid": "VARCHAR(64)",
        "urlscan_score": "REAL",
        "phash_distance": "INTEGER",
        "visual_similarity_pct": "REAL",
        "threat_score": "INTEGER",
        "severity": "INTEGER",
        "signals_fired": "TEXT DEFAULT '[]'",
        "last_checked_at": "DATETIME",
        "is_false_positive": "BOOLEAN DEFAULT 0",
        "fp_reason": "VARCHAR(256)",
    }

    try:
        inspector = inspect(conn)
        tables = inspector.get_table_names()
        if "lookalike_domains" not in tables:
            return
        existing_cols = {c["name"] for c in inspector.get_columns("lookalike_domains")}
        for col_name, col_type in ALLOWED_NEW_COLS.items():
            if col_name not in existing_cols:
                # Both col_name and col_type are from a hardcoded whitelist above
                conn.execute(
                    text(f"ALTER TABLE lookalike_domains ADD COLUMN {col_name} {col_type}")
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate lookalike_domains: %s", exc)


def _migrate_cti_schema(conn) -> None:
    """Ensure CTI MVP tables include expected columns on upgrades."""
    from sqlalchemy import inspect, text

    TABLE_COLS: dict[str, dict[str, str]] = {
        "cti_indicators": {
            "country_code": "VARCHAR(8) DEFAULT ''",
            "actor_names": "TEXT DEFAULT '[]'",
            "tags_json": "TEXT DEFAULT '[]'",
            "metadata_json": "TEXT DEFAULT '{}'",
            "stix_json": "TEXT DEFAULT '{}'",
            "tlp": "VARCHAR(20) DEFAULT 'TLP:CLEAR'",
            "is_false_positive": "BOOLEAN DEFAULT 0",
            "false_positive_reason": "TEXT",
            "first_seen_at": "DATETIME",
            "last_seen_at": "DATETIME",
            "updated_at": "DATETIME",
        },
        "cti_actors": {
            "aliases": "TEXT DEFAULT '[]'",
            "mitre_group_id": "VARCHAR(30) DEFAULT ''",
            "techniques": "TEXT DEFAULT '[]'",
            "software": "TEXT DEFAULT '[]'",
            "stix_json": "TEXT DEFAULT '{}'",
            "updated_at": "DATETIME",
        },
        "cti_techniques": {
            "tactics": "TEXT DEFAULT '[]'",
            "stix_json": "TEXT DEFAULT '{}'",
            "updated_at": "DATETIME",
        },
        "cti_siem_matches": {
            "sentinel_alert_id": "VARCHAR(128) DEFAULT ''",
            "matched_rule": "VARCHAR(255) DEFAULT ''",
            "raw_payload": "TEXT DEFAULT '{}'",
            "dispatched_channels": "TEXT DEFAULT '[]'",
        },
        "cti_vuln_intel": {
            "epss": "FLOAT DEFAULT 0",
            "is_cisa_kev": "BOOLEAN DEFAULT 0",
            "cvss": "FLOAT",
            "vendor": "VARCHAR(255) DEFAULT ''",
            "product": "VARCHAR(255) DEFAULT ''",
            "summary": "TEXT DEFAULT ''",
            "stix_json": "TEXT DEFAULT '{}'",
            "updated_at": "DATETIME",
        },
        "cti_reports": {
            "summary": "TEXT DEFAULT ''",
            "tlp": "VARCHAR(20) DEFAULT 'TLP:CLEAR'",
            "report_json": "TEXT DEFAULT '{}'",
            "stix_json": "TEXT DEFAULT '{}'",
            "updated_at": "DATETIME",
        },
        "cti_sentinel_coverage": {
            "has_sentinel_rule": "BOOLEAN DEFAULT 0",
            "has_recent_activity": "BOOLEAN DEFAULT 0",
            "state": "VARCHAR(30) DEFAULT 'BLIND_SPOT'",
            "notes": "TEXT DEFAULT ''",
            "updated_at": "DATETIME",
        },
    }

    try:
        inspector = inspect(conn)
        tables = set(inspector.get_table_names())
        for table_name, cols in TABLE_COLS.items():
            if table_name not in tables:
                continue
            existing_cols = {c["name"] for c in inspector.get_columns(table_name)}
            for col_name, col_type in cols.items():
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate CTI schema: %s", exc)


def _migrate_ds_source_credentials(conn) -> None:
    """Encrypt plaintext sensitive credentials in ds_sources.credentials."""
    from sqlalchemy import inspect, text
    import json

    from app.services.storage_credential_vault import StorageCredentialVault

    try:
        inspector = inspect(conn)
        if "ds_sources" not in set(inspector.get_table_names()):
            return
        rows = conn.execute(text("SELECT id, credentials FROM ds_sources")).fetchall()
        if not rows:
            return
        vault = StorageCredentialVault()
        is_postgres = conn.engine.dialect.name == "postgresql"
        update_stmt = (
            text("UPDATE ds_sources SET credentials = CAST(:credentials AS JSONB) WHERE id = :id")
            if is_postgres
            else text("UPDATE ds_sources SET credentials = :credentials WHERE id = :id")
        )
        for row in rows:
            creds = vault.parse_json_credentials(row.credentials)
            if not creds:
                continue
            encrypted = vault.encrypt_credentials(creds)
            if encrypted == creds:
                continue
            conn.execute(update_stmt, {"credentials": json.dumps(encrypted), "id": row.id})
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate ds_sources credentials: %s", exc)


def _migrate_deep_search_schema(conn) -> None:
    """Ensure Deep Search file/chunk tables have the Phase 1 ingestion columns."""
    from sqlalchemy import inspect, text

    DS_FILE_COLS: dict[str, str] = {
        "size_bytes": "BIGINT DEFAULT 0",
        "mtime": "DATETIME",
        "etag": "VARCHAR(256) DEFAULT ''",
        "content_sha256": "VARCHAR(64) DEFAULT ''",
        "indexed_at": "DATETIME",
        "last_seen_at": "DATETIME",
    }
    DS_CHUNK_COLS: dict[str, str] = {
        "start_offset": "INTEGER DEFAULT 0",
        "end_offset": "INTEGER DEFAULT 0",
    }

    try:
        inspector = inspect(conn)
        tables = set(inspector.get_table_names())
        if "ds_files" in tables:
            existing = {c["name"] for c in inspector.get_columns("ds_files")}
            for col_name, col_type in DS_FILE_COLS.items():
                if col_name not in existing:
                    conn.execute(text(f"ALTER TABLE ds_files ADD COLUMN {col_name} {col_type}"))
        if "ds_chunks" in tables:
            existing = {c["name"] for c in inspector.get_columns("ds_chunks")}
            for col_name, col_type in DS_CHUNK_COLS.items():
                if col_name not in existing:
                    conn.execute(text(f"ALTER TABLE ds_chunks ADD COLUMN {col_name} {col_type}"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate Deep Search schema: %s", exc)


def _migrate_sl_rules(conn) -> None:
    """Add alert_email and alert_telegram columns to sl_rules if missing."""
    from sqlalchemy import inspect, text

    ALLOWED_NEW_COLS: dict[str, str] = {
        "alert_email": "VARCHAR(254) DEFAULT ''",
        "alert_telegram": "VARCHAR(100) DEFAULT ''",
    }

    try:
        inspector = inspect(conn)
        tables = inspector.get_table_names()
        if "sl_rules" not in tables:
            return
        existing_cols = {c["name"] for c in inspector.get_columns("sl_rules")}
        for col_name, col_type in ALLOWED_NEW_COLS.items():
            if col_name not in existing_cols:
                conn.execute(
                    text(f"ALTER TABLE sl_rules ADD COLUMN {col_name} {col_type}")
                )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate sl_rules: %s", exc)


def _migrate_vulnscan(conn) -> None:
    """Add alert bookkeeping and scanner-config columns to vuln scanner tables if missing."""
    from sqlalchemy import inspect, text

    scans_new_cols: dict[str, str] = {
        "severe_alert_processed_at": "DATETIME",
        "scanner_config_json": "TEXT DEFAULT '{}'",
    }
    targets_new_cols: dict[str, str] = {
        "scanner_config_json": "TEXT DEFAULT '{}'",
    }

    try:
        inspector = inspect(conn)
        tables = inspector.get_table_names()
        if "vs_scans" in tables:
            existing_cols = {c["name"] for c in inspector.get_columns("vs_scans")}
            for col_name, col_type in scans_new_cols.items():
                if col_name not in existing_cols:
                    conn.execute(text(f"ALTER TABLE vs_scans ADD COLUMN {col_name} {col_type}"))
        if "vs_scan_targets" in tables:
            existing_target_cols = {c["name"] for c in inspector.get_columns("vs_scan_targets")}
            for col_name, col_type in targets_new_cols.items():
                if col_name not in existing_target_cols:
                    conn.execute(text(f"ALTER TABLE vs_scan_targets ADD COLUMN {col_name} {col_type}"))
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not migrate vulnscan schema: %s", exc)


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
        # Add lookalike domain enrichment columns if upgrading from older version
        await conn.run_sync(_migrate_lookalike_domains)
        # Ensure CTI MVP schema columns exist on upgrades
        await conn.run_sync(_migrate_cti_schema)
        # Encrypt existing ds_sources credentials (if ds_sources already exists)
        await conn.run_sync(_migrate_ds_source_credentials)
        # Ensure Deep Search ingestion columns exist on upgrades
        await conn.run_sync(_migrate_deep_search_schema)
        # Add alert_email / alert_telegram to sl_rules if upgrading from older version
        await conn.run_sync(_migrate_sl_rules)
        # Add vulnscan alert bookkeeping columns if upgrading from older version
        await conn.run_sync(_migrate_vulnscan)
