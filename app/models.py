from sqlalchemy import (
    JSON,
    Column,
    Integer,
    String,
    Boolean,
    Float,
    DateTime,
    Text,
    ForeignKey,
    BigInteger,
    UniqueConstraint,
    Index,
    Computed,
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TSVECTOR
from app.database import Base
from app.config import settings


def _utcnow():
    return datetime.now(timezone.utc)


_IS_POSTGRES = settings.database_url.startswith("postgresql")


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    role = Column(String(20), default="user")
    created_at = Column(DateTime, default=_utcnow)


class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)
    files = relationship("File", back_populates="project")


class File(Base):
    __tablename__ = "files"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    original_name = Column(String(255), nullable=False)
    path = Column(String(512), nullable=False)
    size = Column(BigInteger, default=0)
    mime_type = Column(String(100), default="")
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=True)
    indexed = Column(Boolean, default=False)
    checksum = Column(String(64), default="")
    uploaded_at = Column(DateTime, default=_utcnow)
    tags = Column(Text, default="")
    project = relationship("Project", back_populates="files")


class Integration(Base):
    __tablename__ = "integrations"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    service_type = Column(String(50), nullable=False, unique=True)
    api_key_encrypted = Column(Text, default="")
    base_url = Column(String(512), default="")
    is_active = Column(Boolean, default=False)
    rate_limit = Column(Integer, default=60)
    cache_ttl = Column(Integer, default=3600)
    created_at = Column(DateTime, default=_utcnow)


class SearchTemplate(Base):
    __tablename__ = "search_templates"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    query = Column(Text, nullable=False)
    filters_json = Column(Text, default="{}")
    schedule = Column(String(100), default="")
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)


class MonitoringJob(Base):
    __tablename__ = "monitoring_jobs"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    type = Column(String(50), nullable=False)
    config_json = Column(Text, default="{}")
    schedule = Column(String(100), default="*/15 * * * *")
    is_active = Column(Boolean, default=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    runs = relationship(
        "MonitoringRun",
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="MonitoringRun.started_at.desc()",
    )
    findings = relationship(
        "MonitoringFinding",
        back_populates="job",
        cascade="all, delete-orphan",
        order_by="MonitoringFinding.last_seen.desc()",
    )


class MonitoringRun(Base):
    __tablename__ = "monitoring_runs"
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("monitoring_jobs.id"), nullable=False)
    trigger_type = Column(String(20), default="manual")  # manual | scheduled
    status = Column(String(20), default="running")  # running | completed | failed
    findings_count = Column(Integer, default=0)
    preview_count = Column(Integer, default=0)
    summary_json = Column(Text, default="{}")
    error_message = Column(Text, default="")
    started_at = Column(DateTime, default=_utcnow)
    completed_at = Column(DateTime, nullable=True)
    job = relationship("MonitoringJob", back_populates="runs")
    findings = relationship("MonitoringFinding", back_populates="run")


class MonitoringFinding(Base):
    __tablename__ = "monitoring_findings"
    id = Column(Integer, primary_key=True)
    job_id = Column(Integer, ForeignKey("monitoring_jobs.id"), nullable=False)
    run_id = Column(Integer, ForeignKey("monitoring_runs.id"), nullable=False)
    check_type = Column(String(50), nullable=False)
    matched_target = Column(String(512), nullable=False)
    source = Column(String(512), default="")
    evidence_json = Column(Text, default="{}")
    status = Column(String(20), default="new")  # new | investigating | resolved
    fingerprint = Column(String(128), default="")
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)
    created_at = Column(DateTime, default=_utcnow)
    job = relationship("MonitoringJob", back_populates="findings")
    run = relationship("MonitoringRun", back_populates="findings")


class WatchlistItem(Base):
    __tablename__ = "watchlist_items"
    id = Column(Integer, primary_key=True)
    type = Column(String(20), nullable=False)  # email/domain/keyword/brand/ip
    value = Column(String(512), nullable=False)
    integrations_json = Column(Text, default="[]")
    alert_email = Column(String(256), default="")
    alert_telegram = Column(String(100), default="")
    created_at = Column(DateTime, default=_utcnow)


class SearchLog(Base):
    __tablename__ = "search_logs"
    id = Column(Integer, primary_key=True)
    query = Column(Text, nullable=False)
    results_count = Column(Integer, default=0)
    duration_ms = Column(Integer, default=0)
    source = Column(String(50), default="local")
    created_at = Column(DateTime, default=_utcnow)


class ApiRequestLog(Base):
    __tablename__ = "api_request_logs"
    id = Column(Integer, primary_key=True)
    integration_id = Column(Integer, ForeignKey("integrations.id"), nullable=True)
    endpoint = Column(String(256), default="")
    status_code = Column(Integer, default=200)
    duration_ms = Column(Integer, default=0)
    cached = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)


class Brand(Base):
    __tablename__ = "brands"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    url = Column(String(512), default="")
    keywords = Column(Text, default="")
    logo_path = Column(String(512), default="")
    similarity_threshold = Column(Float, default=0.8)
    monitoring_enabled = Column(Boolean, default=True)
    # Per-brand Advanced Domain Checks settings
    generate_mode = Column(String(20), default="domain")   # domain | brand_name | both
    generate_limit = Column(Integer, default=1000)
    created_at = Column(DateTime, default=_utcnow)
    alerts = relationship("BrandAlert", back_populates="brand")
    owned_domains = relationship("OwnedDomain", back_populates="brand", cascade="all, delete-orphan")
    logo_misuse_cases = relationship("LogoMisuseCase", back_populates="brand", cascade="all, delete-orphan")


class OwnedDomain(Base):
    """Domains owned/trusted by the organisation (used to mark alerts as trusted).

    Scoped per Brand: each monitoring profile has its own list of owned domains.
    """
    __tablename__ = "owned_domains"
    id = Column(Integer, primary_key=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=True)
    domain = Column(String(512), nullable=False)
    match_subdomains = Column(Boolean, default=True)
    notes = Column(String(512), default="")
    created_at = Column(DateTime, default=_utcnow)
    brand = relationship("Brand", back_populates="owned_domains")


class BrandAlert(Base):
    __tablename__ = "brand_alerts"
    id = Column(Integer, primary_key=True)
    brand_id = Column(Integer, ForeignKey("brands.id"))
    similar_domain = Column(String(512), nullable=False)
    similarity_score = Column(Float, default=0.0)
    source = Column(String(100), default="")
    details_json = Column(Text, default="{}")
    status = Column(String(20), default="new")  # new/reviewed/dismissed
    # Extended domain check results
    ip = Column(String(64), nullable=True)
    http_status = Column(Integer, nullable=True)
    ssl_valid = Column(Boolean, nullable=True)
    page_title = Column(String(512), nullable=True)
    similarity_pct = Column(Float, nullable=True)
    alive = Column(Boolean, nullable=True)
    checked_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    brand = relationship("Brand", back_populates="alerts")


class LogoMisuseCase(Base):
    __tablename__ = "logo_misuse_cases"
    id = Column(Integer, primary_key=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False)
    source_url = Column(Text, nullable=False)
    page_title = Column(String(512), default="")
    thumbnail_url = Column(Text, default="")
    match_type = Column(String(50), default="logo")   # logo | text | domain | manual
    confidence = Column(Float, default=0.0)
    description = Column(Text, default="")
    status = Column(String(20), default="new")        # new | reviewing | confirmed | dismissed | takedown_requested
    detection_source = Column(String(50), default="manual")
    evidence_json = Column(Text, default="{}")
    reported_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    brand = relationship("Brand", back_populates="logo_misuse_cases")


class SocialListeningRule(Base):
    __tablename__ = "sl_rules"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False)
    brand_terms = Column(Text, default="[]")
    hashtags = Column(Text, default="[]")
    exclusions = Column(Text, default="[]")
    languages = Column(Text, default='["uk","ru","en"]')
    platforms = Column(Text, default="[]")
    severity_threshold = Column(Integer, default=2)
    alert_on = Column(String(40), default="EVERY_MENTION")
    schedule_cron = Column(String(100), default="*/15 * * * *")
    alert_email = Column(String(254), default="")
    alert_telegram = Column(String(100), default="")
    store_all = Column(Boolean, default=False)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class SLRawMention(Base):
    __tablename__ = "sl_raw_mentions"
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("sl_rules.id"), nullable=False)
    source_platform = Column(String(50), nullable=False)
    source_url = Column(Text, default="")
    author_id = Column(String(200), default="")
    author_username = Column(String(200), default="")
    content_raw = Column(Text, default="")
    content_fingerprint = Column(String(64), unique=True, nullable=False)
    published_at = Column(DateTime, nullable=True)
    collected_at = Column(DateTime, default=_utcnow)
    status = Column(String(20), default="pending")


class SLMention(Base):
    __tablename__ = "sl_mentions"
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("sl_rules.id"), nullable=False)
    raw_id = Column(Integer, ForeignKey("sl_raw_mentions.id"), nullable=True)
    source_platform = Column(String(50), nullable=False)
    source_url = Column(Text, default="")
    source_channel = Column(String(200), default="")
    author_id = Column(String(200), default="")
    author_username = Column(String(200), default="")
    author_reach = Column(Integer, default=0)
    content_raw = Column(Text, default="")
    content_normalized = Column(Text, default="")
    content_fingerprint = Column(String(64), unique=True, nullable=False)
    language = Column(String(20), default="unknown")
    sentiment_label = Column(String(10), default="NEU")
    sentiment_score = Column(Float, default=0.0)
    entities_json = Column(Text, default="[]")
    matched_terms_json = Column(Text, default="[]")
    threat_indicators_json = Column(Text, default="{}")
    relevance_score = Column(Float, default=0.0)
    severity = Column(Integer, default=1)
    engagement_json = Column(Text, default="{}")
    status = Column(String(20), default="new")
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    published_at = Column(DateTime, nullable=True)
    collected_at = Column(DateTime, default=_utcnow)
    created_at = Column(DateTime, default=_utcnow)


class SLAlert(Base):
    __tablename__ = "sl_alerts"
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("sl_rules.id"), nullable=False)
    mention_id = Column(Integer, ForeignKey("sl_mentions.id"), nullable=True)
    alert_type = Column(String(40), nullable=False)
    severity = Column(Integer, default=1)
    title = Column(String(255), nullable=False)
    body = Column(Text, default="")
    channels_json = Column(Text, default="[]")
    status = Column(String(20), default="pending")
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    sent_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True)
    type = Column(String(50), default="info")
    title = Column(String(256), nullable=False)
    message = Column(Text, default="")
    read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)


class WatchedFolder(Base):
    __tablename__ = "watched_folders"
    id = Column(Integer, primary_key=True)
    path = Column(String(512), unique=True, nullable=False)
    is_active = Column(Boolean, default=True)
    files_count = Column(Integer, default=0)
    last_scan = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)


class TILookupHistory(Base):
    __tablename__ = "ti_lookup_history"
    id = Column(Integer, primary_key=True)
    ioc_value = Column(String(512), nullable=False)
    ioc_type = Column(String(20), nullable=False)   # ip, domain, hash, url, email
    sources_json = Column(Text, default="[]")        # JSON list of queried service types
    results_json = Column(Text, default="{}")        # Full JSON results keyed by service type
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=_utcnow)


# ── TI Dashboard (Variant B) ──────────────────────────────────────────────

class TIDashboard(Base):
    """Manifest-driven Threat Intelligence dashboard."""
    __tablename__ = "ti_dashboards"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    slug = Column(String(100), unique=True, nullable=False)
    scope = Column(String(20), default="global")   # "user" | "global"
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    widgets = relationship(
        "TIWidget",
        back_populates="dashboard",
        cascade="all, delete-orphan",
        order_by="TIWidget.id",
    )


class TIWidget(Base):
    """Widget placed on a TI dashboard."""
    __tablename__ = "ti_widgets"
    id = Column(Integer, primary_key=True)
    dashboard_id = Column(Integer, ForeignKey("ti_dashboards.id"), nullable=False)
    type = Column(String(50), nullable=False)          # e.g. "ti_stats", "ti_recent_lookups"
    title = Column(String(200), nullable=False, default="")
    params_json = Column(Text, default="{}")            # JSON widget parameters
    layout_json = Column(Text, default='{"x":0,"y":0,"w":12,"h":2}')  # JSON {x,y,w,h}
    dashboard = relationship("TIDashboard", back_populates="widgets")


# ── External Storage Sources ──────────────────────────────────────────────────

class StorageSource(Base):
    """External storage connection (S3, SFTP, WebDAV) for Local Index."""
    __tablename__ = "storage_sources"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    source_type = Column(String(20), nullable=False)   # s3 | sftp | webdav
    config_encrypted = Column(Text, default="")        # Fernet-encrypted JSON of connection params
    is_enabled = Column(Boolean, default=True)
    schedule = Column(String(50), default="@hourly")   # cron expr, @hourly/@daily, or "disabled"
    max_file_size_mb = Column(Integer, default=25)     # per-source max file size limit
    recursive = Column(Boolean, default=True)
    # Last sync status
    last_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(String(20), default="")   # ok | error | running
    last_run_scanned = Column(Integer, default=0)
    last_run_indexed = Column(Integer, default=0)
    last_run_errors = Column(Integer, default=0)
    last_run_error_msg = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    catalog_entries = relationship(
        "StorageFileCatalog",
        back_populates="source",
        cascade="all, delete-orphan",
    )


class StorageFileCatalog(Base):
    """File catalog entry for an external storage source (used for incremental indexing)."""
    __tablename__ = "storage_file_catalog"
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey("storage_sources.id"), nullable=False)
    path = Column(String(2048), nullable=False)        # file key / remote path
    size = Column(BigInteger, default=0)
    mtime = Column(DateTime, nullable=True)
    etag = Column(String(256), default="")             # ETag / hash if available
    content_hash = Column(String(64), default="")      # SHA-256 of content
    last_indexed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="pending")     # pending | indexed | error | skipped
    error = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    source = relationship("StorageSource", back_populates="catalog_entries")


# ── Deep Search (TS-DS-001 Phase 1 foundation) ───────────────────────────────

_DS_JSON = JSONB if _IS_POSTGRES else JSON
_DS_TEXT_ARRAY = ARRAY(Text) if _IS_POSTGRES else JSON
_DS_TSVECTOR = TSVECTOR if _IS_POSTGRES else Text


class DSStorageSource(Base):
    __tablename__ = "ds_sources"
    id = Column(Integer, primary_key=True)
    display_name = Column(String(255), nullable=False)
    source_type = Column(String(32), nullable=False)
    host = Column(String(255), default="")
    port = Column(Integer, nullable=True)
    path = Column(String(2048), default="")
    protocol = Column(String(32), default="")
    bucket_name = Column(String(255), default="")
    credentials = Column(_DS_JSON, default=dict)
    api_config = Column(_DS_JSON, default=dict)
    schedule_cron = Column(String(100), default="@hourly")
    max_file_size_mb = Column(Integer, default=25)
    include_extensions = Column(_DS_TEXT_ARRAY, default=list)
    exclude_extensions = Column(_DS_TEXT_ARRAY, default=list)
    enabled = Column(Boolean, default=True)
    last_crawl_at = Column(DateTime, nullable=True)
    last_crawl_started_at = Column(DateTime, nullable=True)
    last_crawl_completed_at = Column(DateTime, nullable=True)
    last_crawl_status = Column(String(20), default="")
    last_crawl_error = Column(Text, default="")
    last_crawl_files_scanned = Column(Integer, default=0)
    last_crawl_files_indexed = Column(Integer, default=0)
    health_status = Column(String(20), default="unknown")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class DSFile(Base):
    __tablename__ = "ds_files"
    __table_args__ = (
        UniqueConstraint("source_id", "file_path", name="uq_ds_files_source_path"),
        Index("idx_ds_files_source", "source_id"),
        Index("idx_ds_files_status", "index_status"),
        Index("idx_ds_files_severity", "severity_max"),
        Index("idx_ds_files_path", "file_path"),
    )
    id = Column(Integer, primary_key=True)
    source_id = Column(Integer, ForeignKey("ds_sources.id", ondelete="CASCADE"), nullable=False)
    file_path = Column(String(4096), nullable=False)
    file_name = Column(String(512), default="")
    size_bytes = Column(BigInteger, default=0)
    mtime = Column(DateTime, nullable=True)
    etag = Column(String(256), default="")
    content_sha256 = Column(String(64), default="")
    index_status = Column(String(20), default="pending")
    parse_mode = Column(String(20), default="auto")
    leak_count = Column(Integer, default=0)
    severity_max = Column(Integer, default=0)
    has_credentials = Column(Boolean, default=False)
    has_pii = Column(Boolean, default=False)
    has_api_keys = Column(Boolean, default=False)
    pattern_names = Column(_DS_TEXT_ARRAY, default=list)
    indexed_at = Column(DateTime, nullable=True)
    last_seen_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class DSChunk(Base):
    __tablename__ = "ds_chunks"
    __table_args__ = (
        Index("idx_ds_chunks_file", "file_id"),
        Index("idx_ds_chunks_fts", "fts_vector", postgresql_using="gin"),
    )
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("ds_files.id", ondelete="CASCADE"), nullable=False)
    chunk_index = Column(Integer, default=0)
    content = Column(Text, default="")
    start_offset = Column(Integer, default=0)
    end_offset = Column(Integer, default=0)
    if _IS_POSTGRES:
        fts_vector = Column(
            _DS_TSVECTOR,
            Computed("to_tsvector('simple', content)", persisted=True),
        )
    else:
        fts_vector = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)


class DSLeakRecord(Base):
    __tablename__ = "ds_leak_records"
    __table_args__ = (
        Index("idx_ds_leak_file", "file_id"),
        Index("idx_ds_leak_category", "category"),
        Index("idx_ds_leak_severity", "severity"),
        Index("idx_ds_leak_email", "email"),
        Index("idx_ds_leak_domain", "email_domain"),
        Index("idx_ds_leak_pattern", "pattern_name"),
    )
    id = Column(Integer, primary_key=True)
    file_id = Column(Integer, ForeignKey("ds_files.id", ondelete="CASCADE"), nullable=False)
    chunk_id = Column(Integer, ForeignKey("ds_chunks.id", ondelete="CASCADE"), nullable=True)
    pattern_name = Column(String(120), nullable=False)
    category = Column(String(80), default="")
    severity = Column(Integer, default=0)
    matched_value = Column(Text, default="")
    matched_value_masked = Column(Text, default="")
    context_before = Column(Text, default="")
    context_after = Column(Text, default="")
    line_number = Column(Integer, nullable=True)
    char_offset = Column(Integer, nullable=True)
    email = Column(String(320), default="")
    email_domain = Column(String(255), default="")
    password_plain = Column(Text, default="")
    password_hash = Column(Text, default="")
    hash_type = Column(String(50), default="")
    status = Column(String(20), default="open")
    is_false_positive = Column(Boolean, default=False)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)


class DSMonitoredEntity(Base):
    __tablename__ = "ds_monitored_entities"
    __table_args__ = (
        UniqueConstraint("entity_type", "entity_value", name="uq_ds_monitored_entities_type_value"),
    )
    id = Column(Integer, primary_key=True)
    entity_type = Column(String(50), nullable=False)
    entity_value = Column(String(1024), nullable=False)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


# ── Infrastructure Intelligence ───────────────────────────────────────────────

class InfraInvestigation(Base):
    __tablename__ = "infra_investigations"
    id = Column(Integer, primary_key=True)
    target = Column(String(512), nullable=False)
    target_type = Column(String(50), nullable=False)   # domain | ip | cidr | asn | org
    modules_json = Column(Text, default='["dns","network","cert","cloud"]')
    status = Column(String(20), default="pending")     # pending | running | completed | failed
    summary_json = Column(Text, default="{}")
    error_message = Column(Text, default="")
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    findings = relationship(
        "InfraFinding",
        back_populates="investigation",
        cascade="all, delete-orphan",
        order_by="InfraFinding.severity.desc()",
    )


class InfraFinding(Base):
    __tablename__ = "infra_findings"
    id = Column(Integer, primary_key=True)
    investigation_id = Column(Integer, ForeignKey("infra_investigations.id"), nullable=False)
    module = Column(String(50), nullable=False)        # dns | network | cert | cloud
    finding_type = Column(String(100), nullable=False) # subdomain | open_port | historical_dns | cert_new | bucket_exposed | ...
    entity = Column(String(512), nullable=False)       # discovered entity value
    severity = Column(Integer, default=1)              # 1=info … 5=critical
    source = Column(String(100), default="")           # shodan | censys | crtsh | ...
    data_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=_utcnow)
    investigation = relationship("InfraInvestigation", back_populates="findings")


# ── Look-alike Domains — Brand Protection (TS-LAD-001 v1.1) ──────────────────

class LookalikeRule(Base):
    """Per-brand monitoring rule for look-alike domain detection."""
    __tablename__ = "lookalike_rules"
    id = Column(Integer, primary_key=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=True)
    name = Column(String(200), nullable=False)
    protected_domain = Column(String(253), nullable=False)   # e.g. "kyivstar.ua"
    brand_terms = Column(Text, default="[]")                 # JSON list of terms
    # Generation config
    algorithms = Column(Text, default="[]")                  # JSON list; empty = all
    tld_list = Column(String(20), default="top100")          # top30|top100|top500|full1500
    attack_words = Column(String(20), default="core")        # core|extended
    include_idn = Column(Boolean, default=True)
    include_bitsquatting = Column(Boolean, default=True)
    max_variants = Column(Integer, default=10000)
    similarity_threshold_pct = Column(Integer, default=70)   # 30–100
    alert_threshold = Column(Integer, default=50)            # 30–100
    watch_mode_enabled = Column(Boolean, default=False)
    watch_feed_source = Column(String(50), default="whoisds")
    watch_last_run_at = Column(DateTime, nullable=True)
    watch_alert_email = Column(Text, default="")
    watch_alert_telegram = Column(Text, default="")
    # State
    active = Column(Boolean, default=True)
    last_scan_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    # Relationships
    domains = relationship("LookalikeDomain", back_populates="rule", cascade="all, delete-orphan")
    trusted_domains = relationship("RuleTrustedDomain", back_populates="rule", cascade="all, delete-orphan")


class LookalikeDomain(Base):
    """One row per generated+checked variant domain."""
    __tablename__ = "lookalike_domains"
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("lookalike_rules.id"), nullable=False)
    fqdn = Column(String(253), nullable=False)
    label = Column(String(63), nullable=False)              # part before TLD
    tld = Column(String(63), nullable=False)
    algorithms = Column(Text, default="[]")                 # JSON list of alg IDs
    levenshtein_distance = Column(Integer, nullable=True)
    similarity_score = Column(Float, nullable=True)         # 0.0–1.0 composite score
    is_idn = Column(Boolean, default=False)
    unicode_form = Column(String(253), nullable=True)
    # Status
    status = Column(String(20), default="unregistered")     # unregistered|registered|trusted|error
    # DNS
    dns_checked_at = Column(DateTime, nullable=True)
    has_a_record = Column(Boolean, nullable=True)
    has_mx_record = Column(Boolean, nullable=True)
    has_ns_record = Column(Boolean, nullable=True)
    ip = Column(String(64), nullable=True)
    # HTTP
    http_status = Column(Integer, nullable=True)
    page_title = Column(String(512), nullable=True)
    final_url = Column(String(2048), nullable=True)
    server_header = Column(String(256), nullable=True)
    redirect_detected = Column(Boolean, nullable=True)
    redirects_to_legitimate = Column(Boolean, nullable=True)
    brand_in_title = Column(Boolean, nullable=True)
    phishing_keywords_in_title = Column(Boolean, nullable=True)
    # SSL
    ssl_valid = Column(Boolean, nullable=True)
    ssl_issuer = Column(String(256), nullable=True)
    ssl_uses_lets_encrypt = Column(Boolean, nullable=True)
    ssl_cert_age_days = Column(Integer, nullable=True)
    ssl_is_self_signed = Column(Boolean, nullable=True)
    # GeoIP
    country_code = Column(String(5), nullable=True)
    asn = Column(String(50), nullable=True)
    org = Column(String(256), nullable=True)
    is_high_risk_country = Column(Boolean, nullable=True)
    # WHOIS
    registrar = Column(String(256), nullable=True)
    domain_age_days = Column(Integer, nullable=True)
    whois_privacy = Column(Boolean, nullable=True)
    registrant_org = Column(String(256), nullable=True)
    creation_date = Column(DateTime, nullable=True)
    expiry_date = Column(DateTime, nullable=True)
    # VirusTotal
    vt_malicious = Column(Integer, nullable=True)
    vt_suspicious = Column(Integer, nullable=True)
    vt_harmless = Column(Integer, nullable=True)
    vt_undetected = Column(Integer, nullable=True)
    vt_engines = Column(Text, nullable=True)
    vt_community_score = Column(Integer, nullable=True)
    vt_last_analysis_date = Column(DateTime, nullable=True)
    # Screenshot / visual similarity (Phase 2)
    screenshot_url = Column(Text, nullable=True)
    urlscan_uuid = Column(String(64), nullable=True)
    urlscan_score = Column(Float, nullable=True)
    phash_distance = Column(Integer, nullable=True)
    visual_similarity_pct = Column(Float, nullable=True)
    # Threat score
    threat_score = Column(Integer, nullable=True)           # 0–100
    severity = Column(Integer, nullable=True)               # 1–5
    signals_fired = Column(Text, default="[]")              # JSON list of signal IDs
    # Timestamps
    first_seen_at = Column(DateTime, default=_utcnow)
    last_checked_at = Column(DateTime, nullable=True)
    # False-positive / trusted flag
    is_false_positive = Column(Boolean, default=False)
    fp_reason = Column(String(256), nullable=True)
    rule = relationship("LookalikeRule", back_populates="domains")


class NrdFeedEntry(Base):
    __tablename__ = "nrd_feed_entries"
    __table_args__ = (UniqueConstraint("rule_id", "fqdn"),)

    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("lookalike_rules.id"), nullable=False)
    fqdn = Column(String(253), nullable=False)
    feed_date = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=_utcnow)


class RuleTrustedDomain(Base):
    """Trusted domain registry, scoped per rule (§10.5)."""
    __tablename__ = "rule_trusted_domains"
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("lookalike_rules.id"), nullable=False)
    fqdn_pattern = Column(String(253), nullable=False)
    match_type = Column(String(10), nullable=False, default="exact")  # exact|wildcard|suffix
    reason = Column(Text, nullable=True)
    added_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    verified = Column(Boolean, default=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    rule = relationship("LookalikeRule", back_populates="trusted_domains")


# ── Vulnerability Scanner (TS-VS-001) ─────────────────────────────────────────

class VSScanTarget(Base):
    __tablename__ = "vs_scan_targets"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    target_type = Column(String(20), nullable=False, default="web")  # web | network | api | cidr
    target_value = Column(Text, nullable=False)
    scope = Column(String(20), nullable=False, default="SELF")       # SELF | INTERNAL | THREAT_INTEL
    tags_json = Column(Text, default="[]")
    default_profile = Column(String(20), nullable=False, default="standard")
    schedule_cron = Column(String(100), nullable=True)
    notify_channels_json = Column(Text, default='["email","telegram"]')
    active = Column(Boolean, default=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    scans = relationship("VSScan", back_populates="target", cascade="all, delete-orphan")


class VSScan(Base):
    __tablename__ = "vs_scans"
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey("vs_scan_targets.id"), nullable=False)
    profile = Column(String(20), nullable=False, default="standard")  # quick | standard | deep
    scope = Column(String(20), nullable=False, default="SELF")
    status = Column(String(20), nullable=False, default="pending")
    # pending | running | completed | failed | cancelled
    scanners_used_json = Column(Text, default="[]")
    progress_pct = Column(Integer, default=0)
    findings_total = Column(Integer, default=0)
    findings_critical = Column(Integer, default=0)
    findings_high = Column(Integer, default=0)
    findings_medium = Column(Integer, default=0)
    findings_low = Column(Integer, default=0)
    findings_info = Column(Integer, default=0)
    findings_new = Column(Integer, default=0)
    findings_fixed = Column(Integer, default=0)
    findings_persisted = Column(Integer, default=0)
    overall_risk = Column(String(10), nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    severe_alert_processed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, default="")
    initiated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    comment = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)
    target = relationship("VSScanTarget", back_populates="scans")
    findings = relationship("VSFinding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("VSReport", back_populates="scan", cascade="all, delete-orphan")


class VSFinding(Base):
    __tablename__ = "vs_findings"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("vs_scans.id"), nullable=False)
    target_id = Column(Integer, ForeignKey("vs_scan_targets.id"), nullable=False)

    # Classification
    scanner_source = Column(String(30), nullable=False)        # nuclei|openvas|zap|nikto|testssl|headers|dns_sec
    scanner_finding_id = Column(String(255), default="")
    title = Column(Text, nullable=False)
    description = Column(Text, default="")
    finding_type = Column(String(50), nullable=False)          # CVE|MISCONFIGURATION|EXPOSURE|MISSING_HEADER|SSL_ISSUE|INJECTION|INFORMATION_DISCLOSURE
    owasp_category = Column(String(5), nullable=True)

    # Severity
    severity = Column(String(10), nullable=False, default="INFO")  # CRITICAL|HIGH|MEDIUM|LOW|INFO
    severity_numeric = Column(Integer, nullable=False, default=1)   # 5|4|3|2|1
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(Text, default="")

    # Identifiers
    cve_ids_json = Column(Text, default="[]")
    cwe_ids_json = Column(Text, default="[]")
    wasc_id = Column(String(20), nullable=True)

    # Target details
    target_url = Column(Text, nullable=False, default="")
    target_host = Column(String(512), nullable=False, default="")
    target_ip = Column(String(64), nullable=True)
    target_port = Column(Integer, nullable=True)
    affected_parameter = Column(Text, nullable=True)

    # Evidence
    request_excerpt = Column(Text, nullable=True)
    response_excerpt = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    curl_command = Column(Text, nullable=True)

    # Remediation
    remediation_summary = Column(Text, default="")
    remediation_steps_json = Column(Text, default="[]")
    remediation_effort = Column(String(10), default="MEDIUM")   # LOW|MEDIUM|HIGH
    patch_available = Column(Boolean, default=False)
    patch_url = Column(Text, nullable=True)
    references_json = Column(Text, default="[]")

    # Status
    status = Column(String(30), nullable=False, default="new")  # new|confirmed|false_positive|accepted_risk|remediated|retest_pending
    false_positive_reason = Column(Text, nullable=True)
    accepted_risk_reason = Column(Text, nullable=True)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)

    # Deduplication
    fingerprint = Column(String(64), nullable=False, default="")
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)
    occurrence_count = Column(Integer, default=1)

    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    scan = relationship("VSScan", back_populates="findings")


class VSReport(Base):
    __tablename__ = "vs_reports"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("vs_scans.id"), nullable=False)
    format = Column(String(10), nullable=False)   # pdf | html | json | csv | kql
    file_path = Column(Text, nullable=False, default="")
    file_size_bytes = Column(Integer, nullable=True)
    generated_at = Column(DateTime, default=_utcnow)
    generated_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    expires_at = Column(DateTime, nullable=True)
    scan = relationship("VSScan", back_populates="reports")


class VSCustomTemplate(Base):
    __tablename__ = "vs_custom_templates"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    template_id = Column(String(100), nullable=False, unique=True)
    yaml_content = Column(Text, nullable=False)
    severity = Column(String(10), nullable=False, default="medium")
    tags_json = Column(Text, default="[]")
    is_active = Column(Boolean, default=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)

# ── Impersonation Monitoring (TS-IMP-001) ─────────────────────────────────────

class ImpersonationRule(Base):
    """Per-brand configuration rule for the Impersonation Monitoring module."""
    __tablename__ = "impersonation_rules"
    id = Column(Integer, primary_key=True)
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=True)
    name = Column(String(200), nullable=False)
    brand_name = Column(String(100), nullable=False)
    brand_name_uk = Column(String(100), default="")
    brand_name_ru = Column(String(100), default="")
    official_domains = Column(Text, default="[]")
    official_developer_ids = Column(Text, default="[]")
    executive_names = Column(Text, default="[]")
    partner_domains = Column(Text, default="[]")
    trademark_name = Column(String(200), default="")
    trademark_reg_no = Column(String(100), default="")
    org_name = Column(String(200), default="")
    contact_name = Column(String(200), default="")
    contact_email = Column(String(256), default="")
    contact_phone = Column(String(50), default="")
    m1_social_enabled = Column(Boolean, default=True)
    m2_apps_enabled = Column(Boolean, default=True)
    m3_email_enabled = Column(Boolean, default=True)
    m5_exec_enabled = Column(Boolean, default=True)
    m6_ads_enabled = Column(Boolean, default=True)
    m7_vip_enabled = Column(Boolean, default=True)
    m8_domain_enabled = Column(Boolean, default=True)
    social_platforms = Column(Text, default='["telegram","instagram","vk","facebook"]')
    min_impersonation_score = Column(Integer, default=40)
    schedule_cron = Column(String(100), default="0 */6 * * *")
    active = Column(Boolean, default=True)
    last_scan_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    findings = relationship("ImpersonationFinding", back_populates="rule", cascade="all, delete-orphan")


class ImpersonationFinding(Base):
    """A single detected impersonation threat across any of the 8 modules."""
    __tablename__ = "impersonation_findings"
    id = Column(Integer, primary_key=True)
    rule_id = Column(Integer, ForeignKey("impersonation_rules.id"), nullable=False)
    module = Column(String(10), nullable=False)
    platform = Column(String(50), nullable=False)
    finding_type = Column(String(50), nullable=False)
    target_url = Column(Text, default="")
    target_identifier = Column(String(512), default="")
    display_name = Column(String(512), default="")
    description = Column(Text, default="")
    subscriber_count = Column(Integer, nullable=True)
    threat_score = Column(Integer, default=0)
    signals_json = Column(Text, default="[]")
    evidence_json = Column(Text, default="{}")
    status = Column(String(30), default="new")
    false_positive_reason = Column(Text, nullable=True)
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    fingerprint = Column(String(64), unique=True, nullable=False)
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    rule = relationship("ImpersonationRule", back_populates="findings")


class TakedownRequest(Base):
    """Takedown request generated by the Takedown Automation Engine (M4)."""
    __tablename__ = "takedown_requests"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("impersonation_findings.id"), nullable=False)
    target_platform = Column(String(50), nullable=False)
    target_url = Column(Text, nullable=False)
    cover_letter = Column(Text, default="")
    submission_contact_json = Column(Text, default="{}")
    status = Column(String(30), default="draft")
    submitted_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    submitted_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


# ── Phase 2 Models (TS-IMP-001 v2) ────────────────────────────────────────────

class AlertRule(Base):
    """Escalation rule: auto-dispatch Slack/PagerDuty/Teams when a finding matches criteria."""
    __tablename__ = "impersonation_alert_rules"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    # Matching criteria (all conditions are ANDed; None = match any)
    match_module = Column(String(10), nullable=True)       # e.g. "m1"
    match_finding_type = Column(String(50), nullable=True)  # e.g. "fake_account"
    min_threat_score = Column(Integer, default=80)
    # Notification channels (JSON array of channel configs)
    # e.g. [{"type": "slack", "webhook": "..."}, {"type": "pagerduty", "key": "..."}]
    channels_json = Column(Text, default="[]")
    active = Column(Boolean, default=True)
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class LegalTask(Base):
    """Legal workflow item: UDRP submission, C&D letter, trademark filing, etc."""
    __tablename__ = "impersonation_legal_tasks"
    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("impersonation_findings.id"), nullable=True)
    takedown_id = Column(Integer, ForeignKey("takedown_requests.id"), nullable=True)
    task_type = Column(String(50), nullable=False)  # udrp | cease_and_desist | trademark_filing | other
    title = Column(String(300), nullable=False)
    description = Column(Text, default="")
    status = Column(String(30), default="open")    # open | in_progress | submitted | resolved | closed
    due_date = Column(DateTime, nullable=True)
    assigned_to = Column(Integer, ForeignKey("users.id"), nullable=True)
    external_ref = Column(String(300), default="")  # Jira/Asana ticket ID or external case number
    notes = Column(Text, default="")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class ThreatActor(Base):
    """Repeat threat actor identified through correlated infrastructure."""
    __tablename__ = "impersonation_threat_actors"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)       # internal identifier / alias
    description = Column(Text, default="")
    country_of_origin = Column(String(100), default="")
    known_aliases_json = Column(Text, default="[]")  # JSON list of known aliases
    attack_patterns_json = Column(Text, default="[]")  # JSON list of MITRE ATT&CK patterns
    # Infrastructure fingerprints for correlation
    registrar_names_json = Column(Text, default="[]")
    hosting_asns_json = Column(Text, default="[]")
    registrant_emails_json = Column(Text, default="[]")
    payment_gateways_json = Column(Text, default="[]")
    # Linked finding IDs (denormalised JSON list for fast UI rendering)
    linked_finding_ids_json = Column(Text, default="[]")
    first_seen = Column(DateTime, default=_utcnow)
    last_seen = Column(DateTime, default=_utcnow)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    profile = relationship("ThreatActorProfile", back_populates="actor", uselist=False, cascade="all, delete-orphan")


class ThreatActorProfile(Base):
    """Extended profile attached to a ThreatActor (one-to-one)."""
    __tablename__ = "impersonation_threat_actor_profiles"
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("impersonation_threat_actors.id"), nullable=False, unique=True)
    notes = Column(Text, default="")
    motivation = Column(String(200), default="")   # financial | hacktivism | espionage | unknown
    sophistication = Column(String(50), default="")  # low | medium | high | advanced
    target_sectors_json = Column(Text, default="[]")
    ioc_json = Column(Text, default="[]")          # IP addresses, email addresses, domains as IoCs
    tlp_level = Column(String(10), default="amber")  # white | green | amber | red
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
    actor = relationship("ThreatActor", back_populates="profile")


class ServiceLevelAgreement(Base):
    """SLA definition: expected time-to-respond / time-to-resolve per severity or module."""
    __tablename__ = "impersonation_slas"
    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, default="")
    # Match criteria (None = match any)
    match_module = Column(String(10), nullable=True)
    match_severity = Column(String(20), nullable=True)   # critical | high | medium | low
    # SLA times in minutes
    time_to_detect_min = Column(Integer, default=0)
    time_to_triage_min = Column(Integer, default=240)    # 4 h
    time_to_takedown_min = Column(Integer, default=1440)  # 24 h
    time_to_resolve_min = Column(Integer, default=4320)   # 72 h
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


# Backward-compatible alias used by Phase 2 API contracts/specs.
SLAPolicy = ServiceLevelAgreement


class AuditLogEntry(Base):
    """Immutable audit log for all state changes and user actions."""
    __tablename__ = "impersonation_audit_log"
    id = Column(Integer, primary_key=True)
    actor_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)    # e.g. "finding.status_change"
    entity_type = Column(String(50), nullable=False)  # finding | takedown | rule | alert_rule | legal_task | threat_actor
    entity_id = Column(Integer, nullable=True)
    old_value_json = Column(Text, nullable=True)
    new_value_json = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)


# ── Threat Intelligence (TS-CTI-001 v1.0 MVP) ────────────────────────────────

class CTIIndicator(Base):
    __tablename__ = "cti_indicators"
    __table_args__ = (
        Index("ix_cti_indicators_value", "value"),
        Index("ix_cti_indicators_ioc_type", "ioc_type"),
        Index("ix_cti_indicators_severity", "severity"),
        Index("ix_cti_indicators_score", "score"),
        Index("ix_cti_indicators_false_positive", "is_false_positive"),
    )
    id = Column(Integer, primary_key=True)
    value = Column(String(512), nullable=False)
    ioc_type = Column(String(30), nullable=False, default="general")
    source = Column(String(100), default="")
    score = Column(Integer, default=0)
    severity = Column(String(12), default="LOW")
    country_code = Column(String(8), default="")
    actor_names = Column(Text, default="[]")
    tags_json = Column(Text, default="[]")
    metadata_json = Column(Text, default="{}")
    stix_json = Column(Text, default="{}")
    tlp = Column(String(20), default="TLP:CLEAR")
    is_false_positive = Column(Boolean, default=False)
    false_positive_reason = Column(Text, nullable=True)
    first_seen_at = Column(DateTime, default=_utcnow)
    last_seen_at = Column(DateTime, default=_utcnow)
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class CTIActor(Base):
    __tablename__ = "cti_actors"
    __table_args__ = (
        Index("ix_cti_actors_name", "name"),
        Index("ix_cti_actors_mitre_group_id", "mitre_group_id"),
    )
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    aliases = Column(Text, default="[]")
    mitre_group_id = Column(String(30), default="")
    techniques = Column(Text, default="[]")
    software = Column(Text, default="[]")
    stix_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class CTITechnique(Base):
    __tablename__ = "cti_techniques"
    __table_args__ = (
        UniqueConstraint("technique_id", name="uq_cti_techniques_technique_id"),
        Index("ix_cti_techniques_technique_id", "technique_id"),
    )
    id = Column(Integer, primary_key=True)
    technique_id = Column(String(32), nullable=False)
    name = Column(String(255), nullable=False)
    tactics = Column(Text, default="[]")
    stix_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class CTISIEMMatch(Base):
    __tablename__ = "cti_siem_matches"
    __table_args__ = (
        Index("ix_cti_siem_matches_indicator_id", "indicator_id"),
        Index("ix_cti_siem_matches_severity", "severity"),
        Index("ix_cti_siem_matches_created_at", "created_at"),
    )
    id = Column(Integer, primary_key=True)
    indicator_id = Column(Integer, ForeignKey("cti_indicators.id"), nullable=False)
    indicator_value = Column(String(512), nullable=False)
    severity = Column(String(12), nullable=False, default="LOW")
    sentinel_alert_id = Column(String(128), default="")
    matched_rule = Column(String(255), default="")
    raw_payload = Column(Text, default="{}")
    dispatched_channels = Column(Text, default="[]")
    created_at = Column(DateTime, default=_utcnow)


class CTIVulnIntel(Base):
    __tablename__ = "cti_vuln_intel"
    __table_args__ = (
        Index("ix_cti_vuln_intel_cve", "cve"),
        Index("ix_cti_vuln_intel_epss", "epss"),
        Index("ix_cti_vuln_intel_kev", "is_cisa_kev"),
    )
    id = Column(Integer, primary_key=True)
    cve = Column(String(64), nullable=False)
    epss = Column(Float, default=0.0)
    is_cisa_kev = Column(Boolean, default=False)
    cvss = Column(Float, nullable=True)
    vendor = Column(String(255), default="")
    product = Column(String(255), default="")
    summary = Column(Text, default="")
    stix_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class CTIReport(Base):
    __tablename__ = "cti_reports"
    __table_args__ = (
        Index("ix_cti_reports_title", "title"),
        Index("ix_cti_reports_tlp", "tlp"),
        Index("ix_cti_reports_created_at", "created_at"),
    )
    id = Column(Integer, primary_key=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, default="")
    tlp = Column(String(20), default="TLP:CLEAR")
    report_json = Column(Text, default="{}")
    stix_json = Column(Text, default="{}")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)


class CTISentinelCoverage(Base):
    __tablename__ = "cti_sentinel_coverage"
    __table_args__ = (
        Index("ix_cti_sentinel_coverage_technique_id", "technique_id"),
        Index("ix_cti_sentinel_coverage_state", "state"),
        UniqueConstraint("technique_id", "actor_name", name="uq_cti_sentinel_coverage_technique_actor"),
    )
    id = Column(Integer, primary_key=True)
    technique_id = Column(String(32), nullable=False)
    actor_name = Column(String(255), default="")
    has_sentinel_rule = Column(Boolean, default=False)
    has_recent_activity = Column(Boolean, default=False)
    state = Column(String(30), default="BLIND_SPOT")
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=_utcnow)
    updated_at = Column(DateTime, default=_utcnow, onupdate=_utcnow)
