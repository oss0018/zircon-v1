from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, Text, ForeignKey, BigInteger
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.database import Base


def _utcnow():
    return datetime.now(timezone.utc)


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
    brand_id = Column(Integer, ForeignKey("brands.id"), nullable=False)
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
