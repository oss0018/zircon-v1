from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Any, Dict, Literal
from datetime import datetime
from pydantic_core import PydanticCustomError
import html as _html
import json


def _sanitize(v: str, max_length: int = 2048) -> str:
    """Strip HTML tags and escape special chars. Applied in schema validators."""
    from app.utils.sanitize import sanitize_string
    return sanitize_string(v, max_length=max_length)


# ── Auth ────────────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: str = "user"

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        return v.strip()[:50]


class UserOut(BaseModel):
    id: int
    username: str
    role: str
    created_at: datetime

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def sanitize_username(cls, v: str) -> str:
        return v.strip()[:50]


# ── Projects ─────────────────────────────────────────────────────────────────
class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = ""

    @field_validator("name", "description")
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=500)


class ProjectOut(BaseModel):
    id: int
    name: str
    description: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Files ────────────────────────────────────────────────────────────────────
class FileOut(BaseModel):
    id: int
    name: str
    original_name: str
    size: int
    mime_type: str
    project_id: Optional[int]
    indexed: bool
    checksum: str
    uploaded_at: datetime
    tags: str

    model_config = {"from_attributes": True}


class FileUpdate(BaseModel):
    name: Optional[str] = None
    tags: Optional[str] = None
    project_id: Optional[int] = None

    @field_validator("name", "tags")
    @classmethod
    def sanitize_fields(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _sanitize(v.strip(), max_length=255)


def _validate_base_url(v: Optional[str]) -> Optional[str]:
    """Validate that base_url, if provided, starts with http:// or https://."""
    if v is None:
        return v
    v = v.strip()[:512]
    if v and not v.startswith(("http://", "https://")):
        from pydantic_core import PydanticCustomError
        raise PydanticCustomError(
            "invalid_url_scheme",
            "Base URL must start with http:// or https://",
        )
    return v


# ── Integrations ──────────────────────────────────────────────────────────────
class IntegrationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    service_type: str
    api_key: str = ""
    base_url: str = ""
    rate_limit: int = 60
    cache_ttl: int = 3600

    @field_validator("name", "service_type")
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=200)

    @field_validator("base_url")
    @classmethod
    def sanitize_base_url(cls, v: str) -> str:
        return _validate_base_url(v) or ""


class IntegrationOut(BaseModel):
    id: int
    name: str
    service_type: str
    base_url: str
    is_active: bool
    rate_limit: int
    cache_ttl: int
    created_at: datetime

    model_config = {"from_attributes": True}


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    rate_limit: Optional[int] = None
    cache_ttl: Optional[int] = None
    is_active: Optional[bool] = None

    @field_validator("base_url")
    @classmethod
    def sanitize_base_url(cls, v: Optional[str]) -> Optional[str]:
        return _validate_base_url(v)


# ── Search ───────────────────────────────────────────────────────────────────
class SearchQuery(BaseModel):
    query: str = Field(..., min_length=1)
    source: str = "local"  # local | osint | deep_search | all
    integrations: List[str] = []
    query_type: str = "general"  # email/domain/ip/url/hash/general
    limit: int = 50
    offset: int = 0
    fuzzy: bool = True

    @field_validator("query")
    @classmethod
    def sanitize_query(cls, v: str) -> str:
        from app.utils.sanitize import sanitize_search_query
        return sanitize_search_query(v.strip())


class SearchResult(BaseModel):
    source: str
    score: float = 0.0
    data: Any
    cached: bool = False


class SearchTemplateCreate(BaseModel):
    name: str
    query: str
    filters_json: str = "{}"
    schedule: str = ""

    @field_validator("name", "query")
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=512)


class SearchTemplateOut(BaseModel):
    id: int
    name: str
    query: str
    filters_json: str
    schedule: str
    is_active: bool
    last_run: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Monitoring ────────────────────────────────────────────────────────────────
class MonitoringJobCreate(BaseModel):
    name: str
    type: str = "unified"
    config_json: Any = "{}"
    schedule: str = "manual"
    is_active: bool = True

    @field_validator("name", "type")
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=200)


class MonitoringJobOut(BaseModel):
    id: int
    name: str
    type: str
    config_json: str
    schedule: str
    is_active: bool
    last_run: Optional[datetime]
    next_run: Optional[datetime]
    created_at: datetime

    model_config = {"from_attributes": True}


class MonitoringRunOut(BaseModel):
    id: int
    job_id: int
    trigger_type: str
    status: str
    findings_count: int
    preview_count: int
    summary_json: str
    error_message: str
    started_at: datetime
    completed_at: Optional[datetime]


class MonitoringFindingOut(BaseModel):
    id: int
    job_id: int
    run_id: int
    check_type: str
    matched_target: str
    source: str
    evidence_json: str
    status: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime


# ── Watchlist ─────────────────────────────────────────────────────────────────
WATCHLIST_ITEM_TYPES = {"email", "domain", "ip", "keyword", "brand"}


class WatchlistItemCreate(BaseModel):
    type: str  # email/domain/keyword/brand/ip
    value: str = Field(..., min_length=1)
    integrations_json: str = "[]"
    alert_email: str = ""
    alert_telegram: str = ""

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        val = (v or "").strip().lower()
        if val not in WATCHLIST_ITEM_TYPES:
            raise PydanticCustomError("invalid_watchlist_type", "Invalid watchlist item type")
        return val

    @field_validator("value")
    @classmethod
    def sanitize_value(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=512)

    @field_validator("alert_email")
    @classmethod
    def sanitize_email(cls, v: str) -> str:
        v = v.strip()[:254]
        return _html.escape(v, quote=True)

    @field_validator("alert_telegram")
    @classmethod
    def sanitize_telegram(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=100)


class WatchlistItemUpdate(BaseModel):
    type: Optional[str] = None
    value: Optional[str] = Field(None, min_length=1)
    integrations_json: Optional[str] = None
    alert_email: Optional[str] = None
    alert_telegram: Optional[str] = None

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        val = v.strip().lower()
        if val not in WATCHLIST_ITEM_TYPES:
            raise PydanticCustomError("invalid_watchlist_type", "Invalid watchlist item type")
        return val

    @field_validator("value")
    @classmethod
    def sanitize_value(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _sanitize(v.strip(), max_length=512)

    @field_validator("alert_email")
    @classmethod
    def sanitize_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()[:254]
        return _html.escape(v, quote=True)

    @field_validator("alert_telegram")
    @classmethod
    def sanitize_telegram(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _sanitize(v.strip(), max_length=100)


class WatchlistItemOut(BaseModel):
    id: int
    type: str
    value: str
    integrations_json: str
    alert_email: str
    alert_telegram: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Brand Protection ──────────────────────────────────────────────────────────
class BrandCreate(BaseModel):
    name: str = Field(..., min_length=1)
    url: str = ""
    keywords: str = ""
    similarity_threshold: float = 0.8
    monitoring_enabled: bool = True

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=200)

    @field_validator("url")
    @classmethod
    def sanitize_url(cls, v: str) -> str:
        from pydantic import field_validator as _fv  # noqa: F401 – used below
        from pydantic_core import PydanticCustomError
        v = v.strip()[:2048]
        if not v:
            return v
        # Only allow http(s) URLs
        if not v.startswith(("http://", "https://")):
            raise PydanticCustomError(
                "invalid_url_scheme",
                "URL must start with http:// or https://",
            )
        return _html.escape(v, quote=True)

    @field_validator("keywords")
    @classmethod
    def sanitize_keywords(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=1000)


class BrandOut(BaseModel):
    id: int
    name: str
    url: str
    keywords: str
    similarity_threshold: float
    monitoring_enabled: bool
    generate_mode: str = "domain"
    generate_limit: int = 1000
    created_at: datetime

    model_config = {"from_attributes": True}


class BrandAlertOut(BaseModel):
    id: int
    brand_id: int
    similar_domain: str
    similarity_score: float
    source: str
    details_json: str
    status: str
    ip: Optional[str] = None
    http_status: Optional[int] = None
    ssl_valid: Optional[bool] = None
    page_title: Optional[str] = None
    similarity_pct: Optional[float] = None
    alive: Optional[bool] = None
    checked_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Look-alike Domains ─────────────────────────────────────────────────────────
class LookalikeRuleOut(BaseModel):
    id: int
    brand_id: int
    name: str
    protected_domain: str
    brand_terms: List[str] = []
    algorithms: List[str] = []
    tld_list: str = "top100"
    attack_words: str = "core"
    include_idn: bool = True
    include_bitsquatting: bool = True
    max_variants: int = 10000
    similarity_threshold_pct: int = 70
    alert_threshold: int = 50
    active: bool = True
    watch_mode_enabled: bool = False
    watch_feed_source: str = "whoisds"
    watch_last_run_at: Optional[datetime] = None
    watch_alert_email: str = ""
    watch_alert_telegram: str = ""
    last_scan_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class LookalikeDomainOut(BaseModel):
    id: int
    rule_id: int
    fqdn: str
    vt_malicious: Optional[int] = None
    vt_suspicious: Optional[int] = None
    vt_harmless: Optional[int] = None
    vt_undetected: Optional[int] = None
    vt_engines: Optional[str] = None
    vt_community_score: Optional[int] = None
    vt_last_analysis_date: Optional[datetime] = None

    model_config = {"from_attributes": True}


# ── Owned / Trusted Domains ───────────────────────────────────────────────────
class OwnedDomainCreate(BaseModel):
    brand_id: int
    domain: str = Field(..., min_length=1, max_length=512)
    match_subdomains: bool = True
    notes: str = Field("", max_length=512)

    @field_validator("domain")
    @classmethod
    def sanitize_domain(cls, v: str) -> str:
        return _sanitize(v.strip().lower(), max_length=512)

    @field_validator("notes")
    @classmethod
    def sanitize_notes(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=512)


class OwnedDomainOut(BaseModel):
    id: int
    brand_id: Optional[int]
    domain: str
    match_subdomains: bool
    notes: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Logo Misuse ───────────────────────────────────────────────────────────────
class LogoMisuseCaseCreate(BaseModel):
    brand_id: int
    source_url: str = Field(..., min_length=1)
    page_title: str = ""
    thumbnail_url: str = ""
    match_type: str = "logo"
    confidence: float = 0.0
    description: str = ""
    detection_source: str = "manual"

    @field_validator("source_url", "page_title", "description")
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=2048)


class LogoMisuseCaseUpdate(BaseModel):
    status: Optional[str] = None
    description: Optional[str] = None
    confidence: Optional[float] = None


class LogoMisuseCaseOut(BaseModel):
    id: int
    brand_id: int
    source_url: str
    page_title: str
    thumbnail_url: str
    match_type: str
    confidence: float
    description: str
    status: str
    detection_source: str
    evidence_json: str
    reported_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class LogoMisuseStats(BaseModel):
    total: int
    by_status: dict
    by_match_type: dict
    by_brand: dict


# ── Social Listening ───────────────────────────────────────────────────────────
class SLRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    brand_id: int
    brand_terms: List[str] = []
    hashtags: List[str] = []
    exclusions: List[str] = []
    languages: List[str] = ["uk", "ru", "en"]
    platforms: List[str] = []
    severity_threshold: int = Field(2, ge=1, le=5)
    alert_on: str = "EVERY_MENTION"
    schedule_cron: str = "*/15 * * * *"
    alert_email: str = ""
    alert_telegram: str = ""
    store_all: bool = False
    active: bool = True

    @field_validator("name", "alert_on", "schedule_cron")
    @classmethod
    def sanitize_text_fields(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=200)

    @field_validator("brand_terms", "hashtags", "exclusions", "languages", "platforms")
    @classmethod
    def sanitize_list_fields(cls, v: List[str]) -> List[str]:
        return [_sanitize(str(item).strip(), max_length=200) for item in v if str(item).strip()]

    @field_validator("alert_email")
    @classmethod
    def sanitize_email(cls, v: str) -> str:
        v = v.strip()[:254]
        return _html.escape(v, quote=True)

    @field_validator("alert_telegram")
    @classmethod
    def sanitize_telegram(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=100)


class SLRuleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    brand_id: Optional[int] = None
    brand_terms: Optional[List[str]] = None
    hashtags: Optional[List[str]] = None
    exclusions: Optional[List[str]] = None
    languages: Optional[List[str]] = None
    platforms: Optional[List[str]] = None
    severity_threshold: Optional[int] = Field(None, ge=1, le=5)
    alert_on: Optional[str] = None
    schedule_cron: Optional[str] = None
    alert_email: Optional[str] = None
    alert_telegram: Optional[str] = None
    store_all: Optional[bool] = None
    active: Optional[bool] = None

    @field_validator("name", "alert_on", "schedule_cron")
    @classmethod
    def sanitize_optional_text_fields(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _sanitize(v.strip(), max_length=200)

    @field_validator("brand_terms", "hashtags", "exclusions", "languages", "platforms")
    @classmethod
    def sanitize_optional_list_fields(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        return [_sanitize(str(item).strip(), max_length=200) for item in v if str(item).strip()]

    @field_validator("alert_email")
    @classmethod
    def sanitize_optional_email(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()[:254]
        return _html.escape(v, quote=True)

    @field_validator("alert_telegram")
    @classmethod
    def sanitize_optional_telegram(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _sanitize(v.strip(), max_length=100)


class SLRuleOut(BaseModel):
    id: int
    name: str
    brand_id: int
    brand_terms: List[str] = []
    hashtags: List[str] = []
    exclusions: List[str] = []
    languages: List[str] = []
    platforms: List[str] = []
    severity_threshold: int
    alert_on: str
    schedule_cron: str
    alert_email: str = ""
    alert_telegram: str = ""
    store_all: bool
    active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class SLMentionOut(BaseModel):
    id: int
    rule_id: int
    raw_id: Optional[int] = None
    source_platform: str
    source_url: str
    source_channel: str
    author_id: str
    author_username: str
    author_reach: int
    content_raw: str
    content_normalized: str
    content_fingerprint: str
    language: str
    sentiment_label: str
    sentiment_score: float
    entities_json: str
    matched_terms_json: str
    threat_indicators_json: str
    relevance_score: float
    severity: int
    engagement_json: str
    status: str
    reviewed_by: Optional[int] = None
    reviewed_at: Optional[datetime] = None
    published_at: Optional[datetime] = None
    collected_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


class SLMentionStatusUpdate(BaseModel):
    status: Literal["new", "reviewed", "fp", "escalated"]


class SLAlertOut(BaseModel):
    id: int
    rule_id: int
    mention_id: Optional[int] = None
    alert_type: str
    severity: int
    title: str
    body: str
    channels_json: str
    status: str
    acknowledged_by: Optional[int] = None
    acknowledged_at: Optional[datetime] = None
    sent_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class SLDashboardStats(BaseModel):
    total_mentions: int
    sentiment_breakdown: Dict[str, int] = {}
    top_platforms: Dict[str, int] = {}


# ── Notifications ─────────────────────────────────────────────────────────────
class NotificationOut(BaseModel):
    id: int
    type: str
    title: str
    message: str
    read: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Watched Folders ───────────────────────────────────────────────────────────
class WatchedFolderCreate(BaseModel):
    path: str


class WatchedFolderOut(BaseModel):
    id: int
    path: str
    is_active: bool
    files_count: int
    last_scan: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Deep Search ───────────────────────────────────────────────────────────────
class DeepSearchFolderInfo(BaseModel):
    name: str
    files_count: int
    size_bytes: int
    created_at: Optional[str] = None


class DeepSearchFileMatch(BaseModel):
    line: int
    text: str


class DeepSearchResult(BaseModel):
    file_path: str
    file_name: str
    matches: List[DeepSearchFileMatch]
    match_count: int


class DeepSearchResponse(BaseModel):
    query: str
    results: List[DeepSearchResult]
    total_files_searched: int
    total_matches: int


# ── TI Dashboards (Variant B) ─────────────────────────────────────────────────
class TIWidgetCreate(BaseModel):
    type: str
    title: str = ""
    params_json: str = "{}"
    layout_json: str = '{"x":0,"y":0,"w":12,"h":2}'

    @field_validator("type", "title")
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=200)


class TIWidgetOut(BaseModel):
    id: int
    dashboard_id: int
    type: str
    title: str
    params_json: str
    layout_json: str

    model_config = {"from_attributes": True}


class TIDashboardCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    slug: str = Field(..., min_length=1, max_length=100)
    scope: str = "global"
    is_default: bool = False

    @field_validator("name", "slug")
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=200)


class TIDashboardOut(BaseModel):
    id: int
    name: str
    slug: str
    scope: str
    is_default: bool
    created_at: datetime
    updated_at: datetime
    widgets: List[TIWidgetOut] = []

    model_config = {"from_attributes": True}



# ── Storage Sources ──────────────────────────────────────────────────────────

class StorageSourceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    source_type: str = Field(..., pattern=r"^(s3|sftp|webdav|localfs|api)$")
    config: dict = {}                       # raw config dict (secrets will be encrypted)
    is_enabled: bool = True
    schedule: str = "@hourly"
    max_file_size_mb: int = Field(25, ge=1, le=100)
    recursive: bool = True

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=100)

    @field_validator("schedule")
    @classmethod
    def sanitize_schedule(cls, v: str) -> str:
        return v.strip()[:50]


class StorageSourceUpdate(BaseModel):
    name: Optional[str] = None
    config: Optional[dict] = None
    is_enabled: Optional[bool] = None
    schedule: Optional[str] = None
    max_file_size_mb: Optional[int] = Field(None, ge=1, le=100)
    recursive: Optional[bool] = None

    @field_validator("name")
    @classmethod
    def sanitize_name(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _sanitize(v.strip(), max_length=100)

    @field_validator("schedule")
    @classmethod
    def sanitize_schedule(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return v.strip()[:50]


class StorageSourceOut(BaseModel):
    id: int
    name: str
    source_type: str
    is_enabled: bool
    schedule: str
    max_file_size_mb: int
    recursive: bool
    last_run_at: Optional[datetime] = None
    last_run_status: str
    last_run_scanned: int
    last_run_indexed: int
    last_run_errors: int
    last_run_error_msg: str = ""
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class StorageFileCatalogOut(BaseModel):
    id: int
    source_id: int
    path: str
    size: int
    mtime: Optional[datetime] = None
    etag: str
    last_indexed_at: Optional[datetime] = None
    status: str
    error: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Dashboard ─────────────────────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_files: int
    indexed_files: int
    total_searches: int
    active_integrations: int
    watchlist_items: int
    active_monitoring_jobs: int
    brand_alerts_new: int
    unread_notifications: int
    recent_searches: List[Any] = []
    file_types: dict = {}

# ── Impersonation Monitoring ────────────────────────────────────────────────────

def _parse_json_list(value):
    if value in (None, ""):
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            parsed = [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    return []


class ImpersonationRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    brand_id: Optional[int] = None
    brand_name: str = Field(..., min_length=1, max_length=100)
    brand_name_uk: str = ""
    brand_name_ru: str = ""
    official_domains: List[str] = []
    official_developer_ids: List[str] = []
    executive_names: List[str] = []
    partner_domains: List[str] = []
    trademark_name: str = ""
    trademark_reg_no: str = ""
    org_name: str = ""
    contact_name: str = ""
    contact_email: str = ""
    contact_phone: str = ""
    m1_social_enabled: bool = True
    m2_apps_enabled: bool = True
    m3_email_enabled: bool = True
    m5_exec_enabled: bool = True
    m6_ads_enabled: bool = True
    m7_vip_enabled: bool = True
    m8_domain_enabled: bool = True
    social_platforms: List[str] = ["telegram", "instagram", "vk", "facebook"]
    min_impersonation_score: int = Field(40, ge=0, le=100)
    schedule_cron: str = "0 */6 * * *"
    active: bool = True


class ImpersonationRuleUpdate(BaseModel):
    name: Optional[str] = None
    brand_name: Optional[str] = None
    brand_name_uk: Optional[str] = None
    brand_name_ru: Optional[str] = None
    official_domains: Optional[List[str]] = None
    official_developer_ids: Optional[List[str]] = None
    executive_names: Optional[List[str]] = None
    partner_domains: Optional[List[str]] = None
    trademark_name: Optional[str] = None
    trademark_reg_no: Optional[str] = None
    org_name: Optional[str] = None
    contact_name: Optional[str] = None
    contact_email: Optional[str] = None
    contact_phone: Optional[str] = None
    m1_social_enabled: Optional[bool] = None
    m2_apps_enabled: Optional[bool] = None
    m3_email_enabled: Optional[bool] = None
    m5_exec_enabled: Optional[bool] = None
    m6_ads_enabled: Optional[bool] = None
    m7_vip_enabled: Optional[bool] = None
    m8_domain_enabled: Optional[bool] = None
    social_platforms: Optional[List[str]] = None
    min_impersonation_score: Optional[int] = Field(None, ge=0, le=100)
    schedule_cron: Optional[str] = None
    active: Optional[bool] = None


class ImpersonationRuleOut(BaseModel):
    id: int
    brand_id: Optional[int]
    name: str
    brand_name: str
    brand_name_uk: str
    brand_name_ru: str
    official_domains: List[str]
    official_developer_ids: List[str]
    executive_names: List[str]
    partner_domains: List[str]
    trademark_name: str
    trademark_reg_no: str
    org_name: str
    contact_name: str
    contact_email: str
    contact_phone: str
    m1_social_enabled: bool
    m2_apps_enabled: bool
    m3_email_enabled: bool
    m5_exec_enabled: bool
    m6_ads_enabled: bool
    m7_vip_enabled: bool
    m8_domain_enabled: bool
    social_platforms: List[str]
    min_impersonation_score: int
    schedule_cron: str
    active: bool
    last_scan_at: Optional[datetime]
    findings_count: int = 0
    created_at: datetime
    updated_at: datetime

    @field_validator("official_domains", "official_developer_ids", "executive_names", "partner_domains", "social_platforms", mode="before")
    @classmethod
    def parse_list_fields(cls, value):
        return _parse_json_list(value)

    model_config = {"from_attributes": True}


class ImpersonationFindingOut(BaseModel):
    id: int
    rule_id: int
    module: str
    platform: str
    finding_type: str
    target_url: str
    target_identifier: str
    display_name: str
    description: str
    subscriber_count: Optional[int]
    threat_score: int
    signals_json: str
    evidence_json: str
    status: str
    false_positive_reason: Optional[str]
    reviewed_by: Optional[int]
    reviewed_at: Optional[datetime]
    fingerprint: str
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class ImpersonationFindingStatusUpdate(BaseModel):
    status: Literal["new", "under_review", "takedown_requested", "resolved", "false_positive"]
    false_positive_reason: Optional[str] = None


class TakedownRequestCreate(BaseModel):
    finding_id: int
    notes: str = ""


class TakedownRequestUpdate(BaseModel):
    status: Optional[Literal["draft", "pending_review", "submitted", "resolved", "completed", "failed"]] = None
    notes: Optional[str] = None


class TakedownRequestOut(BaseModel):
    id: int
    finding_id: int
    target_platform: str
    target_url: str
    cover_letter: str
    submission_contact_json: str
    status: str
    submitted_at: Optional[datetime]
    resolved_at: Optional[datetime]
    submitted_by: Optional[int]
    notes: str
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class ImpersonationStatsByModuleOut(BaseModel):
    total: int = 0
    new: int = 0
    resolved: int = 0


class ImpersonationStatsOut(BaseModel):
    total: int = 0
    high_risk: int = 0
    pending_takedowns: int = 0
    active_rules: int = 0
    by_module: Dict[str, ImpersonationStatsByModuleOut] = Field(default_factory=dict)
    by_status: Dict[str, int] = Field(default_factory=dict)
    by_platform: Dict[str, int] = Field(default_factory=dict)
    score_bands: Dict[str, int] = Field(default_factory=dict)
    trend_14d: List[Dict[str, int | str]] = Field(default_factory=list)


# ── Phase 2 Schemas (TS-IMP-001 v2) ──────────────────────────────────────────

class AlertRuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    match_module: Optional[str] = None
    match_finding_type: Optional[str] = None
    min_threat_score: int = Field(80, ge=0, le=100)
    channels_json: str = "[]"
    active: bool = True


class AlertRuleUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    match_module: Optional[str] = None
    match_finding_type: Optional[str] = None
    min_threat_score: Optional[int] = Field(None, ge=0, le=100)
    channels_json: Optional[str] = None
    active: Optional[bool] = None


class AlertRuleOut(BaseModel):
    id: int
    name: str
    description: str
    match_module: Optional[str]
    match_finding_type: Optional[str]
    min_threat_score: int
    channels_json: str
    active: bool
    created_by: Optional[int]
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class LegalTaskCreate(BaseModel):
    finding_id: Optional[int] = None
    takedown_id: Optional[int] = None
    task_type: str = Field(..., min_length=1, max_length=50)
    title: str = Field(..., min_length=1, max_length=300)
    description: str = ""
    status: str = "open"
    due_date: Optional[datetime] = None
    assigned_to: Optional[int] = None
    external_ref: str = ""
    notes: str = ""


class LegalTaskUpdate(BaseModel):
    task_type: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    due_date: Optional[datetime] = None
    assigned_to: Optional[int] = None
    external_ref: Optional[str] = None
    notes: Optional[str] = None


class LegalTaskOut(BaseModel):
    id: int
    finding_id: Optional[int]
    takedown_id: Optional[int]
    task_type: str
    title: str
    description: str
    status: str
    due_date: Optional[datetime]
    assigned_to: Optional[int]
    external_ref: str
    notes: str
    created_by: Optional[int]
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class ThreatActorCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    country_of_origin: str = ""
    known_aliases: List[str] = []
    attack_patterns: List[str] = []
    registrar_names: List[str] = []
    hosting_asns: List[str] = []
    registrant_emails: List[str] = []
    payment_gateways: List[str] = []
    linked_finding_ids: List[int] = []


class ThreatActorUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    country_of_origin: Optional[str] = None
    known_aliases: Optional[List[str]] = None
    attack_patterns: Optional[List[str]] = None
    registrar_names: Optional[List[str]] = None
    hosting_asns: Optional[List[str]] = None
    registrant_emails: Optional[List[str]] = None
    payment_gateways: Optional[List[str]] = None
    linked_finding_ids: Optional[List[int]] = None


class ThreatActorOut(BaseModel):
    id: int
    name: str
    description: str
    country_of_origin: str
    known_aliases: List[str]
    attack_patterns: List[str]
    registrar_names: List[str]
    hosting_asns: List[str]
    registrant_emails: List[str]
    payment_gateways: List[str]
    linked_finding_ids: List[int]
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime

    @field_validator(
        "known_aliases", "attack_patterns", "registrar_names",
        "hosting_asns", "registrant_emails", "payment_gateways",
        mode="before",
    )
    @classmethod
    def parse_str_list(cls, value):
        return _parse_json_list(value)

    @field_validator("linked_finding_ids", mode="before")
    @classmethod
    def parse_int_list(cls, value):
        if isinstance(value, list):
            return [int(x) for x in value if x is not None]
        try:
            parsed = json.loads(value or "[]")
            return [int(x) for x in parsed if x is not None]
        except Exception:
            return []

    model_config = {"from_attributes": True}


class ThreatActorProfileCreate(BaseModel):
    actor_id: int
    notes: str = ""
    motivation: str = ""
    sophistication: str = ""
    target_sectors: List[str] = []
    ioc: List[str] = []
    tlp_level: str = "amber"


class ThreatActorProfileUpdate(BaseModel):
    notes: Optional[str] = None
    motivation: Optional[str] = None
    sophistication: Optional[str] = None
    target_sectors: Optional[List[str]] = None
    ioc: Optional[List[str]] = None
    tlp_level: Optional[str] = None


class ThreatActorProfileOut(BaseModel):
    id: int
    actor_id: int
    notes: str
    motivation: str
    sophistication: str
    target_sectors: List[str]
    ioc: List[str]
    tlp_level: str
    created_at: datetime
    updated_at: datetime

    @field_validator("target_sectors", "ioc", mode="before")
    @classmethod
    def parse_list(cls, value):
        return _parse_json_list(value)

    model_config = {"from_attributes": True}


class ServiceLevelAgreementCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = ""
    match_module: Optional[str] = None
    match_severity: Optional[str] = None
    time_to_detect_min: int = Field(0, ge=0)
    time_to_triage_min: int = Field(240, ge=0)
    time_to_takedown_min: int = Field(1440, ge=0)
    time_to_resolve_min: int = Field(4320, ge=0)
    active: bool = True


class ServiceLevelAgreementUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    match_module: Optional[str] = None
    match_severity: Optional[str] = None
    time_to_detect_min: Optional[int] = Field(None, ge=0)
    time_to_triage_min: Optional[int] = Field(None, ge=0)
    time_to_takedown_min: Optional[int] = Field(None, ge=0)
    time_to_resolve_min: Optional[int] = Field(None, ge=0)
    active: Optional[bool] = None


class ServiceLevelAgreementOut(BaseModel):
    id: int
    name: str
    description: str
    match_module: Optional[str]
    match_severity: Optional[str]
    time_to_detect_min: int
    time_to_triage_min: int
    time_to_takedown_min: int
    time_to_resolve_min: int
    active: bool
    created_at: datetime
    updated_at: datetime
    model_config = {"from_attributes": True}


class SLAPolicyCreate(ServiceLevelAgreementCreate):
    pass


class SLAPolicyUpdate(ServiceLevelAgreementUpdate):
    pass


class SLAPolicyOut(ServiceLevelAgreementOut):
    pass


class AuditLogEntryOut(BaseModel):
    id: int
    actor_user_id: Optional[int]
    action: str
    entity_type: str
    entity_id: Optional[int]
    old_value_json: Optional[str]
    new_value_json: Optional[str]
    ip_address: Optional[str]
    notes: str
    created_at: datetime
    model_config = {"from_attributes": True}


class EvidencePackageRequest(BaseModel):
    include_screenshot: bool = True
    include_whois: bool = True
    include_dns: bool = True
    include_archive: bool = True
    narrative: str = ""


# ── Deep Search Query API — TS-DS-001 Phase 1 (PR 3/4) ──────────────────────

class SearchHitSchema(BaseModel):
    chunk_id: int
    file_id: int
    source_id: int
    file_path: str
    chunk_index: int
    snippet: str
    rank: float
    file_severity_max: Optional[int]
    file_has_credentials: bool
    file_has_pii: bool
    file_has_api_keys: bool
    file_pattern_names: List[str]
    file_indexed_at: Optional[datetime]

    model_config = {"from_attributes": True}


class SearchResponseSchema(BaseModel):
    items: List[SearchHitSchema]
    total: int
    page: int
    page_size: int
    has_next: bool


class LeakSummarySchema(BaseModel):
    total: int
    severity_max: Optional[int]
    by_pattern: Dict[str, int]
    by_category: Dict[str, int]


class ChunkPreviewSchema(BaseModel):
    chunk_id: int
    chunk_index: int
    snippet: str
    start_offset: int
    end_offset: int


class FileDetailSchema(BaseModel):
    file: Dict[str, Any]
    leak_summary: LeakSummarySchema
    chunks_preview: List[ChunkPreviewSchema]


class ChunkItemSchema(BaseModel):
    chunk_id: int
    chunk_index: int
    content: str
    start_offset: int
    end_offset: int


class ChunkListSchema(BaseModel):
    items: List[ChunkItemSchema]
    total: int
    has_next: bool


class LeakItemSchema(BaseModel):
    leak_id: int
    file_id: int
    file_path: str
    source_id: int
    pattern_name: str
    category: str
    severity: int
    matched_value_masked: str
    line_number: Optional[int]
    context_before: str
    context_after: str
    email: str
    email_domain: str
    detected_at: Optional[datetime]


class LeakListSchema(BaseModel):
    items: List[LeakItemSchema]
    total: int
    page: int
    page_size: int
    has_next: bool
