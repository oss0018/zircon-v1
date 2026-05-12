from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Any
from datetime import datetime
import html as _html


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
    source: str = "local"  # local | osint | all
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
class WatchlistItemCreate(BaseModel):
    type: str  # email/domain/keyword/brand/ip
    value: str = Field(..., min_length=1)
    integrations_json: str = "[]"
    alert_email: str = ""
    alert_telegram: str = ""

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
    source_type: str = Field(..., pattern=r"^(s3|sftp|webdav)$")
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
