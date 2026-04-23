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


# ── Integrations ──────────────────────────────────────────────────────────────
class IntegrationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    service_type: str
    api_key: str = ""
    rate_limit: int = 60
    cache_ttl: int = 3600

    @field_validator("name", "service_type")
    @classmethod
    def sanitize_fields(cls, v: str) -> str:
        return _sanitize(v.strip(), max_length=200)


class IntegrationOut(BaseModel):
    id: int
    name: str
    service_type: str
    is_active: bool
    rate_limit: int
    cache_ttl: int
    created_at: datetime

    model_config = {"from_attributes": True}


class IntegrationUpdate(BaseModel):
    name: Optional[str] = None
    api_key: Optional[str] = None
    rate_limit: Optional[int] = None
    cache_ttl: Optional[int] = None
    is_active: Optional[bool] = None


# ── Search ───────────────────────────────────────────────────────────────────
class SearchQuery(BaseModel):
    query: str = Field(..., min_length=1)
    source: str = "local"  # local | osint | all
    integrations: List[str] = []
    query_type: str = "general"  # email/domain/ip/url/hash/general
    limit: int = 50

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
    type: str
    config_json: str = "{}"
    schedule: str = "*/15 * * * *"

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
