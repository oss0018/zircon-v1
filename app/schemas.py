from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime


# ── Auth ────────────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    role: str = "user"


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


# ── Projects ─────────────────────────────────────────────────────────────────
class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = ""


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


# ── Integrations ──────────────────────────────────────────────────────────────
class IntegrationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    service_type: str
    api_key: str = ""
    rate_limit: int = 60
    cache_ttl: int = 3600


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
