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
    created_at = Column(DateTime, default=_utcnow)
    alerts = relationship("BrandAlert", back_populates="brand")
    owned_domains = relationship("OwnedDomain", back_populates="brand", cascade="all, delete-orphan")


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
