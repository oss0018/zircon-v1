import threading
import http.server
import ssl
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

from app.config import settings
from app.database import init_db
from app.api import auth, files, search, integrations, monitoring, brand_protection, watchlist, dashboard, cve, deep_search, threat_intel, ti_dashboards, impersonation, storage_sources, social_listening, logo_misuse, infra_intel, lookalike, vulnscan
from app.middleware.security_headers import SecurityHeadersMiddleware

_SPA_HTML_CACHE: str = ""


async def seed_ti_default_dashboard():
    """Seed a default 'Threat Intelligence Overview' dashboard if none exists."""
    import json
    from app.database import AsyncSessionLocal
    from app.models import TIDashboard, TIWidget
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(TIDashboard).limit(1))
        if result.scalar_one_or_none():
            return  # Already seeded

        dashboard = TIDashboard(
            name="Threat Intelligence Overview",
            slug="ti-overview",
            scope="global",
            is_default=True,
        )
        db.add(dashboard)
        await db.flush()  # get dashboard.id without committing

        widgets = [
            TIWidget(
                dashboard_id=dashboard.id,
                type="ti_stats",
                title="Overview",
                params_json="{}",
                layout_json=json.dumps({"x": 0, "y": 0, "w": 12, "h": 1}),
            ),
            TIWidget(
                dashboard_id=dashboard.id,
                type="ti_quick_search",
                title="Quick IOC Search",
                params_json="{}",
                layout_json=json.dumps({"x": 0, "y": 1, "w": 12, "h": 2}),
            ),
            TIWidget(
                dashboard_id=dashboard.id,
                type="ti_recent_lookups",
                title="Recent Lookups",
                params_json=json.dumps({"limit": 10}),
                layout_json=json.dumps({"x": 0, "y": 2, "w": 7, "h": 3}),
            ),
            TIWidget(
                dashboard_id=dashboard.id,
                type="ti_source_distribution",
                title="Lookups by Source (7d)",
                params_json="{}",
                layout_json=json.dumps({"x": 7, "y": 2, "w": 5, "h": 3}),
            ),
        ]
        db.add_all(widgets)
        await db.commit()
        print("[init] Default TI dashboard seeded: 'Threat Intelligence Overview'")


async def create_default_admin():
    from app.database import AsyncSessionLocal
    from app.models import User
    from sqlalchemy import select
    from app.api.auth import hash_password

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.username == "admin"))
        if not result.scalar_one_or_none():
            admin = User(
                username="admin",
                password_hash=hash_password("zircon2026"),
                role="admin",
            )
            db.add(admin)
            await db.commit()
            print("[init] Default admin user created: admin / zircon2026")


def start_http_redirect(http_port: int, https_port: int):
    import re
    from urllib.parse import urlsplit, urlunsplit, quote
    _SAFE_HOST = re.compile(r'^[a-zA-Z0-9._-]{1,253}$')

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            raw_host = self.headers.get("Host", "localhost").split(":")[0]
            host = raw_host if _SAFE_HOST.match(raw_host) else "localhost"
            # Re-encode the path to prevent header injection (encodes CR/LF and other special chars)
            parsed = urlsplit(self.path)
            safe_path = quote(parsed.path, safe="/:@!$&'()*+,;=") + (
                "?" + quote(parsed.query, safe="/:@!$&'()*+,;=") if parsed.query else ""
            )
            location = f"https://{host}:{https_port}{safe_path}"
            self.send_response(301)
            self.send_header("Location", location)
            self.end_headers()

        def log_message(self, format, *args):
            pass  # Suppress access log

    def _run():
        try:
            server = http.server.HTTPServer(("0.0.0.0", http_port), RedirectHandler)
            server.serve_forever()
        except Exception as e:
            print(f"[http-redirect] Failed to start on port {http_port}: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    print(f"[http-redirect] Redirecting HTTP port {http_port} → HTTPS {https_port}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await create_default_admin()
    await seed_ti_default_dashboard()

    from app.services.search_engine import search_engine
    search_engine.init_index()

    from app.services.scheduler import start_scheduler
    start_scheduler()

    start_http_redirect(settings.http_port, settings.https_port)

    # Auto-register leaked_accounts as watched folder
    from app.models import WatchedFolder
    from pathlib import Path
    leaked_dir = Path("leaked_accounts").resolve()
    if leaked_dir.exists():
        from app.database import AsyncSessionLocal
        from sqlalchemy import select
        async with AsyncSessionLocal() as session:
            existing = await session.execute(
                select(WatchedFolder).where(WatchedFolder.path == str(leaked_dir))
            )
            if not existing.scalar_one_or_none():
                folder = WatchedFolder(path=str(leaked_dir))
                session.add(folder)
                await session.commit()

    # Create deep_search_data/ directory if it doesn't exist
    Path(settings.deep_search_dir).mkdir(parents=True, exist_ok=True)

    # Create data/logos/ directory for brand logo uploads
    Path("data/logos").mkdir(parents=True, exist_ok=True)

    # Pre-load SPA HTML into memory to avoid disk I/O on every request
    global _SPA_HTML_CACHE
    _index = Path("app/static/index.html")
    if _index.exists():
        _SPA_HTML_CACHE = _index.read_text(encoding="utf-8")
        print(f"[init] index.html cached ({len(_SPA_HTML_CACHE):,} bytes)")

    yield

    from app.services.scheduler import stop_scheduler
    stop_scheduler()


app = FastAPI(title="Zircon FRT", version="1.0.0", lifespan=lifespan)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8181", "https://localhost:8443",
                   "http://127.0.0.1:8181", "https://127.0.0.1:8443", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

static_dir = Path("app/static")
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(files.router, prefix="/api/v1/files", tags=["files"])
app.include_router(search.router, prefix="/api/v1/search", tags=["search"])
app.include_router(integrations.router, prefix="/api/v1/integrations", tags=["integrations"])
app.include_router(monitoring.router, prefix="/api/v1/monitoring", tags=["monitoring"])
app.include_router(brand_protection.router, prefix="/api/v1/brands", tags=["brands"])
app.include_router(watchlist.router, prefix="/api/v1/watchlist", tags=["watchlist"])
app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["dashboard"])
app.include_router(cve.router, prefix="/api/v1/cve", tags=["cve"])
app.include_router(deep_search.router, prefix="/api/v1/deep-search", tags=["deep-search"])
app.include_router(threat_intel.router, prefix="/api/v1/ti", tags=["threat-intel"])
app.include_router(ti_dashboards.router, prefix="/api/v1/ti-dashboards", tags=["ti-dashboards"])
app.include_router(impersonation.router, prefix="/api/v1/impersonation", tags=["impersonation"])
app.include_router(storage_sources.router, prefix="/api/v1/storage-sources", tags=["storage-sources"])
app.include_router(social_listening.router, prefix="/api/v1/social-listening", tags=["social-listening"])
app.include_router(logo_misuse.router, prefix="/api/v1/logo-misuse", tags=["logo-misuse"])
app.include_router(infra_intel.router, prefix="/api/v1/infra", tags=["infra-intelligence"])
app.include_router(lookalike.router, prefix="/api/v1/lookalike", tags=["lookalike-domains"])
app.include_router(vulnscan.router, prefix="/api/v1/vulnscan", tags=["vulnscan"])


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def serve_spa(full_path: str, request: Request):
    if full_path.startswith("api/") or full_path.startswith("static/"):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    global _SPA_HTML_CACHE
    if _SPA_HTML_CACHE:
        return HTMLResponse(content=_SPA_HTML_CACHE)
    index_path = Path("app/static/index.html")
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>Zircon FRT — Static files not found</h1>")
