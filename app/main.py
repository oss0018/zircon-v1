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
from app.api import auth, files, search, integrations, monitoring, brand_protection, watchlist, dashboard


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
    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(301)
            host = self.headers.get("Host", "localhost").split(":")[0]
            self.send_header("Location", f"https://{host}:{https_port}{self.path}")
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

    from app.services.search_engine import search_engine
    search_engine.init_index()

    from app.services.scheduler import start_scheduler
    start_scheduler()

    start_http_redirect(settings.http_port, settings.https_port)
    yield

    from app.services.scheduler import stop_scheduler
    stop_scheduler()


app = FastAPI(title="Zircon FRT", version="1.0.0", lifespan=lifespan)

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


@app.get("/{full_path:path}", response_class=HTMLResponse)
async def serve_spa(full_path: str, request: Request):
    # Don't intercept API or static routes
    if full_path.startswith("api/") or full_path.startswith("static/"):
        from fastapi.responses import JSONResponse
        return JSONResponse({"detail": "Not Found"}, status_code=404)
    index_path = Path("app/static/index.html")
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text())
    return HTMLResponse("<h1>Zircon FRT — Static files not found</h1>")
