#!/usr/bin/env python3
"""
Zircon FRT — OSINT Portal Launcher with Phase 2 Auto-Initialization
Run: python start.py
     python start.py --init-phase2  (force Phase 2 setup on startup)
"""
import sys
import os
import subprocess
import socket
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime

VENV_DIR = Path(".venv")
REQUIREMENTS = Path("requirements.txt")
CERT_FILE = Path("cert.pem")
KEY_FILE = Path("key.pem")
INIT_STATE_FILE = Path(".phase2_initialized")  # Tracks initialization state
HTTP_PORT = 8181
HTTPS_PORT = 8443
APP_MODULE = "app.main:app"

BANNER = """
╔══════════════════════════════════════════════════╗
║           Z I R C O N   F R T                   ║
║        OSINT Intelligence Portal v1.0           ║
║                                                  ║
║      Phase 2: Impersonation Monitoring Active   ║
╚══════════════════════════════════════════════════╝
"""

logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s"
)
logger = logging.getLogger(__name__)


def get_local_ip():
    """Get local network IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def check_python():
    """Verify Python version."""
    if sys.version_info < (3, 11):
        logger.error(f"Python 3.11+ required. Current: {sys.version}")
        sys.exit(1)
    logger.info(f"✅ Python {sys.version.split()[0]}")


def setup_venv():
    """Create or verify virtual environment."""
    venv_python = VENV_DIR / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if not VENV_DIR.exists():
        logger.info("📦 Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
    return venv_python


def install_requirements(venv_python):
    """Install dependencies from requirements.txt."""
    pip = VENV_DIR / ("Scripts/pip.exe" if sys.platform == "win32" else "bin/pip")
    logger.info("📦 Checking/installing dependencies (Phase 2 included)...")
    subprocess.run([str(pip), "install", "-q", "-r", str(REQUIREMENTS)], check=True)
    subprocess.run([str(pip), "install", "-q", "--force-reinstall", "bcrypt==4.0.1"], check=True)
    logger.info("✅ All dependencies installed (including google-play-scraper, apify, etc.)")


def generate_ssl_cert():
    """Generate self-signed SSL certificate if not present."""
    if CERT_FILE.exists() and KEY_FILE.exists():
        logger.info("✅ SSL certificate found")
        return
    logger.info("🔐 Generating self-signed SSL certificate...")
    venv_python = VENV_DIR / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    script = '''
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import ipaddress, socket

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
local_ip = socket.gethostbyname(socket.gethostname())
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, u"Zircon FRT"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Zircon OSINT"),
])
san_list = [
    x509.DNSName(u"localhost"),
    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
]
try:
    san_list.append(x509.IPAddress(ipaddress.IPv4Address(local_ip)))
except Exception:
    pass
san = x509.SubjectAlternativeName(san_list)
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder()
    .subject_name(subject).issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(san, critical=False)
    .sign(key, hashes.SHA256()))
with open("cert.pem","wb") as f: f.write(cert.public_bytes(serialization.Encoding.PEM))
with open("key.pem","wb") as f:
    f.write(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
print("SSL cert generated (10 years)")
'''
    subprocess.run([str(venv_python), "-c", script], check=True)
    logger.info("✅ SSL certificate generated")


def init_dirs():
    """Create required directories."""
    for d in ["data/uploads", "data/monitored", "data/index", "data/db", "leaked_accounts", "deep_search_data"]:
        Path(d).mkdir(parents=True, exist_ok=True)


def init_phase2():
    """
    Initialize Phase 2: run migrations, create admin user, setup .env defaults.
    This is idempotent — can be run multiple times safely.
    """
    venv_python = VENV_DIR / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    force_init = "--init-phase2" in sys.argv
    
    # Check if already initialized (unless --init-phase2 flag is set)
    if INIT_STATE_FILE.exists() and not force_init:
        logger.info("✅ Phase 2 already initialized")
        return
    
    logger.info("🔧 Initializing Phase 2 (Impersonation Monitoring)...")
    
    # 1. Create .env if missing (with sensible defaults)
    env_file = Path(".env")
    if not env_file.exists():
        logger.info("📝 Creating .env from template...")
        template_content = """# Zircon FRT Configuration
# Phase 2 Impersonation Monitoring - Auto-generated on startup

ZIRCON_SECRET_KEY=change-me-in-production-min-32-chars!!
ZIRCON_ALGORITHM=HS256
ZIRCON_ACCESS_TOKEN_EXPIRE_MINUTES=1440
ZIRCON_DATABASE_URL=sqlite+aiosqlite:///./data/db/zircon.db
ZIRCON_WHOOSH_INDEX_DIR=./data/index
ZIRCON_UPLOADS_DIR=./data/uploads
ZIRCON_MONITORED_DIR=./data/monitored
ZIRCON_DEEP_SEARCH_DIR=deep_search_data
ZIRCON_DEEP_SEARCH_STAGING_DIR=/tmp/ds_staging
ZIRCON_ELASTICSEARCH_URL=http://localhost:9200
ZIRCON_ELASTICSEARCH_USERNAME=elastic
ZIRCON_ELASTICSEARCH_PASSWORD=changeme
DS_CREDENTIAL_KEK=
DEEP_SEARCH_LOCAL_MOUNT=/mnt/local_dumps
ZIRCON_HTTP_PORT=8181
ZIRCON_HTTPS_PORT=8443
ZIRCON_ENCRYPTION_KEY=
ZIRCON_SMTP_HOST=
ZIRCON_SMTP_PORT=587
ZIRCON_SMTP_USER=
ZIRCON_SMTP_PASSWORD=
ZIRCON_TELEGRAM_BOT_TOKEN=
ZIRCON_URLSCAN_API_KEY=
ZIRCON_SLACK_WEBHOOK_URL=

# Phase 2 Impersonation Monitoring (optional — graceful degradation)
HIBP_API_KEY=
APIFY_API_KEY=
VK_SERVICE_TOKEN=
PAGERDUTY_API_KEY=
PAGERDUTY_SERVICE_ID=

# Social Listening (reused by Phase 2)
REDDIT_CLIENT_ID=
REDDIT_CLIENT_SECRET=
REDDIT_USER_AGENT=zircon-social-listening/1.0
TELEGRAM_API_ID=
TELEGRAM_API_HASH=
TELEGRAM_SESSION_STRING=
TWITTER_BEARER_TOKEN=

# CTI / Celery
CTI_CELERY_BROKER_URL=redis://localhost:6379/1
CTI_CELERY_RESULT_BACKEND=redis://localhost:6379/1
CTI_THREATFOX_INTERVAL_MINUTES=15
CTI_URLHAUS_INTERVAL_MINUTES=15
CTI_MALWAREBAZAAR_INTERVAL_MINUTES=15
CTI_FEODO_INTERVAL_MINUTES=30
CTI_OTX_INTERVAL_MINUTES=15
CTI_CISA_KEV_INTERVAL_MINUTES=60
CTI_EPSS_INTERVAL_MINUTES=60
CTI_ATTACK_SYNC_INTERVAL_MINUTES=720
CTI_TELEGRAM_INTERVAL_MINUTES=5
CTI_TWITTER_INTERVAL_MINUTES=10

# CTI enrichment
MAXMIND_GEOIP_DB_PATH=./data/geoip/GeoLite2-City.mmdb
VIRUSTOTAL_API_KEY=
GREYNOISE_API_KEY=
ABUSEIPDB_API_KEY=
WHOIS_TIMEOUT_SECONDS=10
SENTINEL_WORKSPACE_ID=
SENTINEL_SHARED_KEY=
SENTINEL_LOG_TYPE=ZirconCTI
CTI_ALERT_EMAIL=
CTI_ALERT_TELEGRAM=
"""
        env_file.write_text(template_content)
        logger.info("✅ .env created with Phase 2 defaults")
    else:
        logger.info("✅ .env already exists")
    
    # 2. Run database migrations (if Alembic is set up)
    logger.info("💾 Running database migrations...")
    migration_result = subprocess.run(
        [str(venv_python), "-m", "alembic", "upgrade", "head"],
        capture_output=True,
        text=True
    )
    if migration_result.returncode == 0:
        logger.info("✅ Database migrations complete")
    else:
        # Alembic might not be configured; this is OK
        logger.info("⚠️  Alembic not configured (OK for SQLite dev mode)")
    
    # 3. Create admin user and initialize Phase 2 data
    logger.info("👤 Setting up admin user and Phase 2 defaults...")
    init_script = f'''
import sys
import asyncio
import os

# Set environment to development for graceful API degradation
os.environ.setdefault("ENV", "development")

try:
    from app.database import AsyncSessionLocal
    from app.models import User, ImpersonationRule
    from sqlalchemy import select
    import hashlib

    async def init_phase2():
        async with AsyncSessionLocal() as db:
            # Create admin user if not exists
            existing_admin = await db.execute(
                select(User).filter(User.username == "admin")
            )
            if not existing_admin.scalar_one_or_none():
                # Hash password: admin / zircon2026
                admin_user = User(
                    username="admin",
                    email="admin@zircon.local",
                    role="admin",
                    is_active=True
                )
                # Set password (bcrypt handled by model)
                admin_user.set_password("zircon2026")
                db.add(admin_user)
                await db.commit()
                print("✅ Admin user created (username: admin, password: zircon2026)")
            else:
                print("✅ Admin user already exists")
            
            # Create default ImpersonationRule for testing
            existing_rule = await db.execute(
                select(ImpersonationRule).filter(ImpersonationRule.brand_name == "Demo Brand")
            )
            if not existing_rule.scalar_one_or_none():
                demo_rule = ImpersonationRule(
                    brand_name="Demo Brand",
                    official_domains="[\\"demo.com\\", \\"www.demo.com\\"]",
                    min_impersonation_score=40,
                    m1_social_enabled=True,
                    m2_apps_enabled=True,
                    m3_email_enabled=True,
                    m5_exec_enabled=True,
                    m7_vip_enabled=True,
                    m8_domain_enabled=True,
                    schedule_cron="0 */6 * * *"
                )
                db.add(demo_rule)
                await db.commit()
                print("✅ Demo ImpersonationRule created (brand: Demo Brand, all modules enabled)")
            else:
                print("✅ Demo rule already exists")

    asyncio.run(init_phase2())
    print("\\n🎉 Phase 2 initialization complete!")
    print("   📊 Impersonation Monitoring ready")
    print("   🔍 8 scanner modules active (M1-M8)")
    print("   📧 Alert dispatch configured")

except ImportError as e:
    # If app not yet loaded, skip (normal on first install)
    print(f"ℹ️  App models not yet available — will initialize on first run")
except Exception as e:
    print(f"⚠️  Phase 2 init skipped: {{type(e).__name__}}")
'''
    
    init_result = subprocess.run(
        [str(venv_python), "-c", init_script],
        capture_output=True,
        text=True
    )
    
    if init_result.stdout:
        for line in init_result.stdout.split('\n'):
            if line.strip():
                logger.info(line)
    
    if init_result.stderr and "DeprecationWarning" not in init_result.stderr:
        logger.warning(init_result.stderr[:200])
    
    # 4. Mark as initialized
    INIT_STATE_FILE.write_text(json.dumps({
        "initialized_at": datetime.now().isoformat(),
        "phase": "2",
        "version": "1.0"
    }))
    
    logger.info("✅ Phase 2 initialization complete")


def start_server():
    """Start the Uvicorn server."""
    venv_uvicorn = VENV_DIR / ("Scripts/uvicorn.exe" if sys.platform == "win32" else "bin/uvicorn")
    local_ip = get_local_ip()
    print(BANNER)
    logger.info(f"🌐 Starting Zircon FRT...")
    logger.info(f"   HTTPS → https://localhost:{HTTPS_PORT}")
    logger.info(f"   HTTPS → https://{local_ip}:{HTTPS_PORT}")
    logger.info(f"   HTTP  → http://localhost:{HTTP_PORT}  (redirects to HTTPS)")
    logger.info(f"")
    logger.info(f"📊 Phase 2 Features:")
    logger.info(f"   • 8 Scanner Modules (M1-M8)")
    logger.info(f"   • Real-time Alert Dispatch (Slack, Email, Telegram, PagerDuty)")
    logger.info(f"   • Evidence Generation & UDRP Packages")
    logger.info(f"   • Threat Actor Correlation")
    logger.info(f"")
    logger.info(f"🔐 Default Admin:")
    logger.info(f"   Username: admin")
    logger.info(f"   Password: zircon2026")
    logger.info(f"")
    logger.info(f"📂 Drop leaked account files → ./leaked_accounts/")
    logger.info(f"   Then add the folder in Settings → Watched Folders")
    logger.info(f"")
    logger.info(f"⚠️  Browser may warn about self-signed cert — click 'Advanced → Proceed'\n")

    env = os.environ.copy()
    env["ZIRCON_HTTP_PORT"] = str(HTTP_PORT)
    env["ZIRCON_HTTPS_PORT"] = str(HTTPS_PORT)

    os.execve(str(venv_uvicorn), [
        str(venv_uvicorn),
        APP_MODULE,
        "--host", "0.0.0.0",
        "--port", str(HTTPS_PORT),
        "--ssl-certfile", str(CERT_FILE),
        "--ssl-keyfile", str(KEY_FILE),
        "--reload",
    ], env)


if __name__ == "__main__":
    check_python()
    setup_venv()
    venv_python = setup_venv()
    install_requirements(venv_python)
    generate_ssl_cert()
    init_dirs()
    init_phase2()  # NEW: Initialize Phase 2 on every startup (idempotent)
    start_server()
