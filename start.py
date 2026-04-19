#!/usr/bin/env python3
"""
Zircon FRT — OSINT Portal Launcher
Run: python start.py
"""
import sys, os, subprocess, socket
from pathlib import Path

VENV_DIR = Path(".venv")
REQUIREMENTS = Path("requirements.txt")
CERT_FILE = Path("cert.pem")
KEY_FILE = Path("key.pem")
HTTP_PORT = 8181
HTTPS_PORT = 8443
APP_MODULE = "app.main:app"

BANNER = """
╔══════════════════════════════════════════════════╗
║           Z I R C O N   F R T                   ║
║        OSINT Intelligence Portal v1.0           ║
╚══════════════════════════════════════════════════╝
"""

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def check_python():
    if sys.version_info < (3, 11):
        print(f"❌ Python 3.11+ required. Current: {sys.version}")
        sys.exit(1)
    print(f"✅ Python {sys.version.split()[0]}")

def setup_venv():
    venv_python = VENV_DIR / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    if not VENV_DIR.exists():
        print("📦 Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
    return venv_python

def install_requirements(venv_python):
    pip = VENV_DIR / ("Scripts/pip.exe" if sys.platform == "win32" else "bin/pip")
    print("📦 Checking/installing dependencies...")
    subprocess.run([str(pip), "install", "-q", "-r", str(REQUIREMENTS)], check=True)
    subprocess.run([str(pip), "install", "-q", "--force-reinstall", "bcrypt==4.0.1"], check=True)
    print("✅ All dependencies installed")

def generate_ssl_cert():
    if CERT_FILE.exists() and KEY_FILE.exists():
        print("✅ SSL certificate found")
        return
    print("🔐 Generating self-signed SSL certificate...")
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
    print("✅ SSL certificate generated")

def init_dirs():
    for d in ["data/uploads", "data/monitored", "data/index", "data/db"]:
        Path(d).mkdir(parents=True, exist_ok=True)

def start_server():
    venv_uvicorn = VENV_DIR / ("Scripts/uvicorn.exe" if sys.platform == "win32" else "bin/uvicorn")
    local_ip = get_local_ip()
    print(BANNER)
    print(f"🌐 Starting Zircon FRT...")
    print(f"   HTTPS → https://localhost:{HTTPS_PORT}")
    print(f"   HTTPS → https://{local_ip}:{HTTPS_PORT}")
    print(f"   HTTP  → http://localhost:{HTTP_PORT}  (redirects to HTTPS)")
    print(f"\n⚠️  Browser may warn about self-signed cert — click 'Advanced → Proceed'\n")

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
    install_requirements(setup_venv())
    generate_ssl_cert()
    init_dirs()
    start_server()
