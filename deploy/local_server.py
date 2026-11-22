"""Run an isolated HTTPS instance for testing on a local network."""
import argparse
import base64
import ipaddress
import json
import os
import secrets
import socket
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy.engine import URL


ROOT = Path(__file__).resolve().parent.parent


def _private_directory(path: Path) -> None:
    created = not path.exists()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.is_dir():
        raise ValueError(f"Not a directory: {path}")
    if os.name == "nt" and created:
        import csv
        import io

        result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                                check=True, capture_output=True, text=True)
        sid = next(csv.reader(io.StringIO(result.stdout)))[1]
        subprocess.run(["icacls", str(path), "/inheritance:r", "/grant:r",
                        f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"],
                       check=True, capture_output=True)
    elif os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError(f"Data directory must not be accessible to group or other users: {path}")


def _write_private(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)


def _create_certificate(cert_path: Path, key_path: Path, bind: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname())])
    names = [x509.DNSName("localhost"), x509.DNSName(socket.gethostname()),
             x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
             x509.IPAddress(ipaddress.ip_address(bind))]
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .sign(key, hashes.SHA256()))
    _write_private(key_path, key.private_bytes(serialization.Encoding.PEM,
                   serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    _write_private(cert_path, cert.public_bytes(serialization.Encoding.PEM))


def prepare(data_dir: Path, bind: str) -> dict[str, str]:
    _private_directory(data_dir)
    config_path = data_dir / "keys.json"
    password_path = data_dir / "initial-admin-password.txt"
    cert_path = data_dir / "cert.pem"
    key_path = data_dir / "key.pem"
    if not config_path.exists():
        if any(data_dir.iterdir()):
            raise RuntimeError("Data directory is not empty but keys.json is missing; refusing initialization")
        config = {
            "secret_key": secrets.token_urlsafe(48),
            "encryption_key": Fernet.generate_key().decode("ascii"),
            "credential_kek": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        }
        _write_private(config_path, json.dumps(config).encode("utf-8"))
        _write_private(password_path, secrets.token_urlsafe(24).encode("ascii"))
        _create_certificate(cert_path, key_path, bind)
    else:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        if not all(path.is_file() for path in (password_path, cert_path, key_path)):
            raise RuntimeError("Local configuration is incomplete; restore the missing files from backup")
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if ipaddress.ip_address(bind) not in names.get_values_for_type(x509.IPAddress):
        raise RuntimeError("The TLS certificate does not cover the bind address; install a matching certificate")
    for name in ("db", "index", "uploads", "monitored", "deep-search", "staging", "vulnscan-reports"):
        (data_dir / name).mkdir(exist_ok=True)
    return {
        "ZIRCON_DATABASE_URL": str(URL.create("sqlite+aiosqlite", database=str(data_dir / "db" / "zircon.db"))),
        "ZIRCON_WHOOSH_INDEX_DIR": str(data_dir / "index"),
        "ZIRCON_UPLOADS_DIR": str(data_dir / "uploads"),
        "ZIRCON_MONITORED_DIR": str(data_dir / "monitored"),
        "ZIRCON_DEEP_SEARCH_DIR": str(data_dir / "deep-search"),
        "ZIRCON_DEEP_SEARCH_STAGING_DIR": str(data_dir / "staging"),
        "ZIRCON_VULNSCAN_REPORTS_DIR": str(data_dir / "vulnscan-reports"),
        "ZIRCON_SECRET_KEY": config["secret_key"],
        "ZIRCON_ENCRYPTION_KEY": config["encryption_key"],
        "DS_CREDENTIAL_KEK": config["credential_kek"],
        "ZIRCON_INITIAL_ADMIN_PASSWORD": password_path.read_text(encoding="utf-8"),
        "ZIRCON_HTTP_PORT": "0",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1", help="Local or private IP address to listen on")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "local-data")
    args = parser.parse_args()
    address = ipaddress.ip_address(args.bind)
    if not (address.is_private or address.is_loopback) or address.is_unspecified or address.is_multicast:
        parser.error("--bind must be a specific private or loopback IP address")
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    data_dir = args.data_dir.resolve()
    os.environ.update(prepare(data_dir, args.bind))
    os.chdir(ROOT)
    sys.path.insert(0, str(ROOT))
    import uvicorn

    print(f"HTTPS: https://{args.bind}:{args.port}")
    print(f"Initial administrator password file: {data_dir / 'initial-admin-password.txt'}")
    print("The bundled self-signed certificate is for testing; use trusted TLS before sensitive use.")
    uvicorn.run("app.main:app", host=args.bind, port=args.port,
                ssl_certfile=str(data_dir / "cert.pem"), ssl_keyfile=str(data_dir / "key.pem"))


if __name__ == "__main__":
    main()
