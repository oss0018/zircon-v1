import asyncio
import ipaddress

import pytest
from cryptography import x509
from cryptography.fernet import Fernet
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.auth import verify_password
from app.config import settings
from app.main import create_default_admin
from app.models import User
from deploy.local_server import prepare


def test_local_configuration_persists_keys_password_and_certificate(tmp_path):
    data = tmp_path / "data"
    initial = prepare(data, "192.168.10.2")
    repeated = prepare(data, "192.168.10.2")
    assert initial == repeated
    Fernet(initial["ZIRCON_ENCRYPTION_KEY"].encode())
    assert initial["ZIRCON_HTTP_PORT"] == "0"
    assert len(initial["ZIRCON_INITIAL_ADMIN_PASSWORD"]) >= 24
    cert = x509.load_pem_x509_certificate((data / "cert.pem").read_bytes())
    addresses = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert ipaddress.ip_address("192.168.10.2") in addresses.get_values_for_type(x509.IPAddress)
    with pytest.raises(RuntimeError, match="certificate does not cover"):
        prepare(data, "192.168.10.3")


def test_local_configuration_refuses_incomplete_existing_data(tmp_path):
    data = tmp_path / "data"
    data.mkdir(mode=0o700)
    (data / "existing").write_text("keep", encoding="utf-8")
    with pytest.raises(RuntimeError, match="refusing initialization"):
        prepare(data, "127.0.0.1")
    assert (data / "existing").read_text(encoding="utf-8") == "keep"


def test_configured_initial_admin_does_not_replace_existing_user(tmp_path, monkeypatch):
    import app.database

    engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "auth.db"))
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def run():
        async with engine.begin() as conn:
            await conn.run_sync(User.__table__.create)
        monkeypatch.setattr(app.database, "AsyncSessionLocal", sessions)
        monkeypatch.setattr(settings, "initial_admin_password", "example-random-password")
        await create_default_admin()
        monkeypatch.setattr(settings, "initial_admin_password", "different-password")
        await create_default_admin()
        async with sessions() as db:
            admin = (await db.execute(select(User).where(User.username == "admin"))).scalar_one()
            assert verify_password("example-random-password", admin.password_hash)
            assert not verify_password("different-password", admin.password_hash)
        await engine.dispose()

    asyncio.run(run())
