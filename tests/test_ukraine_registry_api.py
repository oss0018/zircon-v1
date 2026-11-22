import asyncio
import json

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.auth import get_admin_user, get_current_user
from app.config import settings
from app.database import _migrate_ukraine_registry_companies, _migrate_ukraine_registry_state, get_db
from app.main import app
from app.models import (Notification, UkraineCompanyChange, UkraineCompanyWatch, UkraineRegistryApiSettings,
                        UkraineRegistryCompany, UkraineRegistryState, User)


@pytest.fixture
def registry(monkeypatch, tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///" + str(tmp_path / "registry.db"))

    async def setup():
        async with engine.begin() as conn:
            for model in (User, UkraineRegistryState, UkraineRegistryCompany,
                          UkraineCompanyWatch, UkraineCompanyChange, UkraineRegistryApiSettings, Notification):
                await conn.run_sync(model.__table__.create)

    asyncio.run(setup())
    sessions = async_sessionmaker(engine, expire_on_commit=False)

    async def get_test_db():
        async with sessions() as db:
            yield db

    monkeypatch.setitem(app.dependency_overrides, get_db, get_test_db)
    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: User(id=1, role="user"))
    client = TestClient(app)
    yield client, sessions
    client.close()
    asyncio.run(engine.dispose())


def test_snapshot_search_replacement_and_admin_controls(registry, monkeypatch):
    client, _ = registry
    xml = (
        '<DATA><SUBJECT><EDRPOU>01234567</EDRPOU><NAME>Компанія</NAME>'
        '<STAN>зареєстровано</STAN><SIGNERS><SIGNER>Приклад</SIGNER></SIGNERS>'
        '</SUBJECT></DATA>'
    ).encode()

    response = client.post("/api/v1/ukraine-registry/snapshot", data={"snapshot_date": "2025-01-01"},
                           files={"file": ("snapshot.xml", xml, "application/xml")})
    assert response.status_code == 403
    monkeypatch.setitem(app.dependency_overrides, get_admin_user, lambda: object())
    response = client.post("/api/v1/ukraine-registry/snapshot", data={"snapshot_date": "2025-01-01"},
                           files={"file": ("snapshot.xml", xml, "application/xml")})
    assert response.status_code == 200 and response.json()["company_count"] == 1
    response = client.get("/api/v1/ukraine-registry/companies", params={"q": "КОМПАНІЯ"})
    assert response.status_code == 200
    assert response.json()["results"][0]["edrpou"] == "01234567"
    assert response.json()["results"][0]["signatories"] == ["Приклад"]
    assert client.get("/api/v1/ukraine-registry/companies", params={"q": "01234567"}).json()["results"]

    broken = xml.replace(b"</DATA>", b"")
    response = client.post("/api/v1/ukraine-registry/snapshot", data={"snapshot_date": "2025-01-02"},
                           files={"file": ("snapshot.xml", broken, "application/xml")})
    assert response.status_code == 422
    assert client.get("/api/v1/ukraine-registry/status").json()["snapshot_date"] == "2025-01-01"
    assert client.get("/api/v1/ukraine-registry/companies", params={"q": "01234567"}).json()["results"]
    response = client.post("/api/v1/ukraine-registry/snapshot", data={"snapshot_date": "2025-01-01"},
                           files={"file": ("snapshot.xml", xml, "application/xml")})
    assert response.status_code == 409
    assert client.put("/api/v1/ukraine-registry/enabled?enabled=false").status_code == 200
    assert client.get("/api/v1/ukraine-registry/companies", params={"q": "01234567"}).status_code == 503
    assert client.put("/api/v1/ukraine-registry/enabled?enabled=true").status_code == 200
    assert client.get("/api/v1/ukraine-registry/companies", params={"q": "01234567"}).json()["results"]


def test_company_watches_compare_snapshots_and_isolate_owners(registry, monkeypatch):
    client, sessions = registry
    monkeypatch.setitem(app.dependency_overrides, get_admin_user, lambda: object())

    def upload(day, name="Original", short="Old", status="active", signer="Person", code="01234567", broken=False):
        xml = (
            f"<DATA><SUBJECT><EDRPOU>{code}</EDRPOU><NAME>{name}</NAME>"
            f"<SHORT_NAME>{short}</SHORT_NAME><STAN>{status}</STAN>"
            f"<SIGNERS><SIGNER>{signer}</SIGNER></SIGNERS></SUBJECT>"
            + ("" if broken else "</DATA>")
        ).encode()
        return client.post("/api/v1/ukraine-registry/snapshot", data={"snapshot_date": f"2025-01-{day:02d}"},
                           files={"file": ("snapshot.xml", xml, "application/xml")})

    assert upload(1).status_code == 200
    assert client.post("/api/v1/ukraine-registry/watches/99999999").status_code == 404
    assert client.post("/api/v1/ukraine-registry/watches/notcode").status_code == 422
    created = client.post("/api/v1/ukraine-registry/watches/01234567")
    assert created.status_code == 201
    watch_id = created.json()["id"]
    assert client.post("/api/v1/ukraine-registry/watches/01234567").status_code == 409
    changes_url = f"/api/v1/ukraine-registry/watches/{watch_id}/changes"
    assert client.get(changes_url).json()["results"] == []

    assert upload(2).status_code == 200
    assert client.get(changes_url).json()["results"] == []
    assert upload(3, name="Changed", short="New", status="closed", signer="Other", broken=True).status_code == 422
    partial = (b"<DATA>" + b"".join(
        f"<SUBJECT><EDRPOU>{number:08d}</EDRPOU><NAME>Partial</NAME></SUBJECT>".encode()
        for number in range(1000)
    ))
    response = client.post("/api/v1/ukraine-registry/snapshot", data={"snapshot_date": "2025-01-03"},
                           files={"file": ("partial.xml", partial, "application/xml")})
    assert response.status_code == 422
    assert client.get(changes_url).json()["results"] == []
    assert client.get("/api/v1/ukraine-registry/companies", params={"q": "01234567"}).json()["results"][0]["name"] == "Original"
    assert upload(3, name="Changed", short="New", status="closed", signer="Other").status_code == 200
    changes = client.get(changes_url).json()["results"]
    assert len(changes) == 1
    assert changes[0]["snapshot_date"] == "2025-01-03"
    assert changes[0]["fields"] == {
        "name": {"before": "Original", "after": "Changed"},
        "short_name": {"before": "Old", "after": "New"},
        "status": {"before": "active", "after": "closed"},
        "signatories": {"before": ["Person"], "after": ["Other"]},
    }

    async def notifications():
        async with sessions() as db:
            return (await db.execute(select(Notification))).scalars().all()

    alerts = asyncio.run(notifications())
    assert len(alerts) == 1
    assert "01234567" not in alerts[0].message and "Changed" not in alerts[0].message
    assert upload(4, code="12345678").status_code == 200
    assert client.get("/api/v1/ukraine-registry/watches").json()[0]["company"] is None
    assert upload(5, name="Returned").status_code == 200
    assert len(client.get(changes_url).json()["results"]) == 1
    assert len(asyncio.run(notifications())) == 1

    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: User(id=2, role="user"))
    assert client.get("/api/v1/ukraine-registry/watches").json() == []
    assert client.get(changes_url).status_code == 404
    assert client.delete(f"/api/v1/ukraine-registry/watches/{watch_id}").status_code == 404
    assert client.post("/api/v1/ukraine-registry/watches/01234567").status_code == 201
    monkeypatch.setitem(app.dependency_overrides, get_current_user, lambda: User(id=1, role="user"))

    async def add_history():
        async with sessions() as db:
            db.add_all([UkraineCompanyChange(watch_id=watch_id, snapshot_date="2025-01-05",
                                             fields_json=json.dumps({"name": {"before": "a", "after": "b"}}))
                        for _ in range(50)])
            await db.commit()

    asyncio.run(add_history())
    assert client.get(changes_url).json()["has_more"] is True
    page = client.get(changes_url, params={"offset": 50}).json()
    assert len(page["results"]) == 1 and page["has_more"] is False
    assert client.delete(f"/api/v1/ukraine-registry/watches/{watch_id}").status_code == 204
    assert client.get(changes_url).status_code == 404

    async def remaining_changes():
        async with sessions() as db:
            return (await db.execute(select(UkraineCompanyChange).where(
                UkraineCompanyChange.watch_id == watch_id))).scalars().all()

    assert asyncio.run(remaining_changes()) == []


def test_import_retains_and_reports_missing_and_nonstandard_codes(registry, monkeypatch):
    client, _ = registry
    monkeypatch.setitem(app.dependency_overrides, get_admin_user, lambda: object())
    valid = b"<SUBJECT><EDRPOU>01234567</EDRPOU><NAME>Company</NAME></SUBJECT>"
    missing = b"<SUBJECT><EDRPOU></EDRPOU><NAME>Unidentified</NAME></SUBJECT>"
    invalid = b"<SUBJECT><EDRPOU>1234567</EDRPOU><NAME>Nonstandard</NAME></SUBJECT>"
    alphanumeric = b"<SUBJECT><EDRPOU>A123456</EDRPOU><NAME>Other</NAME></SUBJECT>"

    def upload(date, body):
        return client.post("/api/v1/ukraine-registry/snapshot", data={"snapshot_date": date},
                           files={"file": ("snapshot.xml", b"<DATA>" + body + b"</DATA>", "application/xml")})

    response = upload("2025-01-01", valid + missing + invalid + alphanumeric)
    assert response.status_code == 200
    assert response.json()["company_count"] == 4
    assert response.json()["missing_edrpou_count"] == 1
    assert response.json()["invalid_edrpou_count"] == 2
    assert client.get("/api/v1/ukraine-registry/status").json()["missing_edrpou_count"] == 1
    result = client.get("/api/v1/ukraine-registry/companies", params={"q": "Unidentified"}).json()["results"]
    assert len(result) == 1 and result[0]["edrpou"] is None and not result[0]["watchable"]
    result = client.get("/api/v1/ukraine-registry/companies", params={"q": "1234567"}).json()["results"]
    assert len(result) == 1 and result[0]["edrpou"] == "1234567" and not result[0]["watchable"]
    result = client.get("/api/v1/ukraine-registry/companies", params={"q": "A123456"}).json()["results"]
    assert len(result) == 1 and result[0]["edrpou"] == "A123456" and not result[0]["watchable"]
    assert upload("2025-01-02", b"").status_code == 422
    assert client.get("/api/v1/ukraine-registry/status").json()["snapshot_date"] == "2025-01-01"


def test_ambiguous_edrpou_is_searchable_but_not_monitored(registry, monkeypatch):
    client, _ = registry
    monkeypatch.setitem(app.dependency_overrides, get_admin_user, lambda: object())
    first = b"<SUBJECT><EDRPOU>01234567</EDRPOU><NAME>Original</NAME></SUBJECT>"
    duplicate = b"<SUBJECT><EDRPOU>01234567</EDRPOU><NAME>Different</NAME></SUBJECT>"

    def upload(day, body):
        return client.post("/api/v1/ukraine-registry/snapshot",
                           data={"snapshot_date": f"2025-01-{day:02d}"},
                           files={"file": ("snapshot.xml", b"<DATA>" + body + b"</DATA>", "application/xml")})

    assert upload(1, first).status_code == 200
    watch = client.post("/api/v1/ukraine-registry/watches/01234567").json()
    assert upload(2, first + duplicate).status_code == 200
    results = client.get("/api/v1/ukraine-registry/companies", params={"q": "01234567"}).json()["results"]
    assert len(results) == 2 and all(row["ambiguous"] for row in results)
    assert client.get("/api/v1/ukraine-registry/watches").json()[0]["match_status"] == "ambiguous"
    assert client.post("/api/v1/ukraine-registry/watches/01234567").status_code == 409
    changes_url = f"/api/v1/ukraine-registry/watches/{watch['id']}/changes"
    assert client.get(changes_url).json()["results"] == []
    assert upload(3, duplicate).status_code == 200
    assert client.get(changes_url).json()["results"] == []
    assert upload(4, first).status_code == 200
    assert len(client.get(changes_url).json()["results"]) == 1


def test_registry_state_migration_preserves_existing_snapshot():
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE ukraine_registry_state (id INTEGER PRIMARY KEY, snapshot_date TEXT)"))
        conn.execute(text("INSERT INTO ukraine_registry_state VALUES (1, '2025-01-01')"))
        _migrate_ukraine_registry_state(conn)
        _migrate_ukraine_registry_state(conn)
        row = conn.execute(text(
            "SELECT snapshot_date, missing_edrpou_count, invalid_edrpou_count FROM ukraine_registry_state"
        )).one()
        assert row == ("2025-01-01", 0, 0)
    engine.dispose()


def test_registry_companies_migration_preserves_existing_records():
    engine = create_engine("sqlite://")
    with engine.begin() as conn:
        conn.execute(text("CREATE TABLE ukraine_registry_companies "
                          "(edrpou TEXT PRIMARY KEY, name TEXT, short_name TEXT, name_search TEXT, "
                          "status TEXT, signatories_json TEXT)"))
        conn.execute(text("INSERT INTO ukraine_registry_companies VALUES "
                          "('01234567', 'Company', '', 'company', 'active', '[]')"))
        UkraineRegistryCompany.__table__.create(conn)
        _migrate_ukraine_registry_companies(conn)
        _migrate_ukraine_registry_companies(conn)
        row = conn.execute(text("SELECT edrpou, name FROM ukraine_registry_company_records")).one()
        assert row == ("01234567", "Company")
    engine.dispose()


def test_nais_api_settings_are_admin_only_encrypted_and_not_connected(registry, monkeypatch):
    client, sessions = registry
    url = "/api/v1/ukraine-registry/api-settings"
    payload = {"base_url": "https://edr-api.edu.nais.gov.ua", "token": "test-token"}
    assert client.get(url).status_code == 403
    assert client.put(url, json=payload).status_code == 403
    assert client.delete(url).status_code == 403
    monkeypatch.setitem(app.dependency_overrides, get_admin_user, lambda: object())

    monkeypatch.setattr(settings, "encryption_key", "")
    assert client.put(url, json=payload).status_code == 503
    monkeypatch.setattr(settings, "encryption_key", "invalid-key")
    assert client.put(url, json=payload).status_code == 503
    key = Fernet.generate_key()
    monkeypatch.setattr(settings, "encryption_key", key.decode())
    for bad_url in ("http://edr-api.edu.nais.gov.ua", "https://nais.gov.ua.evil.test",
                    "https://user:password@edr-api.edu.nais.gov.ua",
                    "https://edr-api.edu.nais.gov.ua/2.0", "https://edr-api.edu.nais.gov.ua:8443",
                    "https://edr-api.edu.nais.gov.ua\n.evil.test"):
        response = client.put(url, json={"base_url": bad_url, "token": "test-token"})
        assert response.status_code == 422 and "password" not in response.text
    invalid = client.put(url, json={**payload, "token": "secret with space"})
    assert invalid.status_code == 422 and "secret with space" not in invalid.text
    invalid = client.put(url, json={**payload, "token": {"unexpected": "secret"}})
    assert invalid.status_code == 422 and "secret" not in invalid.text
    assert invalid.headers["cache-control"] == "no-store"
    invalid = client.put(url, content='{"token":"secret"', headers={"Content-Type": "application/json"})
    assert invalid.status_code == 422 and "secret" not in invalid.text
    response = client.put(url, json=payload)
    assert response.status_code == 200 and "test-token" not in response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.json() == {"base_url": payload["base_url"], "token_configured": True, "api_available": False}

    async def encrypted_token():
        async with sessions() as db:
            row = await db.get(UkraineRegistryApiSettings, 1)
            return row.token_encrypted

    cipher = asyncio.run(encrypted_token())
    assert "test-token" not in cipher and Fernet(key).decrypt(cipher.encode()).decode() == "test-token"
    status = client.get(url)
    assert status.headers["cache-control"] == "no-store" and "test-token" not in status.text
    assert client.put(url, json={"base_url": payload["base_url"]}).status_code == 200
    assert asyncio.run(encrypted_token()) == cipher
    assert client.delete(url).status_code == 204
    assert not client.get(url).json()["token_configured"]
