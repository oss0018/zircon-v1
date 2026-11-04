import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api.dashboard import get_settings, save_settings
from app.config import settings
from app.models import NotificationSettings, User
from app.schemas import NotificationSettingsUpdate
from app.services.crypto import decrypt
from app.services import notifications


@pytest.mark.asyncio
async def test_notification_settings_persist_without_returning_secrets(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(NotificationSettings.__table__.create)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    admin = User(id=1, username="admin", password_hash="hash", role="admin")
    monkeypatch.setattr(settings, "smtp_host", "")
    monkeypatch.setattr(settings, "smtp_port", 587)
    monkeypatch.setattr(settings, "smtp_user", "")
    monkeypatch.setattr(settings, "smtp_password", "")
    monkeypatch.setattr(settings, "telegram_bot_token", "")
    monkeypatch.setattr(settings, "telegram_chat_id", "")

    try:
        async with session_factory() as db:
            await save_settings(
                NotificationSettingsUpdate(
                    smtp_host="smtp.example.test",
                    smtp_port=2525,
                    smtp_user="alerts@example.test",
                    smtp_password="mail-secret",
                    telegram_token="bot-secret",
                    telegram_chat_id="-100123",
                ),
                admin,
                db,
            )

        async with session_factory() as db:
            result = await get_settings(admin, db)
            assert result == {
                "smtp_host": "smtp.example.test",
                "smtp_port": 2525,
                "smtp_user": "alerts@example.test",
                "smtp_password": "",
                "telegram_token": "",
                "telegram_chat_id": "-100123",
                "smtp_password_configured": True,
                "telegram_token_configured": True,
            }

            await save_settings(
                NotificationSettingsUpdate(
                    smtp_host="smtp.updated.test",
                    smtp_port=587,
                    smtp_user="alerts@example.test",
                    telegram_chat_id="-100123",
                ),
                admin,
                db,
            )

        async with session_factory() as db:
            saved = await db.get(NotificationSettings, 1)
            assert saved.smtp_host == "smtp.updated.test"
            assert decrypt(saved.smtp_password_encrypted) == "mail-secret"
            assert decrypt(saved.telegram_bot_token_encrypted) == "bot-secret"
            assert settings.smtp_host == "smtp.updated.test"
            assert settings.telegram_bot_token == "bot-secret"

        monkeypatch.setattr("app.database.AsyncSessionLocal", session_factory)
        monkeypatch.setattr(settings, "smtp_host", "")
        monkeypatch.setattr(settings, "telegram_bot_token", "")
        await notifications.load_notification_settings()
        assert settings.smtp_host == "smtp.updated.test"
        assert settings.telegram_bot_token == "bot-secret"
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_email_sender_uses_saved_smtp_configuration(monkeypatch):
    calls = {}

    class FakeSMTP:
        def __init__(self, host, port):
            calls["server"] = (host, port)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def ehlo(self):
            pass

        def starttls(self):
            pass

        def login(self, username, password):
            calls["login"] = (username, password)

        def sendmail(self, sender, recipients, message):
            calls["message"] = (sender, recipients, message)

    monkeypatch.setattr(settings, "smtp_host", "smtp.example.test")
    monkeypatch.setattr(settings, "smtp_port", 2525)
    monkeypatch.setattr(settings, "smtp_user", "alerts@example.test")
    monkeypatch.setattr(settings, "smtp_password", "mail-secret")
    monkeypatch.setattr(notifications.smtplib, "SMTP", FakeSMTP)

    assert await notifications.send_email("recipient@example.test", "Test", "Hello")
    assert calls["server"] == ("smtp.example.test", 2525)
    assert calls["login"] == ("alerts@example.test", "mail-secret")
    assert calls["message"][1] == ["recipient@example.test"]


@pytest.mark.asyncio
async def test_telegram_sender_uses_saved_token_and_default_chat(monkeypatch):
    requests = []

    class FakeResponse:
        status_code = 200

    class FakeClient:
        def __init__(self, timeout):
            assert timeout == 10

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def post(self, url, json):
            requests.append((url, json))
            return FakeResponse()

    monkeypatch.setattr(settings, "telegram_bot_token", "bot-secret")
    monkeypatch.setattr(settings, "telegram_chat_id", "-100123")
    monkeypatch.setattr(notifications.httpx, "AsyncClient", FakeClient)

    assert await notifications.send_telegram("", "Test")
    assert requests == [
        (
            "https://api.telegram.org/botbot-secret/sendMessage",
            {"chat_id": "-100123", "text": "Test", "parse_mode": "HTML"},
        )
    ]
