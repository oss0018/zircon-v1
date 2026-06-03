import asyncio
import json
import sys
from dataclasses import dataclass
from types import ModuleType, SimpleNamespace

from app.services.social_listening.alert_engine import AlertEngine
from app.services.social_listening.adapters.telegram_adapter import TelegramAdapter
from app.services.social_listening.adapters.twitter_adapter import TwitterAdapter
from app.services.social_listening.collector import SocialListeningCollector
from app.services.social_listening.nlp_pipeline import NLPPipeline


@dataclass
class _Raw:
    id: int
    source_platform: str
    source_url: str
    author_id: str
    author_username: str
    content_raw: str
    content_fingerprint: str
    published_at: object
    collected_at: object


@dataclass
class _Rule:
    id: int
    brand_terms: str


@dataclass
class _RuleWithAlerts:
    id: int
    name: str
    brand_terms: str
    alert_email: str = ""
    alert_telegram: str = ""


@dataclass
class _Mention:
    id: int
    source_platform: str
    severity: int
    threat_indicators_json: str
    author_username: str
    content_raw: str
    source_url: str


class _FakeExecResult:
    def scalar_one_or_none(self):
        return None


class _FakeDB:
    def __init__(self):
        self.added = []

    async def execute(self, *_args, **_kwargs):
        return _FakeExecResult()

    def add(self, item):
        self.added.append(item)


def test_compute_fingerprint_normalizes_whitespace_and_urls():
    collector = SocialListeningCollector()

    first = collector._compute_fingerprint("Leak at https://example.com\n now", "user-1")
    second = collector._compute_fingerprint(" leak   at  http://another.com now ", "user-1")

    assert first == second


def test_nlp_pipeline_extracts_indicators_and_terms():
    raw = _Raw(
        id=1,
        source_platform="rss",
        source_url="https://example.com/post",
        author_id="42",
        author_username="brandnews",
        content_raw="Possible leak for ACME. Contact sec@acme.com from 1.2.3.4",
        content_fingerprint="f" * 64,
        published_at=None,
        collected_at=None,
    )
    rule = _Rule(id=10, brand_terms=json.dumps(["ACME"]))

    processed = NLPPipeline().process(raw, rule)
    indicators = json.loads(processed["threat_indicators_json"])
    matched_terms = json.loads(processed["matched_terms_json"])

    assert processed["sentiment_label"] in {"NEG", "NEU"}
    assert "sec@acme.com" in indicators["emails"]
    assert "1.2.3.4" in indicators["ips"]
    assert matched_terms == ["ACME"]
    assert 1 <= processed["severity"] <= 5


def test_alert_engine_creates_background_notification(monkeypatch):
    from app.services import notifications

    scheduled = {"called": False}

    async def _fake_notify(_title, _message, _email, _telegram):
        return None

    def _fake_create_task(coro):
        scheduled["called"] = True
        coro.close()
        return None

    monkeypatch.setattr(notifications, "notify", _fake_notify)
    monkeypatch.setattr("app.services.social_listening.alert_engine.asyncio.create_task", _fake_create_task)

    mention = _Mention(
        id=10,
        source_platform="rss",
        severity=2,
        threat_indicators_json="{}",
        author_username="",
        content_raw="ACME mentioned in post",
        source_url="https://example.com/post",
    )
    rule = _RuleWithAlerts(
        id=1,
        name="ACME rule",
        brand_terms='["ACME"]',
        alert_email="alerts@example.com",
    )
    db = _FakeDB()

    alerts = asyncio.run(AlertEngine().evaluate(mention, rule, db))
    assert alerts
    assert db.added
    assert scheduled["called"] is True


def test_collector_habrahabr_uses_correct_feed_url():
    collector = SocialListeningCollector()
    adapter = collector._adapters["habrahabr"]
    assert adapter._feed_url_template == "https://habr.com/ru/search/feed/?query={term}&target_type=posts"


def test_twitter_adapter_limits_terms_and_resolves_usernames(monkeypatch):
    calls = {}

    class _TweepyException(Exception):
        pass

    class _Forbidden(_TweepyException):
        pass

    class _Client:
        def __init__(self, bearer_token):
            calls["token"] = bearer_token

        def search_recent_tweets(self, **kwargs):
            calls["kwargs"] = kwargs
            return SimpleNamespace(
                data=[SimpleNamespace(id="111", author_id="42", text="hello", created_at=None)],
                includes={"users": [SimpleNamespace(id="42", username="alice")]},
            )

    tweepy_module = ModuleType("tweepy")
    tweepy_module.Client = _Client
    tweepy_module.errors = SimpleNamespace(TweepyException=_TweepyException, Forbidden=_Forbidden)
    monkeypatch.setitem(sys.modules, "tweepy", tweepy_module)

    async def _fake_to_thread(func, *args, **kwargs):
        return func(*args, **kwargs)

    monkeypatch.setattr("app.services.social_listening.adapters.twitter_adapter.asyncio.to_thread", _fake_to_thread)
    monkeypatch.setenv("TWITTER_BEARER_TOKEN", "token")

    rule = _Rule(id=1, brand_terms=json.dumps(["one", "two", "three", "four"]))
    items = asyncio.run(TwitterAdapter().collect(rule))

    assert len(items) == 1
    assert items[0]["author_username"] == "alice"
    assert calls["kwargs"]["expansions"] == ["author_id"]
    assert calls["kwargs"]["user_fields"] == ["username"]
    assert "one OR two OR three" in calls["kwargs"]["query"]
    assert "four" not in calls["kwargs"]["query"]


def test_telegram_adapter_rejects_short_session_string(monkeypatch, caplog):
    class _FloodWaitError(Exception):
        def __init__(self, seconds=0):
            self.seconds = seconds
            super().__init__(f"wait {seconds}")

    class _StringSession:
        def __init__(self, _value):
            self.value = _value

    class _TelegramClient:
        def __init__(self, *_args, **_kwargs):
            pass

    telethon_module = ModuleType("telethon")
    telethon_module.TelegramClient = _TelegramClient
    telethon_sessions_module = ModuleType("telethon.sessions")
    telethon_sessions_module.StringSession = _StringSession
    telethon_errors_module = ModuleType("telethon.errors")
    telethon_errors_module.FloodWaitError = _FloodWaitError

    monkeypatch.setitem(sys.modules, "telethon", telethon_module)
    monkeypatch.setitem(sys.modules, "telethon.sessions", telethon_sessions_module)
    monkeypatch.setitem(sys.modules, "telethon.errors", telethon_errors_module)

    monkeypatch.setenv("TELEGRAM_API_ID", "12345")
    monkeypatch.setenv("TELEGRAM_API_HASH", "abc123")
    monkeypatch.setenv("TELEGRAM_SESSION_STRING", "short")

    rule = SimpleNamespace(brand_terms='["acme"]', platforms="[]")
    with caplog.at_level("WARNING"):
        items = asyncio.run(TelegramAdapter().collect(rule))

    assert items == []
    assert "TELEGRAM_SESSION_STRING seems invalid" in caplog.text
