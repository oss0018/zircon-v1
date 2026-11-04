import asyncio
import json
import socket
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.api.social_listening import (
    _snapshot_to_out,
    create_mention_snapshot,
    list_mention_snapshots,
)
from app.database import _migrate_sl_rules
from app.database import Base
from app.models import Brand, SLMention, SocialListeningRule, User
from app.schemas import SLRuleCreate, SLRuleUpdate
from app.services.social_listening.adapters.bluesky_adapter import BlueskyAdapter
from app.services.social_listening.adapters.mastodon_adapter import MastodonAdapter
from app.services.social_listening.adapters.custom_rss_adapter import _PublicDNSResolver
from app.services.social_listening.adapters.custom_rss_adapter import CustomRSSAdapter
from app.services.social_listening.collector import SocialListeningCollector
from app.api.social_listening import _snapshot_digest


def test_social_listening_rule_accepts_public_https_rss_urls_and_rejects_private_hosts():
    rule = SLRuleCreate(name="brand", brand_id=1, rss_feeds=["https://news.example.org/feed.xml"])
    assert rule.rss_feeds == ["https://news.example.org/feed.xml"]

    with pytest.raises(ValueError, match="public HTTPS"):
        SLRuleCreate(name="brand", brand_id=1, rss_feeds=["https://127.0.0.1/feed.xml"])
    with pytest.raises(ValueError, match="public HTTPS"):
        SLRuleUpdate(rss_feeds=["http://news.example.org/feed.xml"])


def test_social_listening_collector_registers_new_sources():
    collector = SocialListeningCollector()
    assert {"bluesky", "mastodon", "custom_rss"} <= set(collector._adapters)


def test_social_listening_rule_migration_adds_custom_feeds_column():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE sl_rules (id INTEGER PRIMARY KEY)"))
        _migrate_sl_rules(connection)
        columns = {column["name"] for column in inspect(connection).get_columns("sl_rules")}
    engine.dispose()
    assert {"rss_feeds", "alert_email", "alert_telegram"} <= columns


def test_bluesky_adapter_maps_public_search_results(monkeypatch):
    class _Response:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "posts": [
                    {
                        "uri": "at://did:plc:abc/app.bsky.feed.post/post-key",
                        "record": {"text": "Brand update", "createdAt": "2026-01-02T03:04:05Z"},
                        "author": {"did": "did:plc:abc", "handle": "brand.example"},
                    }
                ]
            }

    class _Client:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, *_args, **_kwargs):
            return _Response()

    monkeypatch.setattr("app.services.social_listening.adapters.bluesky_adapter.httpx.AsyncClient", _Client)
    rule = SimpleNamespace(brand_terms=json.dumps(["brand"]), hashtags="[]")
    items = asyncio.run(BlueskyAdapter().collect(rule))

    assert items[0]["source_platform"] == "bluesky"
    assert items[0]["source_url"] == "https://bsky.app/profile/brand.example/post/post-key"
    assert items[0]["content_raw"] == "Brand update"


def test_mastodon_adapter_strips_markup_from_status_content():
    statuses = [
        {
            "url": "https://mastodon.social/@brand/123",
            "content": "<p>Brand&nbsp;update <a href='https://example.org'>read more</a></p>",
            "created_at": "2026-01-02T03:04:05.000Z",
            "account": {"id": "42", "acct": "brand"},
        }
    ]

    mention = MastodonAdapter._statuses(statuses)[0]
    assert mention["content_raw"] == "Brand\u00a0update read more"
    assert mention["author_id"] == "42"
    assert mention["source_url"] == "https://mastodon.social/@brand/123"


def test_custom_rss_dns_resolver_pins_only_public_addresses(monkeypatch):
    public_result = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))
    monkeypatch.setattr(
        "app.services.social_listening.adapters.custom_rss_adapter.socket.getaddrinfo",
        lambda *_args, **_kwargs: [public_result],
    )
    resolver = _PublicDNSResolver()
    result = asyncio.run(resolver.resolve("news.example.org", 443))
    assert result[0]["host"] == "8.8.8.8"

    private_result = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
    monkeypatch.setattr(
        "app.services.social_listening.adapters.custom_rss_adapter.socket.getaddrinfo",
        lambda *_args, **_kwargs: [private_result],
    )
    with pytest.raises(OSError, match="public IP"):
        asyncio.run(resolver.resolve("news.example.org", 443))


def test_custom_rss_adapter_parses_feed_entries(monkeypatch):
    class _Content:
        async def iter_chunked(self, _size):
            yield (
                b'<?xml version="1.0"?><rss version="2.0"><channel><item>'
                b"<title>Brand news</title><link>https://news.example.org/post/1</link>"
                b"<description>Post content</description></item></channel></rss>"
            )

    class _Response:
        status = 200
        headers = {}
        content = _Content()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    class _Session:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def get(self, *_args, **_kwargs):
            return _Response()

    monkeypatch.setattr(
        "app.services.social_listening.adapters.custom_rss_adapter.aiohttp.TCPConnector",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        "app.services.social_listening.adapters.custom_rss_adapter.aiohttp.ClientSession",
        _Session,
    )
    rule = SimpleNamespace(rss_feeds=json.dumps(["https://news.example.org/feed.xml"]))
    items = asyncio.run(CustomRSSAdapter().collect(rule))

    assert len(items) == 1
    assert items[0]["source_platform"] == "custom_rss"
    assert items[0]["content_raw"] == "Brand news\nPost content"


def test_snapshot_integrity_detects_modified_saved_content():
    published_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
    captured_at = datetime.now(timezone.utc)
    snapshot = SimpleNamespace(
        id=1,
        mention_id=2,
        source_platform="bluesky",
        source_url="https://bsky.app/post/1",
        author_username="brand.example",
        content="Original post",
        content_sha256=_snapshot_digest(
            "bluesky",
            "https://bsky.app/post/1",
            "brand.example",
            "Original post",
            published_at,
            3,
            captured_at,
        ),
        published_at=published_at,
        captured_by=3,
        captured_at=captured_at,
    )
    assert _snapshot_to_out(snapshot).integrity_valid is True
    snapshot.content = "Altered post"
    assert _snapshot_to_out(snapshot).integrity_valid is False


@pytest.mark.asyncio
async def test_snapshot_routes_persist_post_evidence_and_verify_hash():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with AsyncSession(engine, expire_on_commit=False) as db:
        user = User(username="snapshot-user", password_hash="hash")
        brand = Brand(name="Snapshot brand")
        db.add_all([user, brand])
        await db.flush()

        rule = SocialListeningRule(name="Snapshot rule", brand_id=brand.id)
        db.add(rule)
        await db.flush()

        mention = SLMention(
            rule_id=rule.id,
            source_platform="bluesky",
            source_url="https://bsky.app/profile/brand.example/post/post-key",
            author_username="brand.example",
            content_raw="Original brand post",
            content_fingerprint="snapshot-test-fingerprint",
        )
        db.add(mention)
        await db.commit()
        await db.refresh(mention)

        created = await create_mention_snapshot(mention.id, db, user)
        listed = await list_mention_snapshots(mention.id, db, user)

    await engine.dispose()
    assert created.content == "Original brand post"
    assert created.integrity_valid is True
    assert len(listed) == 1
    assert listed[0].content_sha256 == created.content_sha256
