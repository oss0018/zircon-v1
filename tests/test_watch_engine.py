import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, patch

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models import Brand, LookalikeDomain, LookalikeRule, NrdFeedEntry
from app.services.lookalike.nrd_feed import fetch_nrd_domains
from app.services.lookalike.watch_engine import run_watch_mode


async def _build_session():
    fd, db_path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, session_factory, db_path


def test_fetch_nrd_domains_local_source_reads_fixture_file():
    result = asyncio.run(fetch_nrd_domains(feed_source="local"))
    assert "watch-login.test" in result
    assert "secure-watch.test" in result
    assert len(result) == 2


def test_fetch_nrd_domains_http_error_returns_empty_list():
    with patch("app.services.lookalike.nrd_feed.httpx.AsyncClient.get", new_callable=AsyncMock) as mocked_get:
        mocked_get.side_effect = httpx.HTTPError("boom")
        result = asyncio.run(fetch_nrd_domains(feed_source="whoisds"))
    assert result == []


def test_run_watch_mode_upserts_and_dedups_entries():
    async def _run():
        engine, session_factory, db_path = await _build_session()
        try:
            async with session_factory() as db:
                brand = Brand(name="Acme")
                db.add(brand)
                await db.flush()
                rule = LookalikeRule(
                    brand_id=brand.id,
                    name="Acme Rule",
                    protected_domain="acme.com",
                    watch_mode_enabled=True,
                    watch_feed_source="local",
                    alert_threshold=5,
                )
                db.add(rule)
                await db.commit()
                await db.refresh(rule)

                with patch("app.services.lookalike.watch_engine.fetch_nrd_domains", new_callable=AsyncMock) as mocked_feed, \
                     patch("app.services.lookalike.watch_engine.dispatch_lookalike_alerts", new_callable=AsyncMock) as mocked_alerts, \
                     patch("app.services.lookalike.watch_engine.composite_score") as mocked_score:
                    mocked_feed.return_value = ["acme-login.com", "acme-login.com"]
                    mocked_score.return_value = 0.96
                    mocked_alerts.return_value = {"sent": 1, "failed": 0}

                    first_summary = await run_watch_mode(rule, db)

                assert first_summary["checked"] == 2
                assert first_summary["matched"] == 2
                assert first_summary["alerted"] == 1

                dom_res = await db.execute(select(LookalikeDomain).where(LookalikeDomain.rule_id == rule.id))
                domains = dom_res.scalars().all()
                assert len(domains) == 1
                assert domains[0].fqdn == "acme-login.com"
                assert domains[0].status == "registered"
                assert domains[0].similarity_score == 0.96

                second_summary = await run_watch_mode(rule, db)
                assert second_summary["alerted"] == 0

                dedup_res = await db.execute(select(NrdFeedEntry).where(NrdFeedEntry.rule_id == rule.id))
                entries = dedup_res.scalars().all()
                assert len(entries) == 1
        finally:
            await engine.dispose()
            os.remove(db_path)

    asyncio.run(_run())


def test_run_watch_mode_alert_threshold_gate_blocks_alert_dispatch():
    async def _run():
        engine, session_factory, db_path = await _build_session()
        try:
            async with session_factory() as db:
                brand = Brand(name="Acme")
                db.add(brand)
                await db.flush()
                rule = LookalikeRule(
                    brand_id=brand.id,
                    name="Acme Rule",
                    protected_domain="acme.com",
                    watch_mode_enabled=True,
                    watch_feed_source="local",
                    alert_threshold=99,
                )
                db.add(rule)
                await db.commit()
                await db.refresh(rule)

                with patch("app.services.lookalike.watch_engine.fetch_nrd_domains", new_callable=AsyncMock) as mocked_feed, \
                     patch("app.services.lookalike.watch_engine.dispatch_lookalike_alerts", new_callable=AsyncMock) as mocked_alerts, \
                     patch("app.services.lookalike.watch_engine.composite_score") as mocked_score:
                    mocked_feed.return_value = ["acme-login.com"]
                    mocked_score.return_value = 0.75
                    summary = await run_watch_mode(rule, db)

                assert summary["checked"] == 1
                assert summary["matched"] == 1
                assert summary["alerted"] == 0
                mocked_alerts.assert_not_called()
        finally:
            await engine.dispose()
            os.remove(db_path)

    asyncio.run(_run())
