import hashlib
import json
import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import SLRawMention, SLMention, SocialListeningRule
from app.services.social_listening.adapters.paste_adapter import PasteAdapter
from app.services.social_listening.adapters.reddit_adapter import RedditAdapter
from app.services.social_listening.adapters.rss_adapter import RSSAdapter
from app.services.social_listening.adapters.telegram_adapter import TelegramAdapter
from app.services.social_listening.adapters.twitter_adapter import TwitterAdapter
from app.services.social_listening.alert_engine import AlertEngine
from app.services.social_listening.nlp_pipeline import NLPPipeline

logger = logging.getLogger(__name__)


class SocialListeningCollector:
    """
    Runs collection for a single SocialListeningRule.
    """

    def __init__(self):
        self._adapters = {
            "reddit": RedditAdapter(),
            "rss": RSSAdapter(),
            "news": RSSAdapter(),
            "paste": PasteAdapter(),
            "pastebin": PasteAdapter(),
            "telegram": TelegramAdapter(),
            "twitter": TwitterAdapter(),
            "habrahabr": RSSAdapter(feed_url_template="https://habr.com/ru/search/feed?q={term}", source_platform="habrahabr"),
        }
        self._nlp = NLPPipeline()
        self._alert_engine = AlertEngine()

    async def run_rule(self, rule: SocialListeningRule, db: AsyncSession) -> dict:
        try:
            parsed_platforms = json.loads(rule.platforms or "[]")
            if isinstance(parsed_platforms, dict):
                candidate = parsed_platforms.get("platforms", [])
                platforms = candidate if isinstance(candidate, list) else []
            elif isinstance(parsed_platforms, list):
                platforms = parsed_platforms
            else:
                platforms = []
        except Exception:
            platforms = []

        collected_items: list[dict] = []
        checked = 0

        for platform in platforms:
            key = str(platform).strip().lower()
            adapter = self._adapters.get(key)
            if not adapter:
                continue
            try:
                results = await adapter.collect(rule)
                checked += len(results)
                collected_items.extend(results)
            except Exception as exc:
                logger.warning("social listening: adapter '%s' failed for rule %s: %s", key, rule.id, exc)

        seen_fingerprints: set[str] = set()
        inserted_raw = 0
        inserted_mentions = 0

        for item in collected_items:
            content = str(item.get("content_raw", "") or "")
            author_id = str(item.get("author_id", "") or "")
            fingerprint = self._compute_fingerprint(content, author_id)
            if fingerprint in seen_fingerprints:
                continue
            seen_fingerprints.add(fingerprint)

            existing = await db.execute(
                select(SLRawMention.id).where(SLRawMention.content_fingerprint == fingerprint).limit(1)
            )
            if existing.scalar_one_or_none():
                continue

            published_at = item.get("published_at")
            if not isinstance(published_at, datetime):
                published_at = datetime.now(timezone.utc)

            try:
                async with db.begin_nested():
                    raw = SLRawMention(
                        rule_id=rule.id,
                        source_platform=str(item.get("source_platform", "unknown") or "unknown")[:50],
                        source_url=str(item.get("source_url", "") or "")[:4000],
                        author_id=author_id[:200],
                        author_username=str(item.get("author_username", "") or "")[:200],
                        content_raw=content[:10000],
                        content_fingerprint=fingerprint,
                        published_at=published_at,
                    )
                    db.add(raw)
                    await db.flush()
                    inserted_raw += 1

                    enriched = self._nlp.process(raw, rule)
                    mention = SLMention(**enriched)
                    db.add(mention)
                    await db.flush()
                    inserted_mentions += 1

                    raw.status = "processed"
                    await self._alert_engine.evaluate(mention, rule, db)
            except IntegrityError:
                continue

        await db.commit()
        return {
            "rule_id": rule.id,
            "checked": checked,
            "new": inserted_raw,
            "mentions": inserted_mentions,
            "platforms": [str(p).strip().lower() for p in platforms if str(p).strip()],
        }

    def _compute_fingerprint(self, content: str, author_id: str) -> str:
        normalized = re.sub(r"\s+", " ", (content or "").lower().strip())
        normalized = re.sub(r"http\S+", "URL", normalized)
        return hashlib.sha256(f"{normalized}|{author_id}".encode()).hexdigest()
