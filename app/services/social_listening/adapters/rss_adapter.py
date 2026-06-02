import asyncio
import json
import logging
from datetime import datetime, timezone
from urllib.parse import quote_plus

from app.models import SocialListeningRule

logger = logging.getLogger(__name__)


class RSSAdapter:
    """
    Polls Google News RSS feeds for each brand term.
    """

    def __init__(self, feed_url_template: str = "https://news.google.com/rss/search?q={term}&hl=uk&gl=UA", source_platform: str = "rss"):
        self._feed_url_template = feed_url_template
        self._source_platform = source_platform

    async def collect(self, rule: SocialListeningRule) -> list[dict]:
        try:
            import feedparser  # type: ignore
        except ImportError:
            logger.warning("social listening: feedparser is not installed; rss adapter skipped")
            return []

        try:
            terms = json.loads(rule.brand_terms or "[]")
        except Exception:
            terms = []

        collected: list[dict] = []
        for term in terms[:20]:
            safe_term = quote_plus(str(term).strip())
            if not safe_term:
                continue
            url = self._feed_url_template.format(term=safe_term)
            try:
                feed = await asyncio.to_thread(feedparser.parse, url)
                for entry in getattr(feed, "entries", [])[:10]:
                    parsed = getattr(entry, "published_parsed", None)
                    published_at = None
                    if parsed:
                        published_at = datetime(*parsed[:6], tzinfo=timezone.utc)
                    collected.append(
                        {
                            "source_platform": self._source_platform,
                            "source_url": str(getattr(entry, "link", "") or ""),
                            "author_id": "",
                            "author_username": str(getattr(entry, "author", "") or ""),
                            "content_raw": f"{getattr(entry, 'title', '')}\n{getattr(entry, 'summary', '')}".strip(),
                            "published_at": published_at,
                        }
                    )
            except Exception as exc:
                logger.warning("social listening: rss fetch failed for term '%s': %s", term, exc)
        return collected
