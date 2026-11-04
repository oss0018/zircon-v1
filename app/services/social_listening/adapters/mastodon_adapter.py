import json
import logging
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import quote, urlsplit

import httpx

from app.config import settings
from app.models import SocialListeningRule

logger = logging.getLogger(__name__)


class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        if data.strip():
            self.parts.append(data.strip())


def _plain_text(value: str) -> str:
    parser = _HTMLText()
    parser.feed(value or "")
    return " ".join(parser.parts)


class MastodonAdapter:
    """Search a configured Mastodon instance; public hashtag timelines need no token."""

    def _base_url(self) -> str:
        parsed = urlsplit(settings.mastodon_instance_url.strip())
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("MASTODON_INSTANCE_URL must be a public HTTPS instance URL")
        return f"https://{parsed.netloc}"

    async def collect(self, rule: SocialListeningRule) -> list[dict]:
        try:
            terms = json.loads(rule.brand_terms or "[]")
            hashtags = json.loads(rule.hashtags or "[]")
        except (TypeError, ValueError):
            terms, hashtags = [], []

        headers = {}
        if settings.mastodon_access_token:
            headers["Authorization"] = f"Bearer {settings.mastodon_access_token}"
        base_url = self._base_url()
        collected: list[dict] = []

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, trust_env=False) as client:
            for tag in hashtags[:20]:
                normalized_tag = str(tag).strip().lstrip("#")
                if not normalized_tag:
                    continue
                try:
                    response = await client.get(
                        f"{base_url}/api/v1/timelines/tag/{quote(normalized_tag, safe='')}",
                        params={"limit": 20},
                        headers=headers,
                    )
                    response.raise_for_status()
                    collected.extend(self._statuses(response.json()))
                except (httpx.HTTPError, ValueError, TypeError) as exc:
                    logger.warning("social listening: Mastodon hashtag search failed for '%s': %s", normalized_tag, exc)

            if terms and settings.mastodon_access_token:
                for term in terms[:20]:
                    query = str(term).strip()
                    if not query:
                        continue
                    try:
                        response = await client.get(
                            f"{base_url}/api/v2/search",
                            params={"q": query, "type": "statuses", "limit": 20},
                            headers=headers,
                        )
                        response.raise_for_status()
                        collected.extend(self._statuses(response.json().get("statuses", [])))
                    except (httpx.HTTPError, ValueError, TypeError) as exc:
                        logger.warning("social listening: Mastodon search failed for term '%s': %s", query, exc)
            elif terms:
                logger.info("Mastodon full-text search skipped; configure MASTODON_ACCESS_TOKEN")

        return collected

    @staticmethod
    def _statuses(statuses: list[dict]) -> list[dict]:
        collected = []
        for status in statuses:
            account = status.get("account") or {}
            content = _plain_text(str(status.get("content") or ""))
            if not content:
                continue
            published_at = status.get("created_at")
            if published_at:
                try:
                    published_at = datetime.fromisoformat(str(published_at).replace("Z", "+00:00"))
                except ValueError:
                    published_at = None
            collected.append(
                {
                    "source_platform": "mastodon",
                    "source_url": str(status.get("url") or status.get("uri") or ""),
                    "author_id": str(account.get("id") or ""),
                    "author_username": str(account.get("acct") or account.get("username") or ""),
                    "content_raw": content,
                    "published_at": published_at,
                }
            )
        return collected
