import logging
from datetime import datetime
from urllib.parse import quote

import httpx

from app.models import SocialListeningRule

logger = logging.getLogger(__name__)


class BlueskyAdapter:
    """Search public Bluesky posts for configured brand terms and hashtags."""

    _SEARCH_URL = "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts"

    async def collect(self, rule: SocialListeningRule) -> list[dict]:
        import json

        try:
            terms = json.loads(rule.brand_terms or "[]")
            hashtags = json.loads(rule.hashtags or "[]")
        except (TypeError, ValueError):
            terms, hashtags = [], []

        queries = [str(term).strip() for term in terms[:20] if str(term).strip()]
        queries.extend(
            f"#{str(tag).strip().lstrip('#')}"
            for tag in hashtags[:20]
            if str(tag).strip().lstrip("#")
        )
        collected: list[dict] = []
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False, trust_env=False) as client:
            for query in queries:
                try:
                    response = await client.get(self._SEARCH_URL, params={"q": query, "limit": 25, "sort": "latest"})
                    response.raise_for_status()
                    posts = response.json().get("posts", [])
                    for post in posts:
                        record = post.get("record") or {}
                        author = post.get("author") or {}
                        text = str(record.get("text") or "").strip()
                        if not text:
                            continue
                        uri = str(post.get("uri") or "")
                        rkey = uri.rsplit("/", 1)[-1]
                        handle = str(author.get("handle") or "")
                        source_url = (
                            f"https://bsky.app/profile/{quote(handle, safe='')}/post/{quote(rkey, safe='')}"
                            if handle and rkey
                            else ""
                        )
                        published_at = record.get("createdAt") or post.get("indexedAt")
                        if published_at:
                            try:
                                published_at = datetime.fromisoformat(str(published_at).replace("Z", "+00:00"))
                            except ValueError:
                                published_at = None
                        collected.append(
                            {
                                "source_platform": "bluesky",
                                "source_url": source_url,
                                "author_id": str(author.get("did") or ""),
                                "author_username": handle,
                                "content_raw": text,
                                "published_at": published_at,
                            }
                        )
                except (httpx.HTTPError, ValueError, TypeError) as exc:
                    logger.warning("social listening: Bluesky search failed for query '%s': %s", query, exc)
        return collected
