import asyncio
import logging
from datetime import datetime, timezone
from os import getenv
from urllib.parse import quote_plus

from app.models import SocialListeningRule

logger = logging.getLogger(__name__)


class RedditAdapter:
    """
    Uses PRAW to search reddit.subreddit('all') for brand terms.
    """

    async def collect(self, rule: SocialListeningRule) -> list[dict]:
        try:
            import praw  # type: ignore
        except ImportError:
            logger.warning("social listening: praw is not installed; reddit adapter skipped")
            return []

        client_id = getenv("REDDIT_CLIENT_ID", "")
        client_secret = getenv("REDDIT_CLIENT_SECRET", "")
        user_agent = getenv("REDDIT_USER_AGENT", "zircon-social-listening/1.0")
        if not client_id or not client_secret:
            logger.warning("social listening: reddit credentials missing; reddit adapter skipped")
            return []

        terms = []
        try:
            import json

            terms = json.loads(rule.brand_terms or "[]")
        except Exception:
            terms = []

        reddit = praw.Reddit(
            client_id=client_id,
            client_secret=client_secret,
            user_agent=user_agent,
            check_for_async=False,
        )

        subreddits = "all+netsec+cybersecurity+hacking+ukraine"

        def _sync_collect() -> list[dict]:
            collected: list[dict] = []
            for term in terms[:20]:
                query = quote_plus(str(term).strip())
                if not query:
                    continue
                try:
                    for post in reddit.subreddit(subreddits).search(query, limit=10, sort="new"):
                        collected.append(
                            {
                                "source_platform": "reddit",
                                "source_url": f"https://www.reddit.com{post.permalink}",
                                "author_id": str(getattr(post.author, "id", "") or ""),
                                "author_username": str(getattr(post.author, "name", "") or ""),
                                "content_raw": f"{post.title}\n{getattr(post, 'selftext', '')}".strip(),
                                "published_at": datetime.fromtimestamp(post.created_utc, tz=timezone.utc),
                            }
                        )
                except Exception as exc:
                    logger.warning("social listening: reddit search failed for term '%s': %s", term, exc)
            return collected

        return await asyncio.to_thread(_sync_collect)
