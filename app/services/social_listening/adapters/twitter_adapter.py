import asyncio
import json
import logging
from os import getenv

from app.models import SocialListeningRule

logger = logging.getLogger(__name__)


class TwitterAdapter:
    """
    Uses Tweepy recent search to find mentions on Twitter/X.
    """

    async def collect(self, rule: SocialListeningRule) -> list[dict]:
        try:
            import tweepy  # type: ignore
        except ImportError:
            logger.warning("social listening: tweepy is not installed; twitter adapter skipped")
            return []

        bearer_token = getenv("TWITTER_BEARER_TOKEN", "").strip()
        if not bearer_token:
            logger.warning("social listening: twitter bearer token missing; twitter adapter skipped")
            return []

        try:
            terms = json.loads(rule.brand_terms or "[]")
        except Exception:
            terms = []

        selected_terms = [str(term).strip() for term in terms[:5] if str(term).strip()]
        if not selected_terms:
            return []

        joined_terms = " OR ".join(selected_terms)
        query = f"({joined_terms}) (lang:uk OR lang:ru OR lang:en) -is:retweet"
        client = tweepy.Client(bearer_token=bearer_token)

        try:
            response = await asyncio.to_thread(
                client.search_recent_tweets,
                query=query,
                max_results=10,
                tweet_fields=["created_at", "author_id", "text"],
            )
        except tweepy.errors.TweepyException as exc:
            logger.warning("social listening: twitter search failed: %s", exc)
            return []

        collected: list[dict] = []
        for tweet in getattr(response, "data", []) or []:
            collected.append(
                {
                    "source_platform": "twitter",
                    "source_url": f"https://twitter.com/i/web/status/{tweet.id}",
                    "author_id": str(getattr(tweet, "author_id", "") or ""),
                    "author_username": "",
                    "content_raw": str(getattr(tweet, "text", "") or ""),
                    "published_at": getattr(tweet, "created_at", None),
                }
            )
        return collected
