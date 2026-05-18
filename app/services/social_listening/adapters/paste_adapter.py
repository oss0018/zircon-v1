import asyncio
import json
import logging
from datetime import datetime, timezone
from urllib.parse import quote_plus

import httpx

from app.models import SocialListeningRule

logger = logging.getLogger(__name__)


class PasteAdapter:
    """
    Searches pastebin.com and pastes.io for brand terms via HTTP GET.
    """

    _SEARCH_ENDPOINTS = {
        "pastebin.com": "https://pastebin.com/search?q={term}",
        "pastes.io": "https://pastes.io/search?q={term}",
    }
    _RATE_LIMIT_SECONDS = 6  # max 10 req/min per domain

    def __init__(self):
        self._last_request_at: dict[str, datetime] = {}

    async def _respect_rate_limit(self, domain: str):
        last = self._last_request_at.get(domain)
        if not last:
            return
        elapsed = (datetime.now(timezone.utc) - last).total_seconds()
        if elapsed < self._RATE_LIMIT_SECONDS:
            await asyncio.sleep(self._RATE_LIMIT_SECONDS - elapsed)

    async def collect(self, rule: SocialListeningRule) -> list[dict]:
        try:
            terms = json.loads(rule.brand_terms or "[]")
        except Exception:
            terms = []

        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Zircon/1.0"}
        timeout = httpx.Timeout(10.0)
        collected: list[dict] = []

        async with httpx.AsyncClient(headers=headers, timeout=timeout, follow_redirects=True) as client:
            for term in terms[:10]:
                safe_term = quote_plus(str(term).strip())
                if not safe_term:
                    continue

                for domain, template in self._SEARCH_ENDPOINTS.items():
                    try:
                        await self._respect_rate_limit(domain)
                        url = template.format(term=safe_term)
                        resp = await client.get(url)
                        self._last_request_at[domain] = datetime.now(timezone.utc)
                        if resp.status_code != 200:
                            continue
                        body = resp.text[:5000]
                        if str(term).lower() in body.lower():
                            collected.append(
                                {
                                    "source_platform": "paste",
                                    "source_url": str(resp.url),
                                    "author_id": "",
                                    "author_username": domain,
                                    "content_raw": body[:1200],
                                    "published_at": datetime.now(timezone.utc),
                                }
                            )
                    except Exception as exc:
                        logger.warning("social listening: paste adapter error for %s (%s): %s", term, domain, exc)
        return collected
