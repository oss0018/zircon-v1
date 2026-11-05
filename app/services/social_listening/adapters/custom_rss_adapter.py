import asyncio
import ipaddress
import json
import logging
import socket
from datetime import datetime, timezone
from urllib.parse import urlsplit

import aiohttp
import feedparser

from app.models import SocialListeningRule

logger = logging.getLogger(__name__)
_MAX_FEED_BYTES = 2 * 1024 * 1024


class _PublicDNSResolver(aiohttp.abc.AbstractResolver):
    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET):
        try:
            addresses = await asyncio.to_thread(
                socket.getaddrinfo, host, port, family=family, type=socket.SOCK_STREAM
            )
        except OSError as exc:
            raise OSError("RSS host could not be resolved") from exc

        results = []
        for address in addresses:
            ip = address[4][0].split("%", 1)[0]
            if not ipaddress.ip_address(ip).is_global:
                raise OSError("RSS hosts must resolve only to public IP addresses")
            results.append(
                {
                    "hostname": host,
                    "host": ip,
                    "port": port,
                    "family": address[0],
                    "proto": address[2],
                    "flags": address[3],
                }
            )
        if not results:
            raise OSError("RSS host did not resolve to a public IP address")
        return results

    async def close(self) -> None:
        return None


class CustomRSSAdapter:
    """Fetch user-configured public HTTPS feeds without following redirects."""

    async def collect(self, rule: SocialListeningRule) -> list[dict]:
        try:
            feeds = json.loads(rule.rss_feeds or "[]")
        except (TypeError, ValueError):
            feeds = []
        if not isinstance(feeds, list):
            return []

        collected: list[dict] = []
        timeout = aiohttp.ClientTimeout(total=15)
        connector = aiohttp.TCPConnector(
            resolver=_PublicDNSResolver(),
            use_dns_cache=False,
            family=socket.AF_UNSPEC,
        )
        async with aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            trust_env=False,
            headers={"User-Agent": "Zircon-SocialListening/1.0"},
        ) as client:
            for feed_url in feeds[:10]:
                parsed = urlsplit(str(feed_url))
                host = parsed.hostname or ""
                try:
                    port = parsed.port
                except ValueError:
                    port = -1
                if (
                    parsed.scheme != "https"
                    or not host
                    or port not in (None, 443)
                    or parsed.username
                    or parsed.password
                ):
                    logger.warning("social listening: custom RSS feed URL rejected by public-host validation")
                    continue
                try:
                    async with client.get(str(feed_url), allow_redirects=False) as response:
                        if response.status < 200 or response.status >= 300:
                            logger.warning(
                                "social listening: custom RSS feed returned HTTP %s", response.status
                            )
                            continue
                        if int(response.headers.get("content-length", "0") or "0") > _MAX_FEED_BYTES:
                            logger.warning("social listening: custom RSS feed exceeded size limit")
                            continue
                        body = bytearray()
                        async for chunk in response.content.iter_chunked(64 * 1024):
                            body.extend(chunk)
                            if len(body) > _MAX_FEED_BYTES:
                                raise ValueError("feed exceeds size limit")
                    feed = await asyncio.to_thread(feedparser.parse, bytes(body))
                    for entry in getattr(feed, "entries", [])[:20]:
                        parsed_date = getattr(entry, "published_parsed", None)
                        published_at = (
                            datetime(*parsed_date[:6], tzinfo=timezone.utc) if parsed_date else None
                        )
                        collected.append(
                            {
                                "source_platform": "custom_rss",
                                "source_url": str(getattr(entry, "link", "") or ""),
                                "author_id": "",
                                "author_username": str(getattr(entry, "author", "") or host),
                                "content_raw": f"{getattr(entry, 'title', '')}\n{getattr(entry, 'summary', '')}".strip(),
                                "published_at": published_at,
                            }
                        )
                except (aiohttp.ClientError, ValueError, OSError) as exc:
                    logger.warning("social listening: custom RSS fetch failed for %s: %s", host, exc)
        return collected
