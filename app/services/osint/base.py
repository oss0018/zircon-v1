"""
Base OSINT client with caching and rate limiting.
"""
import time
from typing import Any, Dict, Optional
import httpx


class BaseOSINTClient:
    service_name: str = "base"
    base_url: str = ""

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self._cache: Dict[str, Dict[str, Any]] = {}

    def _cache_key(self, *args) -> str:
        return "|".join(str(a) for a in args)

    def _get_cached(self, key: str, ttl: int = 3600) -> Optional[Any]:
        entry = self._cache.get(key)
        if entry and (time.time() - entry["ts"]) < ttl:
            return entry["data"]
        return None

    def _set_cache(self, key: str, data: Any):
        self._cache[key] = {"ts": time.time(), "data": data}

    async def _request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.request(method, url, **kwargs)
                if resp.status_code == 200:
                    try:
                        return resp.json()
                    except Exception:
                        return {"raw": resp.text}
                elif resp.status_code == 404:
                    return {"not_found": True}
                elif resp.status_code == 401:
                    return {"error": "Invalid API key"}
                elif resp.status_code == 429:
                    return {"error": "Rate limit exceeded"}
                else:
                    return {"error": f"HTTP {resp.status_code}", "body": resp.text[:500]}
        except httpx.TimeoutException:
            return {"error": "Request timeout"}
        except Exception as e:
            return {"error": str(e)}

    async def search(self, query: str, query_type: str = "general") -> Dict[str, Any]:
        return {"error": "Not implemented"}
