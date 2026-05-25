from app.services.osint.base import BaseOSINTClient

_MAX_RESULTS = 50


class GrayhatWarfareClient(BaseOSINTClient):
    """Client for the GrayhatWarfare Buckets API v2.

    API key is a plain bearer token obtained from
    https://buckets.grayhatwarfare.com/account.
    """

    service_name = "grayhatwarfare"
    base_url = "https://buckets.grayhatwarfare.com/api/v2"

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"}

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}

        ck = self._cache_key("grayhatwarfare", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        result = await self._request(
            "GET",
            f"{self.base_url}/buckets/list",
            params={"keywords": query, "limit": _MAX_RESULTS},
            headers=self._headers(),
        )
        self._set_cache(ck, result)
        return result

    async def search_files(self, query: str) -> dict:
        """Search for exposed files across all indexed buckets."""
        if not self.api_key:
            return {"error": "API key not configured"}

        ck = self._cache_key("grayhatwarfare_files", query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        result = await self._request(
            "GET",
            f"{self.base_url}/buckets/files",
            params={"keywords": query, "limit": _MAX_RESULTS},
            headers=self._headers(),
        )
        self._set_cache(ck, result)
        return result
