from app.services.osint.base import BaseOSINTClient


class OpenSquatClient(BaseOSINTClient):
    """Client for the openSquat lookalike domain detection API.

    API docs: https://opensquat.com/docs
    Authentication: Bearer token via Authorization header.
    """

    service_name = "opensquat"
    base_url = "https://opensquat.com/api/v2"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}

        ck = self._cache_key("opensquat", query_type, query)
        cached = self._get_cached(ck, ttl=300)  # 5-minute cache
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"Authorization": f"Bearer {self.api_key}"}

        # openSquat primary endpoint: find lookalike domains for a keyword/domain
        result = await self._request(
            "GET",
            f"{self.base_url}/domain/{query}",
            headers=headers,
        )

        self._set_cache(ck, result)
        return result
