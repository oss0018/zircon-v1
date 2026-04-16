from app.services.osint.base import BaseOSINTClient


class URLScanClient(BaseOSINTClient):
    service_name = "urlscan"
    base_url = "https://urlscan.io/api/v1"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("urlscan", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
        if query_type == "url":
            # Submit URL for scanning
            result = await self._request(
                "POST",
                f"{self.base_url}/scan/",
                headers=headers,
                json={"url": query, "visibility": "private"},
            )
        else:
            # Search existing scans
            q = f"domain:{query}" if query_type == "domain" else f"ip:{query}" if query_type == "ip" else query
            result = await self._request(
                "GET",
                f"{self.base_url}/search/",
                headers=headers,
                params={"q": q, "size": 20},
            )
        self._set_cache(ck, result)
        return result
