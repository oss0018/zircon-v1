from app.services.osint.base import BaseOSINTClient


class ZoomEyeClient(BaseOSINTClient):
    service_name = "zoomeye"
    base_url = "https://api.zoomeye.org"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("zoomeye", query_type, query)
        cached = self._get_cached(ck, ttl=3600)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"API-KEY": self.api_key}
        if query_type == "ip":
            path = "/host/search"
            params = {"query": f"ip:{query}", "page": 1}
        elif query_type == "domain":
            path = "/web/search"
            params = {"query": f"site:{query}", "page": 1}
        elif query_type == "org":
            path = "/host/search"
            params = {"query": f'org:"{query}"', "page": 1}
        else:
            path = "/host/search"
            params = {"query": query, "page": 1}

        result = await self._request("GET", f"{self.base_url}{path}", headers=headers, params=params)
        self._set_cache(ck, result)
        return result
