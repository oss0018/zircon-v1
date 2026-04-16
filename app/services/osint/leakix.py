from app.services.osint.base import BaseOSINTClient


class LeakIXClient(BaseOSINTClient):
    service_name = "leakix"
    base_url = "https://leakix.net"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("leakix", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"api-key": self.api_key, "Accept": "application/json"}
        if query_type == "ip":
            result = await self._request("GET", f"{self.base_url}/host/{query}", headers=headers)
        elif query_type == "domain":
            result = await self._request("GET", f"{self.base_url}/domain/{query}", headers=headers)
        else:
            result = await self._request(
                "GET",
                f"{self.base_url}/search",
                headers=headers,
                params={"q": query, "scope": "leak", "page": 0},
            )
        self._set_cache(ck, result)
        return result
