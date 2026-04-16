from app.services.osint.base import BaseOSINTClient


class ShodanClient(BaseOSINTClient):
    service_name = "shodan"
    base_url = "https://api.shodan.io"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("shodan", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        params = {"key": self.api_key}
        if query_type == "ip":
            result = await self._request("GET", f"{self.base_url}/shodan/host/{query}", params=params)
        elif query_type == "domain":
            result = await self._request("GET", f"{self.base_url}/dns/domain/{query}", params=params)
        else:
            result = await self._request(
                "GET",
                f"{self.base_url}/shodan/host/search",
                params={**params, "query": query, "page": 1},
            )
        self._set_cache(ck, result)
        return result
