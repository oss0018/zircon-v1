from app.services.osint.base import BaseOSINTClient


class CensysClient(BaseOSINTClient):
    service_name = "censys"
    base_url = "https://search.censys.io/api/v2"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        # api_key format: "api_id:api_secret"
        parts = self.api_key.split(":", 1)
        auth = (parts[0], parts[1]) if len(parts) == 2 else (self.api_key, "")

        ck = self._cache_key("censys", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        if query_type == "ip":
            result = await self._request("GET", f"{self.base_url}/hosts/{query}", auth=auth)
        elif query_type == "domain":
            result = await self._request(
                "POST",
                f"{self.base_url}/hosts/search",
                auth=auth,
                json={"q": f"dns.names: {query}", "per_page": 20},
            )
        else:
            result = await self._request(
                "POST",
                f"{self.base_url}/hosts/search",
                auth=auth,
                json={"q": query, "per_page": 20},
            )
        self._set_cache(ck, result)
        return result
