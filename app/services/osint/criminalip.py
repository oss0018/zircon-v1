from app.services.osint.base import BaseOSINTClient


class CriminalIPClient(BaseOSINTClient):
    service_name = "criminalip"
    base_url = "https://api.criminalip.io/v1"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("criminalip", query_type, query)
        cached = self._get_cached(ck, ttl=3600)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"x-api-key": self.api_key}
        if query_type == "ip":
            result = await self._request(
                "GET",
                f"{self.base_url}/asset/ip/report",
                headers=headers,
                params={"ip": query},
            )
        elif query_type == "domain":
            result = await self._request("GET", f"{self.base_url}/domain/report/{query}", headers=headers)
        else:
            result = await self._request(
                "GET",
                f"{self.base_url}/banner/search",
                headers=headers,
                params={"query": query, "offset": 0},
            )
        self._set_cache(ck, result)
        return result
