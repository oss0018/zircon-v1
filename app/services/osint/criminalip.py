from app.services.osint.base import BaseOSINTClient


class CriminalIPClient(BaseOSINTClient):
    service_name = "criminalip"
    base_url = "https://api.criminalip.io"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}

        ck = self._cache_key("criminalip", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"x-api-key": self.api_key}
        if query_type == "ip":
            result = await self._request(
                "GET",
                f"{self.base_url}/v1/asset/ip/summary",
                params={"ip": query},
                headers=headers,
            )
        elif query_type == "domain":
            result = await self._request(
                "GET",
                f"{self.base_url}/v1/domain/search",
                params={"query": query},
                headers=headers,
            )
        else:
            result = await self._request(
                "GET",
                f"{self.base_url}/v1/banner/search",
                params={"query": query, "offset": 0},
                headers=headers,
            )

        self._set_cache(ck, result)
        return result
