from app.services.osint.base import BaseOSINTClient


class AlienVaultClient(BaseOSINTClient):
    service_name = "alienvault"
    base_url = "https://otx.alienvault.com/api/v1"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("alienvault", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"X-OTX-API-KEY": self.api_key}
        if query_type == "ip":
            result = await self._request(
                "GET", f"{self.base_url}/indicators/IPv4/{query}/general", headers=headers
            )
        elif query_type == "domain":
            result = await self._request(
                "GET", f"{self.base_url}/indicators/domain/{query}/general", headers=headers
            )
        elif query_type == "url":
            result = await self._request(
                "GET", f"{self.base_url}/indicators/url/{query}/general", headers=headers
            )
        elif query_type == "hash":
            result = await self._request(
                "GET", f"{self.base_url}/indicators/file/{query}/general", headers=headers
            )
        else:
            result = await self._request(
                "GET",
                f"{self.base_url}/search/pulses",
                headers=headers,
                params={"q": query, "page": 1, "limit": 20},
            )
        self._set_cache(ck, result)
        return result
