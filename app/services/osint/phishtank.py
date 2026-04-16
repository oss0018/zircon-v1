from app.services.osint.base import BaseOSINTClient


class PhishTankClient(BaseOSINTClient):
    service_name = "phishtank"
    base_url = "https://checkurl.phishtank.com"

    async def search(self, query: str, query_type: str = "url") -> dict:
        ck = self._cache_key("phishtank", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        params: dict = {"url": query, "format": "json"}
        if self.api_key:
            params["app_key"] = self.api_key

        result = await self._request("POST", f"{self.base_url}/checkurl/", data=params)
        self._set_cache(ck, result)
        return result
