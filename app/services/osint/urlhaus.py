from app.services.osint.base import BaseOSINTClient


class URLhausClient(BaseOSINTClient):
    service_name = "urlhaus"
    base_url = "https://urlhaus-api.abuse.ch/v1"

    async def test_connection(self):
        """Verify connectivity by fetching recent URLs (no query needed, always works)."""
        result = await self._request("POST", f"{self.base_url}/urls/recent/")
        if "error" in result:
            return {"ok": False, "error": result["error"]}
        return {"ok": True, "result": result}

    async def search(self, query: str, query_type: str = "url") -> dict:
        # URLhaus is free – no API key required but we keep the pattern
        ck = self._cache_key("urlhaus", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        if query_type == "url":
            result = await self._request("POST", f"{self.base_url}/url/", data={"url": query})
        elif query_type in ("ip", "domain"):
            result = await self._request("POST", f"{self.base_url}/host/", data={"host": query})
        elif query_type == "hash":
            result = await self._request("POST", f"{self.base_url}/payload/", data={"md5_hash": query})
        else:
            result = await self._request("POST", f"{self.base_url}/host/", data={"host": query})

        self._set_cache(ck, result)
        return result
