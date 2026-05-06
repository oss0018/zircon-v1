from app.services.osint.base import BaseOSINTClient

INTELX_DEFAULT_BASE_URL = "https://free.intelx.io"


class IntelXClient(BaseOSINTClient):
    service_name = "intelx"

    def __init__(self, api_key: str = "", base_url: str = "", **kwargs):
        super().__init__(api_key=api_key, **kwargs)
        # Use provided base_url (stripped, no trailing slash) or fall back to default
        self.base_url = (base_url or INTELX_DEFAULT_BASE_URL).strip().rstrip("/") or INTELX_DEFAULT_BASE_URL

    async def test_connection(self):
        """Verify the API key by calling /authenticate/info (no credits consumed)."""
        if not self.api_key:
            return {"ok": False, "error": "API key not configured"}
        result = await self._request(
            "GET",
            f"{self.base_url}/authenticate/info",
            headers={"x-key": self.api_key},
        )
        if "error" in result:
            return {"ok": False, "error": result["error"]}
        return {"ok": True, "result": result}

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("intelx", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"x-key": self.api_key}
        # Start search
        search_resp = await self._request(
            "POST",
            f"{self.base_url}/intelligent/search",
            headers=headers,
            json={"term": query, "buckets": [], "lookuplevel": 0, "maxresults": 20,
                  "timeout": 5, "datefrom": "", "dateto": "", "sort": 4,
                  "media": 0, "terminate": []},
        )
        if "error" in search_resp:
            return search_resp

        search_id = search_resp.get("id", "")
        if not search_id:
            return {"error": "No search ID returned", "raw": search_resp}

        # Fetch results
        result = await self._request(
            "GET",
            f"{self.base_url}/intelligent/search/result",
            headers=headers,
            params={"id": search_id, "limit": 20, "offset": 0},
        )
        self._set_cache(ck, result)
        return result
