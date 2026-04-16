from app.services.osint.base import BaseOSINTClient


class IntelXClient(BaseOSINTClient):
    service_name = "intelx"
    base_url = "https://2.intelx.io"

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
