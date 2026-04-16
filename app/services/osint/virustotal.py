from app.services.osint.base import BaseOSINTClient


class VirusTotalClient(BaseOSINTClient):
    service_name = "virustotal"
    base_url = "https://www.virustotal.com/api/v3"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("virustotal", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"x-apikey": self.api_key}
        if query_type == "url":
            import base64
            url_id = base64.urlsafe_b64encode(query.encode()).decode().strip("=")
            result = await self._request("GET", f"{self.base_url}/urls/{url_id}", headers=headers)
        elif query_type == "domain":
            result = await self._request("GET", f"{self.base_url}/domains/{query}", headers=headers)
        elif query_type == "ip":
            result = await self._request("GET", f"{self.base_url}/ip_addresses/{query}", headers=headers)
        elif query_type == "hash":
            result = await self._request("GET", f"{self.base_url}/files/{query}", headers=headers)
        else:
            result = await self._request(
                "GET",
                f"{self.base_url}/search",
                headers=headers,
                params={"query": query},
            )
        self._set_cache(ck, result)
        return result
