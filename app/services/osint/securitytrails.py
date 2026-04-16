from app.services.osint.base import BaseOSINTClient


class SecurityTrailsClient(BaseOSINTClient):
    service_name = "securitytrails"
    base_url = "https://api.securitytrails.com/v1"

    async def search(self, query: str, query_type: str = "domain") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("securitytrails", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"APIKEY": self.api_key, "Accept": "application/json"}
        if query_type == "domain":
            result = await self._request("GET", f"{self.base_url}/domain/{query}", headers=headers)
        elif query_type == "ip":
            result = await self._request(
                "POST",
                f"{self.base_url}/domains/list",
                headers=headers,
                json={"filter": {"ipv4": query}},
            )
        else:
            result = await self._request(
                "POST",
                f"{self.base_url}/domains/list",
                headers=headers,
                json={"filter": {"keyword": query}},
            )
        self._set_cache(ck, result)
        return result
