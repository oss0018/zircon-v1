from app.services.osint.base import BaseOSINTClient


class HIBPClient(BaseOSINTClient):
    service_name = "hibp"
    base_url = "https://haveibeenpwned.com/api/v3"

    async def search(self, query: str, query_type: str = "email") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("hibp", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {
            "hibp-api-key": self.api_key,
            "User-Agent": "Zircon-FRT-OSINT/1.0",
        }
        if query_type == "email":
            result = await self._request(
                "GET",
                f"{self.base_url}/breachedaccount/{query}",
                headers=headers,
                params={"truncateResponse": "false"},
            )
        elif query_type == "domain":
            result = await self._request(
                "GET",
                f"{self.base_url}/breaches",
                headers=headers,
                params={"domain": query},
            )
        else:
            result = await self._request("GET", f"{self.base_url}/breaches", headers=headers)

        if "not_found" in result:
            result = {"breaches": [], "message": "No breaches found"}
        self._set_cache(ck, result)
        return result
