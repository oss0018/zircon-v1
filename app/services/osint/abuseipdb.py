from app.services.osint.base import BaseOSINTClient


class AbuseIPDBClient(BaseOSINTClient):
    service_name = "abuseipdb"
    base_url = "https://api.abuseipdb.com/api/v2"

    async def search(self, query: str, query_type: str = "ip") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        ck = self._cache_key("abuseipdb", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        headers = {"Key": self.api_key, "Accept": "application/json"}
        if query_type == "ip":
            result = await self._request(
                "GET",
                f"{self.base_url}/check",
                headers=headers,
                params={"ipAddress": query, "maxAgeInDays": 90, "verbose": ""},
            )
        else:
            # Blacklist / bulk check fallback
            result = await self._request(
                "GET",
                f"{self.base_url}/blacklist",
                headers=headers,
                params={"limit": 20},
            )
        self._set_cache(ck, result)
        return result
