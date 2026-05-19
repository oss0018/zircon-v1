import base64

from app.services.osint.base import BaseOSINTClient


class FOFAClient(BaseOSINTClient):
    service_name = "fofa"
    base_url = "https://fofa.info/api/v1"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}
        parts = self.api_key.split(":", 1)
        if len(parts) != 2:
            return {"error": "Invalid API key format. Expected email:api_key"}
        email, key = parts[0].strip(), parts[1].strip()
        if not email or not key:
            return {"error": "Invalid API key format. Expected email:api_key"}

        if query_type == "domain":
            q = f'domain="{query}"'
        elif query_type == "ip":
            q = f'ip="{query}"'
        elif query_type == "org":
            q = f'org="{query}"'
        else:
            q = query

        ck = self._cache_key("fofa", query_type, query)
        cached = self._get_cached(ck, ttl=3600)
        if cached is not None:
            return {**cached, "cached": True}

        qbase64 = base64.b64encode(q.encode()).decode()
        result = await self._request(
            "GET",
            f"{self.base_url}/search/all",
            params={
                "qbase64": qbase64,
                "email": email,
                "key": key,
                "fields": "host,ip,port,protocol,title,server",
                "size": 100,
            },
        )
        self._set_cache(ck, result)
        return result
