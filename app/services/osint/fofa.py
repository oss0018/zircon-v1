import base64

from app.services.osint.base import BaseOSINTClient

_MAX_FOFA_RESULTS = 50


class FOFAClient(BaseOSINTClient):
    service_name = "fofa"
    base_url = "https://fofa.info/api/v1"

    async def search(self, query: str, query_type: str = "general") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}

        parts = self.api_key.split(":", 1)
        if len(parts) != 2:
            return {"error": "Invalid API key format (expected email:api_key)"}
        email, key = parts

        ck = self._cache_key("fofa", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        if query_type == "domain":
            fofa_query = f'domain="{query}"'
        elif query_type == "ip":
            fofa_query = f'ip="{query}"'
        else:
            fofa_query = query

        qbase64 = base64.b64encode(fofa_query.encode("utf-8")).decode("utf-8")
        result = await self._request(
            "GET",
            f"{self.base_url}/search/all",
            params={
                "email": email,
                "key": key,
                "qbase64": qbase64,
                "size": _MAX_FOFA_RESULTS,
                "fields": "host,ip,port,protocol,server,title",
            },
        )
        self._set_cache(ck, result)
        return result
