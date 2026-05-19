"""
WhoisXML API adapter.
Supports whois lookup, reverse whois, reverse IP, and DNS history.
"""
from app.services.osint.base import BaseOSINTClient


class WhoisXMLClient(BaseOSINTClient):
    service_name = "whoisxml"
    base_url = "https://www.whoisxmlapi.com"

    async def search(self, query: str, query_type: str = "domain") -> dict:
        if not self.api_key:
            return {"error": "API key not configured"}

        ck = self._cache_key("whoisxml", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        if query_type == "domain":
            result = await self._request(
                "GET",
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={"domainName": query, "apiKey": self.api_key, "outputFormat": "JSON"},
            )
        elif query_type == "reverse_whois":
            result = await self._request(
                "POST",
                "https://reverse-whois-api.whoisxmlapi.com/api/v2",
                json={
                    "apiKey": self.api_key,
                    "searchType": "current",
                    "basicSearchTerms": {"include": [query]},
                },
            )
        elif query_type == "reverse_ip":
            result = await self._request(
                "GET",
                "https://reverse-ip-api.whoisxmlapi.com/api/v1",
                params={"ip": query, "apiKey": self.api_key, "outputFormat": "JSON"},
            )
        elif query_type == "dns_history":
            result = await self._request(
                "GET",
                "https://dns-history.whoisxmlapi.com/api/v1",
                params={"apiKey": self.api_key, "domainName": query, "type": "A"},
            )
        else:
            result = await self._request(
                "GET",
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={"domainName": query, "apiKey": self.api_key, "outputFormat": "JSON"},
            )

        self._set_cache(ck, result)
        return result
