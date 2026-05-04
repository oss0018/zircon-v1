"""
ThreatFox client (abuse.ch) — free, no API key required.
Supports: hash, IP, domain, URL, tag lookups.
"""
from app.services.osint.base import BaseOSINTClient


class ThreatFoxClient(BaseOSINTClient):
    service_name = "threatfox"
    base_url = "https://threatfox-api.abuse.ch/api/v1"

    async def search(self, query: str, query_type: str = "general") -> dict:
        ck = self._cache_key("threatfox", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        if query_type == "hash":
            payload = {"query": "search_hash", "hash": query}
        elif query_type == "ip":
            payload = {"query": "search_ioc", "search_term": query}
        elif query_type == "domain":
            payload = {"query": "search_ioc", "search_term": query}
        elif query_type == "url":
            payload = {"query": "search_ioc", "search_term": query}
        else:
            # General search by term
            payload = {"query": "search_ioc", "search_term": query}

        result = await self._request("POST", self.base_url, json=payload)
        self._set_cache(ck, result)
        return result
