import asyncio
import re

from app.services.osint.base import BaseOSINTClient


class BGPViewClient(BaseOSINTClient):
    service_name = "bgpview"
    base_url = "https://api.bgpview.io"

    def _normalize_asn(self, query: str) -> str:
        q = str(query).strip().upper()
        match = re.search(r"(\d+)", q)
        if match:
            return match.group(1)
        fallback = q[2:] if q.startswith("AS") else q
        return fallback if fallback.isdigit() else ""

    async def search(self, query: str, query_type: str = "general") -> dict:
        ck = self._cache_key("bgpview", query_type, query)
        cached = self._get_cached(ck, ttl=7200)
        if cached is not None:
            return {**cached, "cached": True}

        if query_type == "asn":
            asn = self._normalize_asn(query)
            if not asn:
                return {"error": "Invalid ASN"}
            asn_info, asn_prefixes = await asyncio.gather(
                self._request("GET", f"{self.base_url}/asn/{asn}"),
                self._request("GET", f"{self.base_url}/asn/{asn}/prefixes"),
            )
            result = {"asn": asn, "asn_info": asn_info, "prefixes": asn_prefixes}
        elif query_type == "ip":
            result = await self._request("GET", f"{self.base_url}/ip/{query}")
        elif query_type == "prefix":
            result = await self._request("GET", f"{self.base_url}/prefix/{query}")
        else:
            result = await self._request(
                "GET",
                f"{self.base_url}/search",
                params={"query_term": query},
            )

        self._set_cache(ck, result)
        return result

    async def test_connection(self) -> dict:
        result = await self.search("3333", "asn")
        ok = "error" not in result
        return {"ok": ok, "result": result}
