import asyncio
import re

from app.services.osint.base import BaseOSINTClient


class RIPEStatClient(BaseOSINTClient):
    service_name = "ripestat"
    base_url = "https://stat.ripe.net/data"

    def _normalize_asn(self, query: str) -> str:
        q = str(query).strip().upper()
        match = re.search(r"(\d+)", q)
        if match:
            return match.group(1)
        fallback = q[2:] if q.startswith("AS") else q
        return fallback if fallback.isdigit() else ""

    async def search(self, query: str, query_type: str = "general") -> dict:
        ck = self._cache_key("ripestat", query_type, query)
        cached = self._get_cached(ck, ttl=7200)
        if cached is not None:
            return {**cached, "cached": True}

        if query_type == "asn":
            asn = self._normalize_asn(query)
            if not asn:
                return {"error": "Invalid ASN"}
            resource = f"AS{asn}"
            overview_task = self._request(
                "GET",
                f"{self.base_url}/as-overview/data.json",
                params={"resource": resource},
            )
            prefixes_task = self._request(
                "GET",
                f"{self.base_url}/announced-prefixes/data.json",
                params={"resource": resource},
            )
            neighbours_task = self._request(
                "GET",
                f"{self.base_url}/asn-neighbours/data.json",
                params={"resource": resource},
            )
            overview, prefixes, neighbours = await asyncio.gather(
                overview_task,
                prefixes_task,
                neighbours_task,
            )
            result = {
                "asn": asn,
                "as_overview": overview,
                "announced_prefixes": prefixes,
                "asn_neighbours": neighbours,
            }
        elif query_type == "ip":
            result = await self._request(
                "GET",
                f"{self.base_url}/network-info/data.json",
                params={"resource": query},
            )
        elif query_type == "prefix":
            result = await self._request(
                "GET",
                f"{self.base_url}/prefix-overview/data.json",
                params={"resource": query},
            )
        else:
            result = await self._request(
                "GET",
                f"{self.base_url}/as-overview/data.json",
                params={"resource": query},
            )

        self._set_cache(ck, result)
        return result

    async def test_connection(self) -> dict:
        result = await self.search("3333", "asn")
        ok = "error" not in result
        return {"ok": ok, "result": result}
