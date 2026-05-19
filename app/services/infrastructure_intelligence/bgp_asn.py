"""
BGP/ASN Intelligence Module using free RIPEstat and BGPView APIs.
"""
import asyncio
import json
import logging

import httpx

logger = logging.getLogger(__name__)
_MAX_PREFIX_RESULTS = 50
_MAX_NEIGHBOR_RESULTS = 20
_MAX_ORG_ASN_CANDIDATES = 3


def _normalize_asn(asn: str) -> str:
    clean = str(asn).strip().upper()
    if clean.startswith("AS"):
        clean = clean[2:]
    return clean


class BGPASNModule:
    def __init__(self, keys: dict[str, str]):
        self._keys = keys

    async def _get_json(self, url: str, params: dict | None = None) -> dict:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(url, params=params or {})
                if resp.status_code == 200:
                    return resp.json()
        except Exception as exc:
            logger.debug("BGP/ASN request error: %s", exc)
        return {}

    async def asn_overview(self, asn: str) -> dict:
        asn_num = _normalize_asn(asn)
        ripe_task = self._get_json(
            "https://stat.ripe.net/data/as-overview/data.json",
            params={"resource": f"AS{asn_num}"},
        )
        bgpview_task = self._get_json(f"https://api.bgpview.io/asn/{asn_num}")
        ripe_res, bgpview_res = await asyncio.gather(ripe_task, bgpview_task, return_exceptions=True)
        return {
            "asn": f"AS{asn_num}",
            "ripe": {} if isinstance(ripe_res, Exception) else ripe_res,
            "bgpview": {} if isinstance(bgpview_res, Exception) else bgpview_res,
        }

    async def asn_prefixes(self, asn: str) -> list[dict]:
        asn_num = _normalize_asn(asn)
        res = await self._get_json(f"https://api.bgpview.io/asn/{asn_num}/prefixes")
        data = res.get("data") or {}
        ipv4 = data.get("ipv4_prefixes") or []
        ipv6 = data.get("ipv6_prefixes") or []
        # Cap output to keep payloads bounded for UI and DB storage.
        return (ipv4 + ipv6)[:_MAX_PREFIX_RESULTS]

    async def ip_to_asn(self, ip: str) -> dict:
        res = await self._get_json(
            "https://stat.ripe.net/data/network-info/data.json",
            params={"resource": ip},
        )
        data = res.get("data") or {}
        asns = data.get("asns") or []
        return {"ip": ip, "asns": asns}

    async def asn_neighbours(self, asn: str) -> list[dict]:
        asn_num = _normalize_asn(asn)
        res = await self._get_json(
            "https://stat.ripe.net/data/asn-neighbours/data.json",
            params={"resource": f"AS{asn_num}"},
        )
        neighbours = (res.get("data") or {}).get("neighbours") or []
        # Limit neighbours to the most relevant slice from upstream response.
        return neighbours[:_MAX_NEIGHBOR_RESULTS]

    async def search_org(self, name: str) -> list[str]:
        res = await self._get_json("https://api.bgpview.io/search", params={"query_term": name})
        asn_entries = (res.get("data") or {}).get("asns") or []
        # Keep org discovery focused by returning top few ASN candidates only.
        return [f"AS{a.get('asn')}" for a in asn_entries if a.get("asn")][:_MAX_ORG_ASN_CANDIDATES]

    async def run(self, target: str, target_type: str) -> list[dict]:
        findings: list[dict] = []

        if target_type == "asn":
            overview = await self.asn_overview(target)
            asn_val = overview.get("asn", str(target))
            prefixes = await self.asn_prefixes(asn_val)
            neighbours = await self.asn_neighbours(asn_val)
            findings.append(self._finding(asn_val, "asn_overview", "ripe,bgpview", overview))
            findings.append(self._finding(asn_val, "asn_prefixes", "bgpview", {"prefixes": prefixes}))
            findings.append(self._finding(asn_val, "asn_neighbours", "ripe", {"neighbours": neighbours}))
            return findings

        if target_type == "ip":
            mapping = await self.ip_to_asn(target)
            findings.append(self._finding(target, "ip_to_asn", "ripe", mapping))
            asns = mapping.get("asns") or []
            if not asns:
                return findings
            asn_val = f"AS{asns[0]}"
            overview = await self.asn_overview(asn_val)
            prefixes = await self.asn_prefixes(asn_val)
            findings.append(self._finding(asn_val, "asn_overview", "ripe,bgpview", overview))
            findings.append(self._finding(asn_val, "asn_prefixes", "bgpview", {"prefixes": prefixes}))
            return findings

        if target_type == "org":
            asns = await self.search_org(target)
            findings.append(self._finding(target, "org_asn_search", "bgpview", {"asns": asns}))
            return findings

        return []

    def _finding(self, entity: str, finding_type: str, source: str, data: dict) -> dict:
        return {
            "entity": entity,
            "module": "bgp_asn",
            "finding_type": finding_type,
            "severity": 1,
            "source": source,
            "data_json": json.dumps(data),
        }
