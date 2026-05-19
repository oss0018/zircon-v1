import asyncio
import json
import re

from app.services.osint.bgpview import BGPViewClient
from app.services.osint.ripestat import RIPEStatClient


class BGPASNModule:
    def __init__(self, _keys: dict[str, str]):
        self.ripestat = RIPEStatClient(api_key="")
        self.bgpview = BGPViewClient(api_key="")

    def _normalize_asn(self, asn: str) -> str:
        match = re.search(r"(\d+)", str(asn))
        if match:
            return match.group(1)
        clean = str(asn).upper()
        fallback = clean[2:] if clean.startswith("AS") else clean
        return fallback if fallback.isdigit() else ""

    async def lookup_asn(self, asn: str) -> list[dict]:
        asn_n = self._normalize_asn(asn)
        if not asn_n:
            return []
        ripe_task = self.ripestat.search(asn_n, "asn")
        bgp_task = self.bgpview.search(asn_n, "asn")
        ripe_res, bgp_res = await asyncio.gather(ripe_task, bgp_task, return_exceptions=True)

        findings: list[dict] = []
        findings.append(
            {
                "entity": f"AS{asn_n}",
                "module": "bgp_asn",
                "finding_type": "asn_info",
                "severity": 1,
                "source": "ripestat,bgpview",
                "data_json": json.dumps(
                    {
                        "asn": asn_n,
                        "ripestat": {} if isinstance(ripe_res, Exception) else ripe_res,
                        "bgpview": {} if isinstance(bgp_res, Exception) else bgp_res,
                    }
                ),
            }
        )

        prefixes: list[str] = []
        if isinstance(ripe_res, dict):
            ripe_prefixes = (
                ripe_res.get("announced_prefixes", {}).get("data", {}).get("prefixes")
                or []
            )
            prefixes.extend([p.get("prefix") for p in ripe_prefixes if isinstance(p, dict) and p.get("prefix")])
        if isinstance(bgp_res, dict):
            ipv4 = bgp_res.get("prefixes", {}).get("data", {}).get("ipv4_prefixes") or []
            ipv6 = bgp_res.get("prefixes", {}).get("data", {}).get("ipv6_prefixes") or []
            prefixes.extend([p.get("prefix") for p in [*ipv4, *ipv6] if isinstance(p, dict) and p.get("prefix")])

        for prefix in list(dict.fromkeys(prefixes))[:50]:
            findings.append(
                {
                    "entity": prefix,
                    "module": "bgp_asn",
                    "finding_type": "ip_prefix",
                    "severity": 1,
                    "source": "ripestat,bgpview",
                    "data_json": json.dumps({"asn": asn_n, "prefix": prefix}),
                }
            )

        peers: list[str] = []
        if isinstance(ripe_res, dict):
            neigh = ripe_res.get("asn_neighbours", {}).get("data", {}).get("neighbours") or []
            peers.extend(
                [
                    str(n.get("asn"))
                    for n in neigh
                    if isinstance(n, dict) and n.get("asn") is not None
                ]
            )
        if isinstance(bgp_res, dict):
            peers_data = bgp_res.get("asn_info", {}).get("data", {}).get("peers") or {}
            ipv4 = peers_data.get("ipv4") or {}
            ipv6 = peers_data.get("ipv6") or {}
            peer_entries = [*(ipv4.get("full_feed") or []), *(ipv6.get("full_feed") or [])]
            peers.extend(
                [
                    str(n.get("asn"))
                    for n in peer_entries
                    if isinstance(n, dict) and n.get("asn") is not None
                ]
            )

        for peer in list(dict.fromkeys(peers))[:20]:
            findings.append(
                {
                    "entity": f"AS{peer}",
                    "module": "bgp_asn",
                    "finding_type": "asn_peer",
                    "severity": 1,
                    "source": "ripestat,bgpview",
                    "data_json": json.dumps({"asn": asn_n, "peer_asn": peer}),
                }
            )

        return findings

    async def lookup_ip(self, ip: str) -> list[dict]:
        network_info = await self.ripestat.search(ip, "ip")
        if not isinstance(network_info, dict):
            return []
        data = network_info.get("data")
        if not isinstance(data, dict):
            return []
        asns = data.get("asns") or []
        if not asns:
            return []
        return await self.lookup_asn(str(asns[0]))

    async def lookup_org(self, org: str) -> list[dict]:
        search_res = await self.bgpview.search(org, "general")
        asn_entries = search_res.get("data", {}).get("asns") or []
        top_asns = [
            str(entry.get("asn"))
            for entry in asn_entries
            if isinstance(entry, dict) and entry.get("asn") is not None
        ][:3]
        if not top_asns:
            return []
        batches = await asyncio.gather(*(self.lookup_asn(asn) for asn in top_asns), return_exceptions=True)
        findings: list[dict] = []
        for batch in batches:
            if isinstance(batch, Exception):
                continue
            findings.extend(batch)
        return findings

    async def run(self, target: str, target_type: str) -> list[dict]:
        if target_type == "asn":
            return await self.lookup_asn(target)
        if target_type == "ip":
            return await self.lookup_ip(target)
        if target_type == "org":
            return await self.lookup_org(target)
        if target_type in {"cidr", "domain"}:
            return []
        return []
