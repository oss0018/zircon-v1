"""
DNS Intelligence Module — subdomain enumeration, passive DNS, reverse IP.
"""
import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


class DNSIntelligenceModule:
    def __init__(self, keys: dict[str, str]):
        self._keys = keys

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _has(self, service: str) -> bool:
        return bool(self._keys.get(service))

    def _client(self, service: str):
        from app.services.osint import get_client
        return get_client(service, self._keys.get(service, ""))

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    async def enumerate_subdomains(self, domain: str) -> list[dict]:
        """Query available sources in parallel, deduplicate, return finding dicts."""
        tasks: list[Any] = []
        labels: list[str] = []

        # crt.sh — no key needed
        tasks.append(self._crtsh_subdomains(domain))
        labels.append("crtsh")

        # SecurityTrails
        if self._has("securitytrails"):
            tasks.append(self._securitytrails_subdomains(domain))
            labels.append("securitytrails")

        # Shodan
        if self._has("shodan"):
            tasks.append(self._shodan_subdomains(domain))
            labels.append("shodan")

        # VirusTotal
        if self._has("virustotal"):
            tasks.append(self._virustotal_subdomains(domain))
            labels.append("virustotal")

        # AlienVault
        if self._has("alienvault"):
            tasks.append(self._alienvault_subdomains(domain))
            labels.append("alienvault")

        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Merge: {fqdn -> set of sources}
        seen: dict[str, set[str]] = {}
        for label, res in zip(labels, results):
            if isinstance(res, Exception):
                logger.debug("DNS enum error from %s: %s", label, res)
                continue
            for sub in res:
                fqdn = sub.lower().lstrip("*.").strip()
                if not fqdn:
                    continue
                seen.setdefault(fqdn, set()).add(label)

        findings = [
            {
                "fqdn": fqdn,
                "sources": sorted(srcs),
                "entity": fqdn,
                "module": "dns",
                "finding_type": "subdomain",
                "severity": 1,
                "source": ",".join(sorted(srcs)),
                "data_json": {"sources": sorted(srcs)},
            }
            for fqdn, srcs in seen.items()
        ]
        return findings

    async def get_passive_dns(self, domain: str) -> list[dict]:
        """Query historical DNS records from SecurityTrails and AlienVault."""
        tasks = []
        if self._has("securitytrails"):
            tasks.append(self._securitytrails_history(domain))
        if self._has("alienvault"):
            tasks.append(self._alienvault_passive(domain))

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings: list[dict] = []
        for res in results:
            if isinstance(res, Exception):
                logger.debug("Passive DNS error: %s", res)
                continue
            findings.extend(res)
        return findings

    async def reverse_ip_lookup(self, ip: str) -> list[dict]:
        """Find co-hosted domains for an IP via SecurityTrails and Shodan."""
        tasks = []
        if self._has("securitytrails"):
            tasks.append(self._securitytrails_reverse_ip(ip))
        if self._has("shodan"):
            tasks.append(self._shodan_reverse_ip(ip))

        if not tasks:
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)
        seen: set[str] = set()
        findings: list[dict] = []
        for res in results:
            if isinstance(res, Exception):
                continue
            for f in res:
                e = f.get("entity", "")
                if e and e not in seen:
                    seen.add(e)
                    findings.append(f)
        return findings

    async def run(self, target: str, target_type: str) -> list[dict]:
        """Orchestrate all DNS sub-functions for the target."""
        findings: list[dict] = []
        if target_type == "domain":
            findings.extend(await self.enumerate_subdomains(target))
            findings.extend(await self.get_passive_dns(target))
        elif target_type == "ip":
            findings.extend(await self.reverse_ip_lookup(target))
        return findings

    # ------------------------------------------------------------------
    # Source-specific helpers
    # ------------------------------------------------------------------

    async def _crtsh_subdomains(self, domain: str) -> list[str]:
        client = self._client("crtsh")
        if not client:
            return []
        res = await client.search(domain, "subdomains")
        return res.get("subdomains", [])

    async def _securitytrails_subdomains(self, domain: str) -> list[str]:
        import httpx
        key = self._keys.get("securitytrails", "")
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.get(
                    f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                    headers={"APIKEY": key, "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    return [f"{s}.{domain}" for s in (data.get("subdomains") or [])]
        except Exception as exc:
            logger.debug("SecurityTrails subdomains error: %s", exc)
        return []

    async def _shodan_subdomains(self, domain: str) -> list[str]:
        client = self._client("shodan")
        if not client:
            return []
        res = await client.search(domain, "domain")
        return [f"{s}.{domain}" for s in (res.get("subdomains") or [])]

    async def _virustotal_subdomains(self, domain: str) -> list[str]:
        client = self._client("virustotal")
        if not client:
            return []
        res = await client.search(domain, "domain")
        subs: list[str] = []
        data_section = res.get("data", {})
        if isinstance(data_section, dict):
            attrs = data_section.get("attributes", {})
            for rel in ("subdomains", "last_dns_records"):
                for item in attrs.get(rel) or []:
                    if isinstance(item, dict):
                        subs.append(item.get("value", ""))
                    elif isinstance(item, str):
                        subs.append(item)
        return [s for s in subs if s]

    async def _alienvault_subdomains(self, domain: str) -> list[str]:
        client = self._client("alienvault")
        if not client:
            return []
        res = await client.search(domain, "domain")
        subs = []
        for r in res.get("passive_dns") or []:
            h = r.get("hostname") or r.get("domain") or ""
            if h:
                subs.append(h)
        return subs

    async def _securitytrails_history(self, domain: str) -> list[dict]:
        import httpx
        key = self._keys.get("securitytrails", "")
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.get(
                    f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
                    headers={"APIKEY": key, "Accept": "application/json"},
                )
                if resp.status_code == 200:
                    records = resp.json().get("records") or []
                    return [
                        {
                            "entity": r.get("values", [{}])[0].get("ip", domain) if r.get("values") else domain,
                            "module": "dns",
                            "finding_type": "historical_dns",
                            "severity": 1,
                            "source": "securitytrails",
                            "data_json": r,
                        }
                        for r in records
                    ]
        except Exception as exc:
            logger.debug("SecurityTrails history error: %s", exc)
        return []

    async def _alienvault_passive(self, domain: str) -> list[dict]:
        client = self._client("alienvault")
        if not client:
            return []
        res = await client.search(domain, "domain")
        findings = []
        for r in res.get("passive_dns") or []:
            findings.append({
                "entity": r.get("address") or r.get("hostname") or domain,
                "module": "dns",
                "finding_type": "historical_dns",
                "severity": 1,
                "source": "alienvault",
                "data_json": r,
            })
        return findings

    async def _securitytrails_reverse_ip(self, ip: str) -> list[dict]:
        import httpx
        key = self._keys.get("securitytrails", "")
        try:
            async with httpx.AsyncClient(timeout=15) as c:
                resp = await c.post(
                    "https://api.securitytrails.com/v1/domains/list",
                    headers={"APIKEY": key, "Accept": "application/json"},
                    json={"filter": {"ipv4": ip}},
                )
                if resp.status_code == 200:
                    records = resp.json().get("records") or []
                    return [
                        {
                            "entity": r.get("hostname") or r.get("name") or ip,
                            "module": "dns",
                            "finding_type": "reverse_ip",
                            "severity": 2,
                            "source": "securitytrails",
                            "data_json": r,
                        }
                        for r in records
                    ]
        except Exception as exc:
            logger.debug("SecurityTrails reverse IP error: %s", exc)
        return []

    async def _shodan_reverse_ip(self, ip: str) -> list[dict]:
        client = self._client("shodan")
        if not client:
            return []
        res = await client.search(ip, "ip")
        hostnames = res.get("hostnames") or []
        return [
            {
                "entity": h,
                "module": "dns",
                "finding_type": "reverse_ip",
                "severity": 2,
                "source": "shodan",
                "data_json": {"ip": ip, "hostname": h},
            }
            for h in hostnames
        ]
