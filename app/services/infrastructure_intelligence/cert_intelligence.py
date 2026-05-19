"""
Certificate Intelligence Module — Certificate Transparency log search and
self-signed/expired certificate detection via TLS handshake.
"""
import ipaddress
import logging

from app.services.infrastructure_intelligence.self_signed_cert_analyzer import (
    SelfSignedCertAnalyzer,
)

logger = logging.getLogger(__name__)


class CertIntelligenceModule:
    def __init__(self, keys: dict[str, str]):
        self._keys = keys

    def _client(self, service: str):
        from app.services.osint import get_client
        return get_client(service, self._keys.get(service, ""))

    async def search_ct_logs(self, domain: str) -> list[dict]:
        """Query crt.sh for certificates issued to *.{domain} and {domain}."""
        client = self._client("crtsh")
        if not client:
            return []

        res = await client.search(domain, "domain")
        certs = res.get("certificates") or []

        findings: list[dict] = []
        seen: set[str] = set()

        for cert in certs:
            name_value = cert.get("name_value", "") or ""
            common_name = cert.get("common_name", "") or name_value
            serial = cert.get("serial_number", "")

            # Deduplicate by serial number
            if serial and serial in seen:
                continue
            if serial:
                seen.add(serial)

            is_wildcard = common_name.startswith("*.")
            severity = 3 if is_wildcard else 1

            san_list = [n.strip() for n in name_value.split("\n") if n.strip()]

            findings.append({
                "entity": common_name or domain,
                "module": "cert",
                "finding_type": "certificate",
                "severity": severity,
                "source": "crtsh",
                "data_json": {
                    "issuer": cert.get("issuer_name", ""),
                    "not_before": cert.get("not_before", ""),
                    "not_after": cert.get("not_after", ""),
                    "serial": serial,
                    "san_count": len(san_list),
                    "common_name": common_name,
                    "is_wildcard": is_wildcard,
                    "id": cert.get("id"),
                    "logged_at": cert.get("entry_timestamp", ""),
                },
            })

        return findings

    async def analyze_self_signed(self, ips: list[str]) -> list[dict]:
        """Run self-signed/expired certificate analysis against a list of IPs."""
        analyzer = SelfSignedCertAnalyzer()
        return await analyzer.analyze_targets(ips)

    async def run(self, target: str, target_type: str) -> list[dict]:
        if target_type == "domain":
            return await self.search_ct_logs(target)
        if target_type == "ip":
            return await self.analyze_self_signed([target])
        if target_type == "cidr":
            try:
                network = ipaddress.ip_network(target, strict=False)
                ips = [str(h) for h in list(network.hosts())[:64]]
            except ValueError:
                return []
            return await self.analyze_self_signed(ips)
        return []
