"""
Certificate Intelligence Module — Certificate Transparency log search and
self-signed/expired certificate detection via TLS handshake.
"""
import ipaddress
import logging
from datetime import datetime, timezone

from app.services.infrastructure_intelligence.self_signed_cert_analyzer import (
    SelfSignedCertAnalyzer,
)

logger = logging.getLogger(__name__)
CERT_EXPIRY_WARNING_DAYS = 30


def _expiry_metadata(not_after: str) -> dict:
    """Return expiry state for a certificate transparency date, when parseable."""
    if not not_after:
        return {}

    try:
        expires_at = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return {}

    now = datetime.now(timezone.utc)
    days_until_expiry = (expires_at - now).days
    is_expired = expires_at < now
    if is_expired:
        severity, finding_type = 4, "expired_cert"
    elif days_until_expiry <= 7:
        severity, finding_type = 4, "expiring_cert"
    elif days_until_expiry <= CERT_EXPIRY_WARNING_DAYS:
        severity, finding_type = 3, "expiring_cert"
    else:
        severity, finding_type = 1, "certificate"

    return {
        "days_until_expiry": days_until_expiry,
        "is_expired": is_expired,
        "validity_status": finding_type,
        "severity": severity,
        "finding_type": finding_type,
    }


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
            not_after = cert.get("not_after", "") or ""
            expiry = _expiry_metadata(not_after)
            if expiry:
                severity = max(severity, expiry["severity"])

            findings.append({
                "entity": common_name or domain,
                "module": "cert",
                "finding_type": expiry.get("finding_type", "certificate"),
                "severity": severity,
                "source": "crtsh",
                "data_json": {
                    "issuer": cert.get("issuer_name", ""),
                    "not_before": cert.get("not_before", ""),
                    "not_after": not_after,
                    **{
                        key: expiry[key]
                        for key in ("days_until_expiry", "is_expired", "validity_status")
                        if key in expiry
                    },
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

    async def analyze_endpoints(
        self,
        endpoints: list[tuple[str, int] | tuple[str, int, str]],
    ) -> list[dict]:
        """Run self-signed/expired certificate analysis against discovered endpoints."""
        analyzer = SelfSignedCertAnalyzer()
        return await analyzer.analyze_endpoints(endpoints)

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
