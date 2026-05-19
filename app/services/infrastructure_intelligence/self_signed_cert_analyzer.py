"""
Self-Signed Certificate Analyzer — performs TLS handshakes to detect
self-signed, expired, or soon-to-expire certificates on common HTTPS ports.
"""
import asyncio
import ipaddress
import json
import logging
import ssl
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

CERT_PORTS = [443, 8443, 8080, 9443, 4443, 2083, 2087, 10443]
CONNECT_TIMEOUT = 5.0
MAX_CONCURRENT = 10


class SelfSignedCertAnalyzer:
    async def _fetch_cert(self, ip: str, port: int) -> dict | None:
        """Open a TLS connection and retrieve certificate details."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx),
                timeout=CONNECT_TIMEOUT,
            )

            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                raw_cert = ssl_obj.getpeercert()

                if not raw_cert:
                    return None

                def _parse_name(tuples_of_tuples) -> str:
                    parts = []
                    for rdn in (tuples_of_tuples or ()):
                        for attr, val in rdn:
                            parts.append(f"{attr}={val}")
                    return ", ".join(parts)

                subject = _parse_name(raw_cert.get("subject", ()))
                issuer = _parse_name(raw_cert.get("issuer", ()))

                def _parse_dt(s: str) -> datetime:
                    return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(
                        tzinfo=timezone.utc
                    )

                not_before_str = raw_cert.get("notBefore", "")
                not_after_str = raw_cert.get("notAfter", "")

                not_before = _parse_dt(not_before_str) if not_before_str else None
                not_after = _parse_dt(not_after_str) if not_after_str else None

                now = datetime.now(timezone.utc)
                is_self_signed = subject == issuer and bool(subject)
                is_expired = (not_after < now) if not_after else False
                days_until_expiry = int((not_after - now).days) if not_after else 0

                # SANs
                san_list: list[str] = []
                for san_type, san_value in raw_cert.get("subjectAltName", ()):
                    san_list.append(f"{san_type}:{san_value}")

                # Serial
                serial_raw = raw_cert.get("serialNumber")
                serial_number = hex(serial_raw) if serial_raw else ""

                # SHA-256 fingerprint via cryptography lib
                sha256_fingerprint = ""
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import hashes
                    der = ssl_obj.getpeercert(binary_form=True)
                    if der:
                        cert_obj = x509.load_der_x509_certificate(der)
                        fp = cert_obj.fingerprint(hashes.SHA256())
                        sha256_fingerprint = fp.hex(":")
                except Exception:
                    pass

                return {
                    "ip": ip,
                    "port": port,
                    "subject": subject,
                    "issuer": issuer,
                    "not_before": not_before.isoformat() if not_before else "",
                    "not_after": not_after.isoformat() if not_after else "",
                    "serial_number": serial_number,
                    "is_self_signed": is_self_signed,
                    "is_expired": is_expired,
                    "days_until_expiry": days_until_expiry,
                    "san_list": san_list,
                    "sha256_fingerprint": sha256_fingerprint,
                }
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

        except Exception:
            return None

    def _classify_finding(self, cert_data: dict) -> dict:
        """Classify a certificate finding and assign severity.

        Expiry/self-signed checks run before the days_until_expiry threshold
        checks, so negative values (already-expired certs) are handled first
        and never fall through to the threshold branches.
        """
        is_self_signed = cert_data.get("is_self_signed", False)
        is_expired = cert_data.get("is_expired", False)
        days_until_expiry = cert_data.get("days_until_expiry", 9999)
        ip = cert_data.get("ip", "")
        port = cert_data.get("port", 0)

        if is_self_signed and is_expired:
            severity = 4
            finding_type = "self_signed_cert"
        elif is_expired:
            severity = 4
            finding_type = "expired_cert"
        elif is_self_signed:
            severity = 3
            finding_type = "self_signed_cert"
        elif days_until_expiry <= 7:
            severity = 4
            finding_type = "expiring_cert"
        elif days_until_expiry <= 30:
            severity = 3
            finding_type = "expiring_cert"
        else:
            severity = 1
            finding_type = "certificate"

        return {
            "module": "cert",
            "finding_type": finding_type,
            "entity": f"{ip}:{port}",
            "severity": severity,
            "source": "tls_handshake",
            "data_json": json.dumps(cert_data),
        }

    async def analyze_ip(self, ip: str) -> list[dict]:
        """Try all CERT_PORTS for a single IP and return findings."""
        sem = asyncio.Semaphore(MAX_CONCURRENT)

        async def _probe(port: int) -> dict | None:
            async with sem:
                return await self._fetch_cert(ip, port)

        results = await asyncio.gather(*[_probe(p) for p in CERT_PORTS])
        findings: list[dict] = []
        for cert_data in results:
            if cert_data is not None:
                findings.append(self._classify_finding(cert_data))
        return findings

    async def analyze_targets(self, targets: list[str]) -> list[dict]:
        """Run analyze_ip for each target with bounded outer concurrency."""
        outer_sem = asyncio.Semaphore(5)

        async def _analyze(ip: str) -> list[dict]:
            async with outer_sem:
                return await self.analyze_ip(ip)

        results = await asyncio.gather(*[_analyze(t) for t in targets])
        findings: list[dict] = []
        for result in results:
            findings.extend(result)
        return findings
