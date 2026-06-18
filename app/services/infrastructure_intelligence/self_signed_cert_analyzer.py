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
    async def _verify_connection(
        self,
        ip: str,
        port: int,
        server_hostname: str | None = None,
    ) -> dict:
        """Attempt a verified TLS connection and capture verification results."""
        result = {
            "server_hostname": server_hostname or "",
            "hostname_valid": None,
            "chain_valid": None,
            "tls_verified": False,
            "verification_error": "",
        }

        if not server_hostname:
            return result

        try:
            verify_ctx = ssl.create_default_context()
            verify_ctx.check_hostname = True
            verify_ctx.verify_mode = ssl.CERT_REQUIRED

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=verify_ctx, server_hostname=server_hostname),
                timeout=CONNECT_TIMEOUT,
            )
            try:
                result["hostname_valid"] = True
                result["chain_valid"] = True
                result["tls_verified"] = True
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
        except ssl.SSLCertVerificationError as exc:
            message = str(exc)
            result["tls_verified"] = False
            result["verification_error"] = message
            lower_message = message.lower()
            if "hostname" in lower_message or "match" in lower_message:
                result["hostname_valid"] = False
            if any(term in lower_message for term in ("self signed", "unable to get local issuer", "certificate verify failed", "issuer")):
                result["chain_valid"] = False
        except ssl.SSLError as exc:
            result["tls_verified"] = False
            result["verification_error"] = str(exc)
        except Exception as exc:
            result["tls_verified"] = False
            result["verification_error"] = str(exc)

        return result

    async def _fetch_cert(
        self,
        ip: str,
        port: int,
        server_hostname: str | None = None,
    ) -> dict | None:
        """Open a TLS connection and retrieve certificate details."""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    ip,
                    port,
                    ssl=ctx,
                    server_hostname=server_hostname or None,
                ),
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

                def _extract_name_value(tuples_of_tuples, key: str) -> str:
                    for rdn in (tuples_of_tuples or ()):
                        for attr, val in rdn:
                            if str(attr).lower() == key.lower():
                                return str(val)
                    return ""

                subject_raw = raw_cert.get("subject", ())
                issuer_raw = raw_cert.get("issuer", ())
                subject = _parse_name(subject_raw)
                issuer = _parse_name(issuer_raw)
                common_name = _extract_name_value(subject_raw, "commonName")
                issuer_common_name = _extract_name_value(issuer_raw, "commonName")

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
                dns_names: list[str] = []
                ip_addresses: list[str] = []
                for san_type, san_value in raw_cert.get("subjectAltName", ()):
                    san_entry = f"{san_type}:{san_value}"
                    san_list.append(san_entry)
                    if str(san_type).lower() == "dns":
                        dns_names.append(str(san_value))
                    elif str(san_type).lower() == "ip address":
                        ip_addresses.append(str(san_value))

                # Serial
                serial_raw = raw_cert.get("serialNumber")
                serial_number = str(serial_raw) if serial_raw else ""

                # Extra parsed certificate details via cryptography lib
                sha256_fingerprint = ""
                signature_algorithm = ""
                version = ""
                public_key_type = ""
                public_key_size = None
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa

                    der = ssl_obj.getpeercert(binary_form=True)
                    if der:
                        cert_obj = x509.load_der_x509_certificate(der)
                        fp = cert_obj.fingerprint(hashes.SHA256())
                        sha256_fingerprint = fp.hex(":")
                        try:
                            signature_algorithm = cert_obj.signature_hash_algorithm.name
                        except Exception:
                            signature_algorithm = ""
                        try:
                            version = cert_obj.version.name
                        except Exception:
                            version = ""
                        try:
                            public_key = cert_obj.public_key()
                            public_key_size = getattr(public_key, "key_size", None)
                            if isinstance(public_key, rsa.RSAPublicKey):
                                public_key_type = "RSA"
                            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                                public_key_type = "EC"
                            elif isinstance(public_key, dsa.DSAPublicKey):
                                public_key_type = "DSA"
                            elif isinstance(public_key, ed25519.Ed25519PublicKey):
                                public_key_type = "Ed25519"
                            elif isinstance(public_key, ed448.Ed448PublicKey):
                                public_key_type = "Ed448"
                            else:
                                public_key_type = public_key.__class__.__name__
                        except Exception:
                            public_key_type = ""
                            public_key_size = None
                except Exception:
                    pass

                verification = await self._verify_connection(ip, port, server_hostname)

                return {
                    "ip": ip,
                    "port": port,
                    "server_hostname": verification.get("server_hostname", ""),
                    "subject": subject,
                    "issuer": issuer,
                    "common_name": common_name,
                    "issuer_common_name": issuer_common_name,
                    "not_before": not_before.isoformat() if not_before else "",
                    "not_after": not_after.isoformat() if not_after else "",
                    "serial_number": serial_number,
                    "is_self_signed": is_self_signed,
                    "is_expired": is_expired,
                    "days_until_expiry": days_until_expiry,
                    "san_list": san_list,
                    "dns_names": dns_names,
                    "ip_addresses": ip_addresses,
                    "sha256_fingerprint": sha256_fingerprint,
                    "signature_algorithm": signature_algorithm,
                    "version": version,
                    "public_key_type": public_key_type,
                    "public_key_size": public_key_size,
                    "hostname_valid": verification.get("hostname_valid"),
                    "chain_valid": verification.get("chain_valid"),
                    "tls_verified": verification.get("tls_verified", False),
                    "verification_error": verification.get("verification_error", ""),
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
        hostname_valid = cert_data.get("hostname_valid")
        chain_valid = cert_data.get("chain_valid")
        ip = cert_data.get("ip", "")
        port = cert_data.get("port", 0)

        if hostname_valid is False:
            severity = 4
            finding_type = "hostname_mismatch_cert"
        elif chain_valid is False and is_self_signed:
            severity = 4
            finding_type = "self_signed_cert"
        elif chain_valid is False:
            severity = 4
            finding_type = "untrusted_issuer_cert"
        elif is_self_signed and is_expired:
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

    async def analyze_endpoint(
        self,
        ip: str,
        port: int,
        server_hostname: str | None = None,
    ) -> list[dict]:
        """Run TLS analysis for a specific discovered endpoint."""
        cert_data = await self._fetch_cert(ip, port, server_hostname=server_hostname)
        if cert_data is None:
            return []
        return [self._classify_finding(cert_data)]

    async def analyze_endpoints(
        self,
        endpoints: list[tuple[str, int] | tuple[str, int, str]],
    ) -> list[dict]:
        """Run TLS analysis for specific discovered endpoints."""
        sem = asyncio.Semaphore(MAX_CONCURRENT)

        async def _probe(endpoint: tuple[str, int] | tuple[str, int, str]) -> list[dict]:
            async with sem:
                if len(endpoint) == 3:
                    ip, port, server_hostname = endpoint
                else:
                    ip, port = endpoint
                    server_hostname = None
                return await self.analyze_endpoint(ip, port, server_hostname=server_hostname)

        results = await asyncio.gather(*[_probe(endpoint) for endpoint in endpoints])
        findings: list[dict] = []
        for result in results:
            findings.extend(result)
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
