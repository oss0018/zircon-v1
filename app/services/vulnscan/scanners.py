import json
from urllib.parse import urlparse

import httpx


def _as_url(target: str) -> str:
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"https://{target}"


def _target_parts(target: str) -> tuple[str, str, int | None]:
    parsed = urlparse(_as_url(target))
    host = parsed.hostname or ""
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    return _as_url(target), host, port


def _base_finding(
    scanner_source: str,
    scanner_finding_id: str,
    title: str,
    description: str,
    finding_type: str,
    severity: str,
    target_url: str,
    target_host: str,
    target_port: int | None,
    cwe_ids: list[str] | None = None,
) -> dict:
    return {
        "scanner_source": scanner_source,
        "scanner_finding_id": scanner_finding_id,
        "title": title,
        "description": description,
        "finding_type": finding_type,
        "severity": severity,
        "cwe_ids_json": json.dumps(cwe_ids or []),
        "target_url": target_url,
        "target_host": target_host,
        "target_port": target_port,
    }


class HeaderScanner:
    @staticmethod
    async def scan(target_url: str) -> list[dict]:
        normalized_url, host, port = _target_parts(target_url)
        findings: list[dict] = []

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=False) as client:
                response = await client.get(normalized_url)
        except Exception as exc:
            return [
                _base_finding(
                    "headers",
                    "headers-fetch-failed",
                    "Unable to fetch target headers",
                    f"Header scan could not fetch target ({type(exc).__name__}).",
                    "EXPOSURE",
                    "LOW",
                    normalized_url,
                    host,
                    port,
                )
            ]

        headers = {k.lower(): v for k, v in response.headers.items()}

        hsts = headers.get("strict-transport-security", "")
        if not hsts or "max-age" not in hsts.lower():
            findings.append(
                _base_finding(
                    "headers",
                    "hsts-missing",
                    "Missing or weak HSTS header",
                    "Strict-Transport-Security is missing or does not define max-age.",
                    "HSTS_MISSING",
                    "MEDIUM",
                    normalized_url,
                    host,
                    port,
                    cwe_ids=["CWE-319"],
                )
            )

        csp = headers.get("content-security-policy", "")
        if not csp:
            findings.append(
                _base_finding(
                    "headers",
                    "csp-missing",
                    "Missing Content-Security-Policy",
                    "Content-Security-Policy header is missing.",
                    "CSP_MISSING",
                    "MEDIUM",
                    normalized_url,
                    host,
                    port,
                    cwe_ids=["CWE-693"],
                )
            )

        xfo = headers.get("x-frame-options", "")
        if xfo.upper() not in {"DENY", "SAMEORIGIN"}:
            findings.append(
                _base_finding(
                    "headers",
                    "xfo-missing",
                    "Missing or misconfigured X-Frame-Options",
                    "X-Frame-Options should be DENY or SAMEORIGIN.",
                    "X_FRAME_MISSING",
                    "MEDIUM",
                    normalized_url,
                    host,
                    port,
                    cwe_ids=["CWE-1021"],
                )
            )

        xcto = headers.get("x-content-type-options", "")
        if xcto.lower() != "nosniff":
            findings.append(
                _base_finding(
                    "headers",
                    "xcto-missing",
                    "Missing X-Content-Type-Options",
                    "X-Content-Type-Options should be set to nosniff.",
                    "MISCONFIGURATION",
                    "LOW",
                    normalized_url,
                    host,
                    port,
                )
            )

        if not headers.get("referrer-policy"):
            findings.append(
                _base_finding(
                    "headers",
                    "referrer-policy-missing",
                    "Missing Referrer-Policy",
                    "Referrer-Policy header is missing.",
                    "MISCONFIGURATION",
                    "LOW",
                    normalized_url,
                    host,
                    port,
                )
            )

        if not headers.get("permissions-policy"):
            findings.append(
                _base_finding(
                    "headers",
                    "permissions-policy-missing",
                    "Missing Permissions-Policy",
                    "Permissions-Policy header is missing.",
                    "MISCONFIGURATION",
                    "LOW",
                    normalized_url,
                    host,
                    port,
                )
            )

        for leak_header in ("server", "x-powered-by", "x-aspnet-version"):
            leak_value = headers.get(leak_header)
            if leak_value:
                findings.append(
                    _base_finding(
                        "headers",
                        f"info-disclosure-{leak_header}",
                        f"Information disclosure via {leak_header}",
                        f"Header {leak_header} reveals backend information: {leak_value}",
                        "INFORMATION_DISCLOSURE",
                        "INFO",
                        normalized_url,
                        host,
                        port,
                    )
                )

        return findings


class DNSSecScanner:
    @staticmethod
    async def scan(domain: str) -> list[dict]:
        # TODO: replace with real subprocess call
        target_url, host, port = _target_parts(domain)
        return [
            _base_finding(
                "dns_sec",
                "dnssec-001",
                "DNSSEC not configured",
                "No DNSSEC DS records detected for target domain.",
                "MISCONFIGURATION",
                "LOW",
                target_url,
                host,
                port,
            ),
            _base_finding(
                "dns_sec",
                "dmarc-001",
                "Missing DMARC policy",
                "Domain does not publish a DMARC record.",
                "DMARC_MISSING",
                "MEDIUM",
                target_url,
                host,
                port,
            ),
        ]


class TestSSLScanner:
    @staticmethod
    async def scan(hostname: str, port: int = 443) -> list[dict]:
        # TODO: replace with real subprocess call
        base_url = _as_url(hostname)
        parsed = urlparse(base_url)
        safe_host = parsed.hostname or hostname
        scheme = parsed.scheme or "https"
        target_url, host, resolved_port = _target_parts(f"{scheme}://{safe_host}:{port}")
        return [
            _base_finding(
                "testssl",
                "testssl-001",
                "Weak TLS protocol support",
                "Server appears to support deprecated TLS protocol/cipher combinations.",
                "SSL_POODLE",
                "HIGH",
                target_url,
                host,
                resolved_port,
            )
        ]


class NiktoScanner:
    @staticmethod
    async def scan(target: str) -> list[dict]:
        # TODO: replace with real subprocess call
        target_url, host, port = _target_parts(target)
        return [
            _base_finding(
                "nikto",
                "nikto-001",
                "Interesting file exposed",
                "Nikto identified potentially sensitive file exposure.",
                "EXPOSURE",
                "MEDIUM",
                target_url,
                host,
                port,
            )
        ]


class NucleiScanner:
    @staticmethod
    async def scan(target: str, profile: str) -> list[dict]:
        # TODO: replace with real subprocess call
        target_url, host, port = _target_parts(target)
        return [
            {
                **_base_finding(
                    "nuclei",
                    "CVE-2021-41773",
                    "Apache Path Traversal",
                    "Potential exploitation path for CVE-2021-41773 detected.",
                    "CVE",
                    "HIGH",
                    target_url,
                    host,
                    port,
                ),
                "cve_ids_json": json.dumps(["CVE-2021-41773"]),
                "cwe_ids_json": json.dumps(["CWE-22"]),
                "cvss_score": 7.5,
            },
            {
                **_base_finding(
                    "nuclei",
                    "CVE-2021-44228",
                    "Log4Shell indicator",
                    "Log4j JNDI lookup behavior indicates Log4Shell exposure.",
                    "CVE",
                    "CRITICAL",
                    target_url,
                    host,
                    port,
                ),
                "cve_ids_json": json.dumps(["CVE-2021-44228"]),
                "cwe_ids_json": json.dumps(["CWE-502"]),
                "cvss_score": 10.0,
            },
        ]


class ZAPPassiveScanner:
    @staticmethod
    async def scan(target_url: str) -> list[dict]:
        # TODO: replace with real subprocess call
        normalized_url, host, port = _target_parts(target_url)
        return [
            _base_finding(
                "zap",
                "zap-passive-001",
                "Cookie without SameSite",
                "Passive scan found cookie without SameSite attribute.",
                "MISCONFIGURATION",
                "LOW",
                normalized_url,
                host,
                port,
            )
        ]


class OpenVASScanner:
    @staticmethod
    async def scan(target: str, profile: str) -> list[dict]:
        # TODO: replace with real subprocess call
        target_url, host, port = _target_parts(target)
        return [
            _base_finding(
                "openvas",
                "openvas-001",
                "Outdated service vulnerability",
                "OpenVAS detected a known vulnerable service version.",
                "EXPOSURE",
                "HIGH",
                target_url,
                host,
                port,
            )
        ]
