import json
import asyncio
from urllib.parse import urlparse

import httpx
import dns.dnssec
import dns.rdatatype
import dns.resolver


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
        target_url, host, port = _target_parts(domain)
        findings: list[dict] = []
        loop = asyncio.get_event_loop()
        resolver = dns.resolver.Resolver()

        def _txt_record_value(rdata) -> str:
            if hasattr(rdata, "strings"):
                return b"".join(rdata.strings).decode("utf-8", errors="ignore")
            return str(rdata).replace('"', "").strip()

        async def _resolve(name: str, rdtype: str | dns.rdatatype.RdataType):
            return await loop.run_in_executor(None, resolver.resolve, name, rdtype)

        def _append_finding(
            scanner_finding_id: str,
            title: str,
            description: str,
            finding_type: str,
            severity: str,
            remediation_summary: str,
            references: list[str],
            cwe_ids: list[str] | None = None,
        ) -> None:
            findings.append(
                {
                    **_base_finding(
                        "dns_sec",
                        scanner_finding_id,
                        title,
                        description,
                        finding_type,
                        severity,
                        target_url,
                        host,
                        port,
                        cwe_ids=cwe_ids,
                    ),
                    "remediation_summary": remediation_summary,
                    "references_json": json.dumps(references),
                }
            )

        try:
            txt_answers = await _resolve(host, "TXT")
            spf_record = next(
                (
                    _txt_record_value(r).strip()
                    for r in txt_answers
                    if _txt_record_value(r).strip().lower().startswith("v=spf1")
                ),
                None,
            )
            if not spf_record:
                _append_finding(
                    "spf-missing",
                    "Missing SPF Record",
                    "Domain does not publish an SPF record, increasing the risk of email spoofing.",
                    "SPF_MISSING",
                    "MEDIUM",
                    "Publish a TXT SPF record that authorizes only legitimate mail senders and ends with a strict -all policy.",
                    ["https://www.rfc-editor.org/rfc/rfc7208"],
                    cwe_ids=["CWE-350"],
                )
            else:
                spf_lower = spf_record.lower()
                mechanisms = [part.strip() for part in spf_lower.split() if part.strip()]
                has_permissive_all = "+all" in mechanisms
                ends_softfail = bool(mechanisms) and mechanisms[-1] == "~all"
                has_hardfail = "-all" in mechanisms
                if has_permissive_all or (ends_softfail and not has_hardfail):
                    _append_finding(
                        "spf-weak",
                        "Weak SPF Policy",
                        "SPF policy uses softfail (~all) or allows all senders (+all), which can let spoofed email pass some filters.",
                        "SPF_WEAK",
                        "LOW",
                        "Update SPF to explicitly authorize trusted senders and end with -all to reject unauthorized sources.",
                        ["https://www.rfc-editor.org/rfc/rfc7208"],
                    )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            _append_finding(
                "spf-missing",
                "Missing SPF Record",
                "Domain does not publish an SPF record, increasing the risk of email spoofing.",
                "SPF_MISSING",
                "MEDIUM",
                "Publish a TXT SPF record that authorizes only legitimate mail senders and ends with a strict -all policy.",
                ["https://www.rfc-editor.org/rfc/rfc7208"],
                cwe_ids=["CWE-350"],
            )
        except (dns.exception.Timeout, Exception):
            pass

        try:
            dmarc_answers = await _resolve(f"_dmarc.{host}", "TXT")
            dmarc_record = next(
                (
                    _txt_record_value(r).strip()
                    for r in dmarc_answers
                    if _txt_record_value(r).strip().lower().startswith("v=dmarc1")
                ),
                None,
            )
            if not dmarc_record:
                _append_finding(
                    "dmarc-missing",
                    "Missing DMARC Policy",
                    "Domain does not publish a DMARC policy, increasing phishing and domain spoofing risk.",
                    "DMARC_MISSING",
                    "MEDIUM",
                    "Publish a DMARC TXT record with alignment and reporting, then enforce with quarantine or reject.",
                    [
                        "https://www.rfc-editor.org/rfc/rfc7489",
                        "https://dmarc.org/",
                    ],
                    cwe_ids=["CWE-350"],
                )
            elif "p=none" in dmarc_record.lower():
                _append_finding(
                    "dmarc-weak",
                    "DMARC Policy Set to None",
                    "DMARC policy is set to p=none, which is monitoring-only and does not block spoofed messages.",
                    "DMARC_WEAK",
                    "LOW",
                    "Move DMARC from p=none to p=quarantine or p=reject after validating legitimate mail sources.",
                    [
                        "https://www.rfc-editor.org/rfc/rfc7489",
                        "https://dmarcian.com/policy-modes-for-dmarc/",
                    ],
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            _append_finding(
                "dmarc-missing",
                "Missing DMARC Policy",
                "Domain does not publish a DMARC policy, increasing phishing and domain spoofing risk.",
                "DMARC_MISSING",
                "MEDIUM",
                "Publish a DMARC TXT record with alignment and reporting, then enforce with quarantine or reject.",
                [
                    "https://www.rfc-editor.org/rfc/rfc7489",
                    "https://dmarc.org/",
                ],
                cwe_ids=["CWE-350"],
            )
        except (dns.exception.Timeout, Exception):
            pass

        try:
            dkim_answers = await _resolve(f"default._domainkey.{host}", "TXT")
            has_dkim = any(
                _txt_record_value(r).strip().lower().startswith("v=dkim1") for r in dkim_answers
            )
            if not has_dkim:
                _append_finding(
                    "dkim-missing-default-selector",
                    "DKIM Not Detected (default selector)",
                    "No DKIM record was detected for default._domainkey; DKIM may still be configured under another selector.",
                    "DKIM_MISSING",
                    "LOW",
                    "Publish a DKIM TXT record for your active selector and ensure outbound mail is cryptographically signed.",
                    [
                        "https://www.rfc-editor.org/rfc/rfc6376",
                        "https://dmarc.org/overview/",
                    ],
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            _append_finding(
                "dkim-missing-default-selector",
                "DKIM Not Detected (default selector)",
                "No DKIM record was detected for default._domainkey; DKIM may still be configured under another selector.",
                "DKIM_MISSING",
                "LOW",
                "Publish a DKIM TXT record for your active selector and ensure outbound mail is cryptographically signed.",
                [
                    "https://www.rfc-editor.org/rfc/rfc6376",
                    "https://dmarc.org/overview/",
                ],
            )
        except (dns.exception.Timeout, Exception):
            pass

        try:
            ds_answers = await _resolve(host, dns.rdatatype.DS)
            if not list(ds_answers):
                _append_finding(
                    "dnssec-not-configured",
                    "DNSSEC Not Configured",
                    "No DNSSEC DS records were detected, increasing exposure to DNS cache-poisoning and spoofing attacks.",
                    "DNSSEC_NOT_CONFIGURED",
                    "LOW",
                    "Enable DNSSEC with your DNS provider and publish DS records at the parent zone.",
                    [
                        "https://www.rfc-editor.org/rfc/rfc4033",
                        "https://www.rfc-editor.org/rfc/rfc4034",
                    ],
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            _append_finding(
                "dnssec-not-configured",
                "DNSSEC Not Configured",
                "No DNSSEC DS records were detected, increasing exposure to DNS cache-poisoning and spoofing attacks.",
                "DNSSEC_NOT_CONFIGURED",
                "LOW",
                "Enable DNSSEC with your DNS provider and publish DS records at the parent zone.",
                [
                    "https://www.rfc-editor.org/rfc/rfc4033",
                    "https://www.rfc-editor.org/rfc/rfc4034",
                ],
            )
        except (dns.exception.Timeout, Exception):
            pass

        try:
            caa_answers = await _resolve(host, dns.rdatatype.CAA)
            if not list(caa_answers):
                _append_finding(
                    "caa-missing",
                    "Missing CAA Record",
                    "No CAA record was detected; CAA helps restrict which certificate authorities can issue TLS certificates for this domain.",
                    "CAA_MISSING",
                    "INFO",
                    "Add CAA records to authorize approved certificate authorities and reduce certificate mis-issuance risk.",
                    ["https://www.rfc-editor.org/rfc/rfc8659"],
                )
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            _append_finding(
                "caa-missing",
                "Missing CAA Record",
                "No CAA record was detected; CAA helps restrict which certificate authorities can issue TLS certificates for this domain.",
                "CAA_MISSING",
                "INFO",
                "Add CAA records to authorize approved certificate authorities and reduce certificate mis-issuance risk.",
                ["https://www.rfc-editor.org/rfc/rfc8659"],
            )
        except (dns.exception.Timeout, Exception):
            pass

        return findings


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
