import json
import asyncio
import html
import re
import shutil
import tempfile
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

import httpx
import dns.dnssec
import dns.rdatatype
import dns.resolver

from app.services.vulnscan.scanner_config import VALID_NUCLEI_SEVERITIES


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


def _tool_not_available_finding(
    tool_name: str,
    scanner_source: str,
    target_url: str,
    target_host: str,
    target_port: int | None,
) -> list[dict]:
    return [
        _base_finding(
            scanner_source,
            f"{scanner_source}-tool-not-available",
            f"{tool_name} not installed",
            f"{tool_name} binary not found. Install it to enable this scanner.",
            "TOOL_NOT_AVAILABLE",
            "INFO",
            target_url,
            target_host,
            target_port,
        )
    ]


def _scan_timeout_finding(
    tool_name: str,
    scanner_source: str,
    target_url: str,
    target_host: str,
    target_port: int | None,
) -> list[dict]:
    return [
        _base_finding(
            scanner_source,
            f"{scanner_source}-scan-timeout",
            f"{tool_name} scan timed out",
            f"{tool_name} scan exceeded the allowed time limit.",
            "SCAN_TIMEOUT",
            "INFO",
            target_url,
            target_host,
            target_port,
        )
    ]


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


_TESTSSL_CHECK_FLAGS = {
    "protocols": "--protocols",
    "vulnerabilities": "--vulnerable",
    "headers": "--headers",
}


class TestSSLScanner:
    @staticmethod
    async def scan(hostname: str, port: int = 443, config: dict | None = None) -> list[dict]:
        config = config or {}
        base_url = _as_url(hostname)
        parsed = urlparse(base_url)
        safe_host = parsed.hostname or hostname
        scheme = parsed.scheme or "https"
        target_url, host, resolved_port = _target_parts(f"{scheme}://{safe_host}:{port}")
        temp_path = Path(tempfile.gettempdir()) / f"testssl_{uuid.uuid4().hex}.json"
        findings: list[dict] = []
        testssl_bin = shutil.which("testssl.sh") or shutil.which("testssl")
        if not testssl_bin:
            return _tool_not_available_finding(
                "TestSSL",
                "testssl",
                target_url,
                host,
                resolved_port,
            )

        cmd = [
            testssl_bin,
            "--jsonfile",
            str(temp_path),
            "--quiet",
            "--color",
            "0",
            "--warnings",
            "off",
        ]
        if config.get("fast") is True:
            cmd.append("--fast")
        for check in config.get("checks") or []:
            flag = _TESTSSL_CHECK_FLAGS.get(check)
            if flag:
                cmd.append(flag)
        cmd.append(f"{safe_host}:{port}")

        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                return _tool_not_available_finding(
                    "TestSSL",
                    "testssl",
                    target_url,
                    host,
                    resolved_port,
                )
            except Exception:
                return []

            try:
                await asyncio.wait_for(process.wait(), timeout=120)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return _scan_timeout_finding("TestSSL", "testssl", target_url, host, resolved_port)

            entries: list[dict] = []
            if temp_path.exists():
                try:
                    raw = json.loads(temp_path.read_text(encoding="utf-8"))
                    if isinstance(raw, list):
                        entries = [e for e in raw if isinstance(e, dict)]
                except (json.JSONDecodeError, OSError):
                    pass

            severity_map = {
                "CRITICAL": "CRITICAL",
                "HIGH": "HIGH",
                "MEDIUM": "MEDIUM",
                "WARN": "MEDIUM",
                "LOW": "LOW",
            }
            finding_type_map = {
                "SSLv2": "SSL_DEPRECATED_PROTOCOL",
                "SSLv3": "SSL_DEPRECATED_PROTOCOL",
                "TLS1": "TLS_DEPRECATED_PROTOCOL",
                "TLS1_1": "TLS_DEPRECATED_PROTOCOL",
                "POODLE_SSL": "SSL_POODLE",
                "POODLE_TLS": "SSL_POODLE",
                "HEARTBLEED": "HEARTBLEED",
                "BEAST": "SSL_BEAST",
                "DROWN": "SSL_DROWN",
                "LOGJAM": "SSL_LOGJAM",
                "CCS": "SSL_CCS_INJECTION",
                "cert_expiration_status": "CERT_EXPIRED",
                "cert_trust": "CERT_UNTRUSTED",
            }
            title_map = {
                "SSLv2": "SSLv2 Supported (deprecated)",
                "SSLv3": "SSLv3 Supported (deprecated)",
                "TLS1": "TLS 1.0 Supported (deprecated)",
                "TLS1_1": "TLS 1.1 Supported (deprecated)",
                "POODLE_SSL": "POODLE Vulnerability Detected",
                "POODLE_TLS": "POODLE Vulnerability Detected",
                "HEARTBLEED": "Heartbleed Vulnerability Detected",
                "BEAST": "BEAST Vulnerability Detected",
                "DROWN": "DROWN Vulnerability Detected",
                "cert_expiration_status": "Certificate Expired or Expiring Soon",
                "cert_trust": "Certificate Not Trusted",
            }
            remediation_map = {
                "SSL_POODLE": "Disable SSLv3/TLS fallback and remove vulnerable ciphers to mitigate POODLE.",
                "HEARTBLEED": "Upgrade OpenSSL to a patched version and reissue TLS certificates and keys.",
                "SSL_DEPRECATED_PROTOCOL": "Disable deprecated SSL/TLS protocol versions and enforce TLS 1.2+.",
                "TLS_DEPRECATED_PROTOCOL": "Disable deprecated TLS protocol versions and enforce TLS 1.2+.",
                "CERT_EXPIRED": "Renew and deploy a valid TLS certificate before expiry.",
            }

            for entry in entries:
                raw_severity = str(entry.get("severity", "")).upper()
                if raw_severity in {"OK", "INFO"}:
                    continue
                severity = severity_map.get(raw_severity)
                if not severity:
                    continue

                entry_id = str(entry.get("id", "")).strip()
                if not entry_id:
                    continue
                finding_type = finding_type_map.get(entry_id, "TLS_MISCONFIGURATION")
                findings.append(
                    {
                        **_base_finding(
                            "testssl",
                            f"testssl-{entry_id}",
                            title_map.get(entry_id, f"TLS Issue: {entry_id}"),
                            str(entry.get("finding", "")).strip(),
                            finding_type,
                            severity,
                            target_url,
                            host,
                            resolved_port,
                        ),
                        "remediation_summary": remediation_map.get(
                            finding_type,
                            "Refer to testssl.sh documentation for remediation guidance.",
                        ),
                        "references_json": json.dumps(["https://testssl.sh/"]),
                    }
                )
            return findings
        except Exception:
            return []
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass


_NIKTO_TUNING_CHARS = set("0123456789abcx")


class NiktoScanner:
    @staticmethod
    async def scan(target: str, config: dict | None = None) -> list[dict]:
        config = config or {}
        target_url, host, port = _target_parts(target)
        temp_path = Path(tempfile.gettempdir()) / f"nikto_{uuid.uuid4().hex}.json"
        findings: list[dict] = []
        nikto_bin = shutil.which("nikto") or shutil.which("nikto.pl")
        if not nikto_bin:
            return _tool_not_available_finding("Nikto", "nikto", target_url, host, port)

        max_time_seconds = 120
        raw_max_time = config.get("max_time")
        if isinstance(raw_max_time, (int, float)) and not isinstance(raw_max_time, bool):
            max_time_seconds = max(30, min(600, int(raw_max_time)))

        cmd = [
            nikto_bin,
            "-h",
            target_url,
            "-Format",
            "json",
            "-output",
            str(temp_path),
            "-nointeractive",
            "-maxtime",
            f"{max_time_seconds}s",
        ]
        tuning = str(config.get("tuning") or "").strip().lower()
        if tuning and all(c in _NIKTO_TUNING_CHARS for c in tuning):
            cmd.extend(["-Tuning", tuning])

        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                return _tool_not_available_finding("Nikto", "nikto", target_url, host, port)
            except Exception:
                return []

            try:
                await asyncio.wait_for(process.wait(), timeout=max_time_seconds + 30)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return _scan_timeout_finding("Nikto", "nikto", target_url, host, port)

            items: list[dict] = []
            if temp_path.exists():
                try:
                    payload = json.loads(temp_path.read_text(encoding="utf-8"))
                    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
                    fallback_items = payload.get("items", []) if isinstance(payload, dict) else []
                    items = vulnerabilities if isinstance(vulnerabilities, list) else []
                    if not items and isinstance(fallback_items, list):
                        items = fallback_items
                except (json.JSONDecodeError, OSError):
                    pass

            for idx, item in enumerate(items):
                if not isinstance(item, dict):
                    continue
                msg = str(item.get("msg", "")).strip()
                msg_lower = msg.lower()
                finding_type = "EXPOSURE"
                if "sql" in msg_lower:
                    finding_type = "SQLI"
                elif "xss" in msg_lower or "cross-site" in msg_lower:
                    finding_type = "XSS"
                elif "default" in msg_lower or "sample" in msg_lower:
                    finding_type = "DEFAULT_FILE"
                elif "outdated" in msg_lower or "version" in msg_lower:
                    finding_type = "OUTDATED_SOFTWARE"
                elif "directory" in msg_lower or "listing" in msg_lower:
                    finding_type = "DIRECTORY_LISTING"
                elif "header" in msg_lower:
                    finding_type = "MISCONFIGURATION"

                references = ["https://cirt.net/nikto2"]
                item_references = item.get("references")
                if isinstance(item_references, str) and item_references.strip():
                    references.append(item_references.strip())

                findings.append(
                    {
                        **_base_finding(
                            "nikto",
                            f"nikto-{item.get('id', idx)}",
                            msg[:120],
                            msg,
                            finding_type,
                            "MEDIUM",
                            target_url,
                            host,
                            port,
                        ),
                        "remediation_summary": "Review the identified issue and apply vendor patches or configuration hardening.",
                        "references_json": json.dumps(references),
                    }
                )

            return findings
        except Exception:
            return []
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass


class NucleiScanner:
    @staticmethod
    async def scan(target: str, profile: str, config: dict | None = None) -> list[dict]:
        config = config or {}
        target_url, host, port = _target_parts(target)
        profile_tags = {
            "quick": ["cve", "exposure", "misconfiguration", "default-login", "ssl"],
            "standard": [
                "cve",
                "exposure",
                "misconfiguration",
                "default-login",
                "ssl",
                "tech",
                "takeover",
                "network",
                "panel",
            ],
            "deep": [],
        }
        nuclei_bin = shutil.which("nuclei")
        if not nuclei_bin:
            return _tool_not_available_finding("Nuclei", "nuclei", target_url, host, port)

        cmd = [nuclei_bin, "-target", target]
        custom_tags = str(config.get("tags") or "").strip()
        if custom_tags:
            tags = [t.strip() for t in custom_tags.split(",") if t.strip()]
            if tags:
                cmd.extend(["-tags", ",".join(tags)])
        elif profile != "deep":
            tags = profile_tags.get(profile, profile_tags["standard"])
            if tags:
                cmd.extend(["-tags", ",".join(tags)])

        severities = config.get("severity")
        if isinstance(severities, list):
            valid_severities = sorted(
                {s.lower() for s in severities if isinstance(s, str) and s.lower() in VALID_NUCLEI_SEVERITIES}
            )
            if valid_severities:
                cmd.extend(["-severity", ",".join(valid_severities)])

        cmd.extend(
            [
                "-json",
                "-no-color",
                "-silent",
                "-timeout",
                "10",
                "-retries",
                "2",
                "-follow-redirects",
                "-rate-limit",
                "150",
                "-concurrency",
                "25",
            ]
        )
        timeout = 600 if profile == "deep" else 300
        findings: list[dict] = []
        seen: set[tuple[str, str]] = set()

        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                return _tool_not_available_finding("Nuclei", "nuclei", target_url, host, port)
            except Exception:
                return []

            started_at = asyncio.get_event_loop().time()
            while True:
                elapsed = asyncio.get_event_loop().time() - started_at
                remaining = timeout - elapsed
                if remaining <= 0:
                    process.kill()
                    await process.wait()
                    return _scan_timeout_finding("Nuclei", "nuclei", target_url, host, port)

                try:
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=remaining)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    return _scan_timeout_finding("Nuclei", "nuclei", target_url, host, port)

                if not line:
                    break

                try:
                    raw = json.loads(line.decode("utf-8", errors="ignore").strip())
                    if not isinstance(raw, dict):
                        continue
                except json.JSONDecodeError:
                    continue

                template_id = str(raw.get("template-id", "")).strip()
                matched_at = str(raw.get("matched-at", target_url)).strip() or target_url
                if not template_id:
                    continue
                dedupe_key = (template_id, matched_at)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                info = raw.get("info", {}) if isinstance(raw.get("info"), dict) else {}
                severity = str(info.get("severity", "info")).upper()
                if severity not in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
                    severity = "INFO"

                classification = (
                    info.get("classification", {})
                    if isinstance(info.get("classification"), dict)
                    else {}
                )
                raw_cve_ids = classification.get("cve-id", []) or []
                raw_cwe_ids = classification.get("cwe-id", []) or []
                cve_ids = raw_cve_ids if isinstance(raw_cve_ids, list) else [str(raw_cve_ids)]
                cwe_ids = raw_cwe_ids if isinstance(raw_cwe_ids, list) else [str(raw_cwe_ids)]
                raw_references = info.get("reference", []) or []
                references = (
                    raw_references
                    if isinstance(raw_references, list)
                    else [str(raw_references)]
                )

                findings.append(
                    {
                        **_base_finding(
                            "nuclei",
                            template_id,
                            str(info.get("name", template_id)),
                            str(info.get("description", ""))[:2000],
                            "CVE" if cve_ids else "EXPOSURE",
                            severity,
                            matched_at,
                            host,
                            port,
                        ),
                        "cve_ids_json": json.dumps(cve_ids),
                        "cwe_ids_json": json.dumps(cwe_ids),
                        "cvss_score": classification.get("cvss-score"),
                        "references_json": json.dumps(references),
                    }
                )

            remaining = timeout - (asyncio.get_event_loop().time() - started_at)
            try:
                await asyncio.wait_for(process.wait(), timeout=max(1, remaining))
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return _scan_timeout_finding("Nuclei", "nuclei", target_url, host, port)
            return findings
        except Exception:
            return []


_NMAP_HIGH_RISK_PORTS = {23, 3389, 5900, 27017}       # telnet, rdp, vnc, mongodb
_NMAP_MEDIUM_RISK_PORTS = {21, 445, 3306, 5432, 6379, 9200}  # ftp, smb, mysql, postgres, redis, elasticsearch
_NMAP_CVE_RE = re.compile(r"cve-\d{4}-\d{4,7}", re.IGNORECASE)


def _nmap_port_severity(port: int) -> str:
    if port in _NMAP_HIGH_RISK_PORTS:
        return "HIGH"
    if port in _NMAP_MEDIUM_RISK_PORTS:
        return "MEDIUM"
    return "INFO"


def _nmap_script_findings(
    script_el: "ET.Element",
    target_url: str,
    host_ip: str,
    port_num: int | None,
) -> list[dict]:
    """Turn an NSE `vuln`-category <script> element into findings.

    Nmap's shared `vulns.lua` library (used by essentially every script in the
    stock `vuln` category) always prefixes positive hits with a "VULNERABLE"
    marker in the human-readable output, so that substring is a reliable,
    tool-agnostic signal without needing a bespoke parser per NSE script.
    """
    output = (script_el.get("output") or "").strip()
    if "VULNERABLE" not in output.upper():
        return []

    script_id = script_el.get("id", "nmap-vuln-script")
    cve_ids = sorted({m.upper() for m in _NMAP_CVE_RE.findall(output)})
    references = (
        [f"https://nvd.nist.gov/vuln/detail/{cve}" for cve in cve_ids]
        if cve_ids
        else ["https://nmap.org/nsedoc/categories/vuln.html"]
    )

    return [
        {
            **_base_finding(
                "nmap",
                f"nmap-{script_id}-{port_num if port_num is not None else 'host'}",
                f"Nmap NSE: {script_id}",
                output[:2000],
                "CVE" if cve_ids else "EXPOSURE",
                "HIGH",
                target_url,
                host_ip,
                port_num,
            ),
            "cve_ids_json": json.dumps(cve_ids),
            "references_json": json.dumps(references),
        }
    ]


class NmapScanner:
    @staticmethod
    async def scan(target: str, profile: str) -> list[dict]:
        target_url, host, _default_port = _target_parts(target)
        temp_path = Path(tempfile.gettempdir()) / f"nmap_{uuid.uuid4().hex}.xml"
        findings: list[dict] = []
        nmap_bin = shutil.which("nmap")
        if not nmap_bin:
            return _tool_not_available_finding("Nmap", "nmap", target_url, host, None)

        if profile == "deep":
            port_args = ["--top-ports", "1000"]
            timeout = 600
            script_timeout = "90s"
            host_timeout = "8m"
        else:
            port_args = ["--top-ports", "100"]
            timeout = 300
            script_timeout = "45s"
            host_timeout = "4m"

        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    nmap_bin,
                    "-Pn",
                    "-sV",
                    "-T4",
                    *port_args,
                    "--script",
                    "vuln",
                    "--script-timeout",
                    script_timeout,
                    "--host-timeout",
                    host_timeout,
                    "-oX",
                    str(temp_path),
                    host,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                return _tool_not_available_finding("Nmap", "nmap", target_url, host, None)
            except Exception:
                return []

            try:
                await asyncio.wait_for(process.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return _scan_timeout_finding("Nmap", "nmap", target_url, host, None)

            root = None
            if temp_path.exists():
                try:
                    root = ET.parse(str(temp_path)).getroot()
                except (ET.ParseError, OSError):
                    root = None

            if root is not None:
                for host_el in root.findall("host"):
                    addr_el = host_el.find("address")
                    host_ip = addr_el.get("addr") if addr_el is not None else host

                    hostscript_el = host_el.find("hostscript")
                    if hostscript_el is not None:
                        for script_el in hostscript_el.findall("script"):
                            findings.extend(
                                _nmap_script_findings(script_el, target_url, host_ip, None)
                            )

                    ports_el = host_el.find("ports")
                    if ports_el is None:
                        continue
                    for port_el in ports_el.findall("port"):
                        state_el = port_el.find("state")
                        if state_el is None or state_el.get("state") != "open":
                            continue
                        try:
                            port_num = int(port_el.get("portid", "0") or 0)
                        except ValueError:
                            continue

                        service_el = port_el.find("service")
                        service_name = service_el.get("name", "") if service_el is not None else ""
                        product = service_el.get("product", "") if service_el is not None else ""
                        version = service_el.get("version", "") if service_el is not None else ""
                        banner = " ".join(part for part in (product, version) if part).strip()

                        findings.append(
                            {
                                **_base_finding(
                                    "nmap",
                                    f"nmap-open-port-{port_num}",
                                    f"Open port {port_num}/tcp ({service_name or 'unknown'})",
                                    (
                                        f"Nmap detected an open {service_name or 'unknown'} "
                                        f"service on port {port_num}"
                                        + (f" ({banner})" if banner else "")
                                        + "."
                                    ),
                                    "OPEN_PORT",
                                    _nmap_port_severity(port_num),
                                    target_url,
                                    host_ip,
                                    port_num,
                                ),
                                "references_json": json.dumps(["https://nmap.org/book/man-port-scanning-basics.html"]),
                            }
                        )

                        for script_el in port_el.findall("script"):
                            findings.extend(
                                _nmap_script_findings(script_el, target_url, host_ip, port_num)
                            )

            return findings
        except Exception:
            return []
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass


_ZAP_RISK_SEVERITY = {
    "0": "INFO",
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
}


def _strip_html(value: str) -> str:
    """Best-effort plain-text rendering of ZAP's HTML-flavoured report fields."""
    text = re.sub(r"<[^>]+>", " ", value or "")
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _zap_alert_finding(alert: dict, target_url: str, host: str, port: int | None) -> dict:
    risk_code = str(alert.get("riskcode", "1"))
    severity = _ZAP_RISK_SEVERITY.get(risk_code, "LOW")
    name = str(alert.get("name") or alert.get("alert") or "ZAP finding").strip()
    description = _strip_html(str(alert.get("desc", ""))) or name
    solution = _strip_html(str(alert.get("solution", "")))
    plugin_id = str(alert.get("pluginid") or alert.get("id") or "0")

    instances = alert.get("instances")
    first_instance = instances[0] if isinstance(instances, list) and instances else {}
    evidence = first_instance.get("evidence") if isinstance(first_instance, dict) else None
    affected_parameter = first_instance.get("param") if isinstance(first_instance, dict) else None

    name_lower = name.lower()
    if "sql" in name_lower:
        finding_type = "SQLI"
    elif "cross site scripting" in name_lower or "cross-site scripting" in name_lower or "xss" in name_lower:
        finding_type = "XSS"
    elif "disclosure" in name_lower or "information" in name_lower:
        finding_type = "EXPOSURE"
    else:
        finding_type = "MISCONFIGURATION"

    references = [
        _strip_html(line)
        for line in re.split(r"<br ?/?>|\n", str(alert.get("reference", "")))
        if _strip_html(line)
    ] or ["https://www.zaproxy.org/"]

    cwe_id = alert.get("cweid")
    cwe_ids = [f"CWE-{cwe_id}"] if cwe_id not in (None, "", -1, "-1", "0") else []
    wasc_id = alert.get("wascid")

    return {
        **_base_finding(
            "zap",
            f"zap-{plugin_id}",
            name[:255],
            description,
            finding_type,
            severity,
            target_url,
            host,
            port,
            cwe_ids,
        ),
        "remediation_summary": solution or "Review the ZAP finding and apply the recommended mitigation.",
        "references_json": json.dumps(references),
        "evidence": evidence,
        "affected_parameter": affected_parameter,
        "wasc_id": str(wasc_id) if wasc_id not in (None, "", -1, "-1") else None,
    }


class ZAPPassiveScanner:
    """Runs a real OWASP ZAP baseline scan (spider + passive rules only, no
    active attacks) via the `zap-baseline.py` CLI shipped with ZAP, and
    parses its JSON report. Degrades to a TOOL_NOT_AVAILABLE finding when ZAP
    isn't installed, matching every other scanner in this module instead of
    fabricating a finding.
    """

    @staticmethod
    async def scan(target_url: str, profile: str = "standard", config: dict | None = None) -> list[dict]:
        config = config or {}
        normalized_url, host, port = _target_parts(target_url)
        temp_path = Path(tempfile.gettempdir()) / f"zap_{uuid.uuid4().hex}.json"
        findings: list[dict] = []
        zap_bin = shutil.which("zap-baseline.py")
        if not zap_bin:
            return _tool_not_available_finding("OWASP ZAP", "zap", normalized_url, host, port)

        if profile == "deep":
            spider_minutes, max_minutes = 3, 8
        else:
            spider_minutes, max_minutes = 1, 4

        raw_spider = config.get("spider_minutes")
        if isinstance(raw_spider, (int, float)) and not isinstance(raw_spider, bool):
            spider_minutes = max(1, min(10, int(raw_spider)))
        raw_max = config.get("max_minutes")
        if isinstance(raw_max, (int, float)) and not isinstance(raw_max, bool):
            max_minutes = max(1, min(30, int(raw_max)))
        # Wall-clock guard needs headroom beyond ZAP's own -T budget for startup/teardown.
        timeout = max_minutes * 60 + 120

        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    zap_bin,
                    "-t",
                    normalized_url,
                    "-J",
                    str(temp_path),
                    "-m",
                    str(spider_minutes),
                    "-T",
                    str(max_minutes),
                    "-I",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                return _tool_not_available_finding("OWASP ZAP", "zap", normalized_url, host, port)
            except Exception:
                return []

            try:
                await asyncio.wait_for(process.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return _scan_timeout_finding("OWASP ZAP", "zap", normalized_url, host, port)

            sites: list[dict] = []
            if temp_path.exists():
                try:
                    payload = json.loads(temp_path.read_text(encoding="utf-8"))
                    raw_sites = payload.get("site", []) if isinstance(payload, dict) else []
                    sites = raw_sites if isinstance(raw_sites, list) else []
                except (json.JSONDecodeError, OSError):
                    sites = []

            for site in sites:
                if not isinstance(site, dict):
                    continue
                alerts = site.get("alerts")
                if not isinstance(alerts, list):
                    continue
                for alert in alerts:
                    if isinstance(alert, dict):
                        findings.append(_zap_alert_finding(alert, normalized_url, host, port))

            return findings
        except Exception:
            return []
        finally:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass


class OpenVASScanner:
    """OpenVAS / Greenbone Vulnerability Manager (GVM) scanning.

    A real OpenVAS scan requires a running `gvmd` daemon reachable over the
    GMP protocol, plus provisioned scan configs and port lists - a stateful
    create-target -> create-task -> start -> poll -> fetch-report lifecycle
    that can run for tens of minutes, unlike the other scanners in this
    module which are bounded one-shot CLI calls. Zircon doesn't bundle or
    manage a GVM daemon, so rather than fabricate a finding (as this scanner
    previously did) we honestly report it as unavailable, exactly like the
    other scanners do when their underlying tool is missing.
    """

    @staticmethod
    async def scan(target: str, profile: str) -> list[dict]:
        target_url, host, port = _target_parts(target)
        return _tool_not_available_finding("OpenVAS/GVM", "openvas", target_url, host, port)
