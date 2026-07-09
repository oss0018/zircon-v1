import json
import asyncio
import shutil
import tempfile
import uuid
from pathlib import Path
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


class TestSSLScanner:
    @staticmethod
    async def scan(hostname: str, port: int = 443) -> list[dict]:
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

        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    testssl_bin,
                    "--jsonfile",
                    str(temp_path),
                    "--quiet",
                    "--color",
                    "0",
                    "--warnings",
                    "off",
                    f"{safe_host}:{port}",
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


class NiktoScanner:
    @staticmethod
    async def scan(target: str) -> list[dict]:
        target_url, host, port = _target_parts(target)
        temp_path = Path(tempfile.gettempdir()) / f"nikto_{uuid.uuid4().hex}.json"
        findings: list[dict] = []
        nikto_bin = shutil.which("nikto") or shutil.which("nikto.pl")
        if not nikto_bin:
            return _tool_not_available_finding("Nikto", "nikto", target_url, host, port)

        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    nikto_bin,
                    "-h",
                    target_url,
                    "-Format",
                    "json",
                    "-output",
                    str(temp_path),
                    "-nointeractive",
                    "-maxtime",
                    "120s",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except FileNotFoundError:
                return _tool_not_available_finding("Nikto", "nikto", target_url, host, port)
            except Exception:
                return []

            try:
                await asyncio.wait_for(process.wait(), timeout=150)
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
    async def scan(target: str, profile: str) -> list[dict]:
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
        tags = profile_tags.get(profile, profile_tags["standard"])
        nuclei_bin = shutil.which("nuclei")
        if not nuclei_bin:
            return _tool_not_available_finding("Nuclei", "nuclei", target_url, host, port)

        cmd = [nuclei_bin, "-target", target]
        if profile != "deep" and tags:
            cmd.extend(["-tags", ",".join(tags)])
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
