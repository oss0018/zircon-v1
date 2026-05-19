"""
Tech Stack Intelligence Module — detect technologies from existing findings and map to CVEs.
"""
import asyncio
import json
import logging
import re

import httpx

logger = logging.getLogger(__name__)

_TECH_DETECTION_PATTERNS = [
    ("Apache", re.compile(r"\bApache(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*"),
    ("nginx", re.compile(r"\bnginx(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:nginx:nginx:{version}:*:*:*:*:*:*:*"),
    ("IIS", re.compile(r"\bIIS(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*"),
    ("PHP", re.compile(r"\bPHP(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*"),
    ("OpenSSH", re.compile(r"\bOpenSSH(?:[_/\s-])(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*"),
    ("WordPress", re.compile(r"\bWordPress(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*"),
    ("Drupal", re.compile(r"\bDrupal(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*"),
    ("Joomla", re.compile(r"\bJoomla!?[:/\s-]*(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:joomla:joomla\\!:{version}:*:*:*:*:*:*:*"),
    ("Tomcat", re.compile(r"\bTomcat(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:apache:tomcat:{version}:*:*:*:*:*:*:*"),
    ("lighttpd", re.compile(r"\blighttpd(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:lighttpd:lighttpd:{version}:*:*:*:*:*:*:*"),
    ("vsftpd", re.compile(r"\bvsftpd(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:vsftpd:vsftpd:{version}:*:*:*:*:*:*:*"),
    ("Postfix", re.compile(r"\bPostfix(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:postfix:postfix:{version}:*:*:*:*:*:*:*"),
    ("Exim", re.compile(r"\bExim(?:/?\s*|\s+)(\d+(?:\.\d+){0,3})?", re.I), "cpe:2.3:a:exim:exim:{version}:*:*:*:*:*:*:*"),
]


def _cvss_to_severity(score: float) -> int:
    if score >= 9:
        return 5
    if score >= 7:
        return 4
    if score >= 4:
        return 3
    return 2


class TechStackModule:
    def __init__(self, keys: dict[str, str]):
        self._keys = keys

    def detect_from_findings(self, findings: list[dict]) -> list[dict]:
        detected: list[dict] = []
        seen: set[tuple[str, str, str]] = set()

        for finding in findings or []:
            raw_data = finding.get("data_json") or {}
            if isinstance(raw_data, str):
                try:
                    raw_data = json.loads(raw_data)
                except Exception:
                    raw_data = {"raw": raw_data}

            banner_text = " ".join(
                str(raw_data.get(k, ""))
                for k in ("banner", "server", "title", "product", "version", "raw")
            ).strip()
            if not banner_text:
                continue

            for tech_name, pattern, cpe_template in _TECH_DETECTION_PATTERNS:
                match = pattern.search(banner_text)
                if not match:
                    continue
                version = (match.group(1) or "").strip() if match.lastindex else ""
                version_cpe = version if version else "*"
                cpe = cpe_template.format(version=version_cpe)
                dedupe_key = (tech_name.lower(), version, cpe)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                entity = f"{tech_name} {version}".strip()
                detected.append({
                    "entity": entity,
                    "module": "tech_stack",
                    "finding_type": "detected_tech",
                    "severity": 2,
                    "source": finding.get("source", "inferred"),
                    "data_json": json.dumps(
                        {
                            "tech_name": tech_name,
                            "version": version,
                            "cpe": cpe,
                            "evidence": banner_text[:300],
                            "from_entity": finding.get("entity", ""),
                        }
                    ),
                })

        return detected

    async def lookup_cves(self, tech_finding: dict) -> list[dict]:
        try:
            data = tech_finding.get("data_json") or "{}"
            data_obj = json.loads(data) if isinstance(data, str) else data
        except Exception:
            return []

        cpe_name = data_obj.get("cpe", "")
        if not cpe_name:
            return []

        # Public NVD API has strict unauthenticated rate limits; keep ~0.7s gap.
        await asyncio.sleep(0.7)
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cpeName": cpe_name, "resultsPerPage": 10}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, params=params)
                if resp.status_code != 200:
                    return []
                payload = resp.json()
        except Exception as exc:
            logger.debug("NVD lookup failed for %s: %s", cpe_name, exc)
            return []

        cve_findings: list[dict] = []
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            cve_id = cve.get("id", "")
            metrics = cve.get("metrics") or {}
            score = 0.0
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                values = metrics.get(metric_key) or []
                if values:
                    cvss_data = (values[0] or {}).get("cvssData") or {}
                    score = float(cvss_data.get("baseScore", 0.0) or 0.0)
                    break
            severity = _cvss_to_severity(score)
            description = ""
            for d in cve.get("descriptions") or []:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break
            cve_findings.append({
                "entity": cve_id or data_obj.get("tech_name", "unknown"),
                "module": "tech_stack",
                "finding_type": "cve",
                "severity": severity,
                "source": "nvd",
                "data_json": json.dumps(
                    {
                        "cve_id": cve_id,
                        "cvss_score": score,
                        "cpe": cpe_name,
                        "tech_name": data_obj.get("tech_name", ""),
                        "description": description[:800],
                    }
                ),
            })
        return cve_findings

    async def run(self, target: str, target_type: str, existing_findings: list[dict] | None = None) -> list[dict]:
        tech_findings = self.detect_from_findings(existing_findings or [])
        cve_findings: list[dict] = []
        high_cve_tech: set[str] = set()

        # Bound outbound enrichment requests per run to keep NVD usage predictable.
        for tf in tech_findings[:10]:
            tf_cves = await self.lookup_cves(tf)
            cve_findings.extend(tf_cves)
            if any(cve.get("severity", 1) >= 4 for cve in tf_cves):
                try:
                    tf_data = tf.get("data_json") or "{}"
                    tf_data_obj = json.loads(tf_data) if isinstance(tf_data, str) else tf_data
                    high_cve_tech.add(tf_data_obj.get("tech_name", "").lower())
                except Exception:
                    pass

        for tf in tech_findings:
            try:
                tf_data = tf.get("data_json") or "{}"
                tf_data_obj = json.loads(tf_data) if isinstance(tf_data, str) else tf_data
                if tf_data_obj.get("tech_name", "").lower() in high_cve_tech:
                    tf["severity"] = max(int(tf.get("severity", 2)), 3)
            except Exception:
                continue

        return tech_findings + cve_findings
