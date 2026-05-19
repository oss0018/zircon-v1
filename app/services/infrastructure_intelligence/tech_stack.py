import asyncio
import json
import re

import httpx


class TechStackModule:
    HIGH_CVE_THRESHOLD = 7.0
    NVD_REQUEST_DELAY = 0.7
    TECH_PATTERNS = {
        "apache": [re.compile(r"\bapache(?:/?\s*httpd)?(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
        "nginx": [re.compile(r"\bnginx(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
        "iis": [re.compile(r"\b(?:microsoft-)?iis(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
        "openssl": [re.compile(r"\bopenssl(?:[ /-]?v?(\d+(?:\.\d+){0,3}[a-z]?))?\b", re.I)],
        "openssh": [re.compile(r"\bopenssh(?:[ /-]?v?(\d+(?:\.\d+){0,3}[a-z]?))?\b", re.I)],
        "php": [re.compile(r"\bphp(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
        "wordpress": [re.compile(r"\bwordpress(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
        "drupal": [re.compile(r"\bdrupal(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
        "joomla": [re.compile(r"\bjoomla!?[\s/-]*v?(\d+(?:\.\d+){0,3})?\b", re.I)],
        "tomcat": [re.compile(r"\b(?:apache )?tomcat(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
        "redis": [re.compile(r"\bredis(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
        "mongodb": [re.compile(r"\bmongodb(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
        "elasticsearch": [re.compile(r"\belasticsearch(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
        "jenkins": [re.compile(r"\bjenkins(?:[ /-]?v?(\d+(?:\.\d+){0,3}))?\b", re.I)],
    }

    CPE_MAP = {
        "apache": "cpe:2.3:a:apache:http_server:{version}:*:*:*:*:*:*:*",
        "nginx": "cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*",
        "iis": "cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*",
        "openssl": "cpe:2.3:a:openssl:openssl:{version}:*:*:*:*:*:*:*",
        "openssh": "cpe:2.3:a:openbsd:openssh:{version}:*:*:*:*:*:*:*",
        "php": "cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*",
        "wordpress": "cpe:2.3:a:wordpress:wordpress:{version}:*:*:*:*:*:*:*",
        "drupal": "cpe:2.3:a:drupal:drupal:{version}:*:*:*:*:*:*:*",
        "joomla": "cpe:2.3:a:joomla:joomla\\!:{version}:*:*:*:*:*:*:*",
        "tomcat": "cpe:2.3:a:apache:tomcat:{version}:*:*:*:*:*:*:*",
        "redis": "cpe:2.3:a:redislabs:redis:{version}:*:*:*:*:*:*:*",
        "mongodb": "cpe:2.3:a:mongodb:mongodb:{version}:*:*:*:*:*:*:*",
        "elasticsearch": "cpe:2.3:a:elastic:elasticsearch:{version}:*:*:*:*:*:*:*",
        "jenkins": "cpe:2.3:a:jenkins:jenkins:{version}:*:*:*:*:*:*:*",
    }

    def __init__(self):
        pass

    def extract_tech_from_findings(self, findings: list[dict]) -> list[dict]:
        text_blobs: list[str] = []
        for finding in findings:
            raw = finding.get("data_json", "")
            if isinstance(raw, str):
                text_blobs.append(raw)
            elif isinstance(raw, (dict, list)):
                text_blobs.append(json.dumps(raw))
            else:
                text_blobs.append(str(raw))

        detected: dict[tuple[str, str], dict] = {}
        for blob in text_blobs:
            for tech, patterns in self.TECH_PATTERNS.items():
                for pattern in patterns:
                    for match in pattern.finditer(blob):
                        version = (match.group(1) or "").strip() or "unknown"
                        key = (tech, version)
                        if key not in detected:
                            detected[key] = {"tech": tech, "version": version}
        return list(detected.values())

    async def query_nvd_cves(self, tech: str, version: str) -> list[dict]:
        """Query NVD CVE API for a resolved CPE.

        Uses a 0.7 second pre-request delay per call to stay within free-tier rate
        limits and maps CVSS v3.1/v3.0/v2 scores into a normalized finding shape.
        """
        cpe_template = self.CPE_MAP.get(tech)
        if not cpe_template:
            return []
        cpe_name = cpe_template.format(version=version if version != "unknown" else "*")

        await asyncio.sleep(self.NVD_REQUEST_DELAY)
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"cpeName": cpe_name},
                )
                if resp.status_code != 200:
                    return []
                payload = resp.json()
        except Exception:
            return []

        out: list[dict] = []
        for item in payload.get("vulnerabilities") or []:
            cve = item.get("cve") or {}
            metrics = cve.get("metrics") or {}
            score = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                values = metrics.get(key) or []
                if values:
                    cvss_data = values[0].get("cvssData") or {}
                    score = float(cvss_data.get("baseScore") or 0.0)
                    break
            desc = ""
            for d in cve.get("descriptions") or []:
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            out.append(
                {
                    "cve_id": cve.get("id", ""),
                    "description": desc,
                    "cvss_score": score,
                    "severity": self.cvss_to_severity(score),
                    "published": cve.get("published", ""),
                }
            )
        return out

    def cvss_to_severity(self, score: float) -> int:
        if score >= 9:
            return 5
        if score >= 7:
            return 4
        if score >= 4:
            return 3
        if score >= 0.1:
            return 2
        return 1

    async def run(self, _target: str, _target_type: str, existing_findings: list[dict]) -> list[dict]:
        """Run tech detection/CVE enrichment.

        _target and _target_type are part of the module interface for consistency
        with other infrastructure modules.
        """
        findings: list[dict] = []
        techs = self.extract_tech_from_findings(existing_findings)

        for tech_info in techs:
            findings.append(
                {
                    "entity": f"{tech_info['tech']}:{tech_info['version']}",
                    "module": "tech_stack",
                    "finding_type": "detected_tech",
                    "severity": 1,
                    "source": "tech_parser",
                    "data_json": json.dumps(tech_info),
                }
            )

        cve_tasks = [self.query_nvd_cves(t["tech"], t["version"]) for t in techs]
        cve_results = await asyncio.gather(*cve_tasks, return_exceptions=True)
        for tech_info, cves in zip(techs, cve_results):
            if isinstance(cves, Exception):
                continue
            for cve in cves:
                score = float(cve.get("cvss_score") or 0.0)
                if score < self.HIGH_CVE_THRESHOLD:
                    continue
                findings.append(
                    {
                        "entity": f"{tech_info['tech']}:{tech_info['version']}",
                        "module": "tech_stack",
                        "finding_type": "cve_match",
                        "severity": self.cvss_to_severity(score),
                        "source": "nvd",
                        "data_json": json.dumps(
                            {
                                "tech": tech_info["tech"],
                                "version": tech_info["version"],
                                **cve,
                            }
                        ),
                    }
                )

        return findings
