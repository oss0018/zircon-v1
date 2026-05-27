import json

from app.models import VSFinding


class RemediationEngine:
    REMEDIATION_DB = {
        "CWE-79": {
            "summary": "Reflected/stored XSS risk detected.",
            "steps": [
                "Apply contextual output encoding.",
                "Use strict input validation and sanitization.",
                "Enable CSP with nonces/hashes where possible.",
            ],
            "effort": "MEDIUM",
        },
        "CWE-89": {
            "summary": "SQL injection risk detected.",
            "steps": [
                "Use parameterized queries/prepared statements.",
                "Avoid dynamic SQL concatenation.",
                "Add server-side validation and least-privileged DB accounts.",
            ],
            "effort": "HIGH",
        },
        "CWE-319": {
            "summary": "Sensitive data might be exposed due to missing transport hardening.",
            "steps": [
                "Enforce HTTPS end-to-end.",
                "Set Strict-Transport-Security with long max-age and includeSubDomains.",
            ],
            "effort": "LOW",
        },
        "CWE-693": {
            "summary": "Missing defense-in-depth security policy.",
            "steps": [
                "Add a restrictive Content-Security-Policy.",
                "Avoid inline scripts and eval-like constructs.",
            ],
            "effort": "MEDIUM",
        },
        "CWE-1021": {
            "summary": "UI redressing/clickjacking risk identified.",
            "steps": [
                "Set X-Frame-Options to DENY or SAMEORIGIN.",
                "Use CSP frame-ancestors as a stronger control.",
            ],
            "effort": "LOW",
        },
        "HSTS_MISSING": {
            "summary": "HSTS is missing or weak.",
            "steps": ["Set Strict-Transport-Security with max-age>=31536000 and includeSubDomains."],
            "effort": "LOW",
        },
        "CSP_MISSING": {
            "summary": "Content-Security-Policy is missing.",
            "steps": ["Define a least-privilege Content-Security-Policy."],
            "effort": "MEDIUM",
        },
        "X_FRAME_MISSING": {
            "summary": "X-Frame-Options is missing or invalid.",
            "steps": ["Set X-Frame-Options to DENY or SAMEORIGIN."],
            "effort": "LOW",
        },
        "SPF_MISSING": {
            "summary": "SPF record missing for domain.",
            "steps": ["Publish SPF TXT record and validate mail sources."],
            "effort": "LOW",
        },
        "DMARC_MISSING": {
            "summary": "DMARC policy is missing.",
            "steps": ["Publish DMARC TXT record with monitoring policy and reporting."],
            "effort": "LOW",
        },
        "SSL_POODLE": {
            "summary": "Legacy TLS/SSL configuration risk.",
            "steps": ["Disable SSLv3/TLS1.0 and weak cipher suites.", "Prefer modern TLS configurations."],
            "effort": "MEDIUM",
        },
        "SSL_HEARTBLEED": {
            "summary": "Potential OpenSSL Heartbleed exposure.",
            "steps": ["Upgrade OpenSSL to a patched version and rotate keys/certificates."],
            "effort": "HIGH",
            "patch_available": True,
        },
    }

    @classmethod
    def _references_from_ids(cls, finding: VSFinding) -> list[str]:
        refs: list[str] = []

        try:
            cve_ids = json.loads(finding.cve_ids_json or "[]")
        except Exception:
            cve_ids = []
        try:
            cwe_ids = json.loads(finding.cwe_ids_json or "[]")
        except Exception:
            cwe_ids = []

        for cve_id in cve_ids:
            refs.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        for cwe_id in cwe_ids:
            cwe_num = str(cwe_id).replace("CWE-", "")
            refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")

        return refs

    @classmethod
    def enrich(cls, finding: VSFinding) -> VSFinding:
        try:
            cve_ids = json.loads(finding.cve_ids_json or "[]")
        except Exception:
            cve_ids = []
        try:
            cwe_ids = json.loads(finding.cwe_ids_json or "[]")
        except Exception:
            cwe_ids = []

        keys = [*cve_ids, *cwe_ids, finding.finding_type]
        rem = None
        for key in keys:
            rem = cls.REMEDIATION_DB.get(key)
            if rem:
                break

        if rem:
            if "summary" in rem:
                finding.remediation_summary = rem["summary"]
            finding.remediation_steps_json = json.dumps(rem.get("steps", []))
            if "effort" in rem:
                finding.remediation_effort = rem["effort"]
            finding.patch_available = bool(rem.get("patch_available", finding.patch_available))
            if rem.get("patch_url"):
                finding.patch_url = rem.get("patch_url")

        finding.references_json = json.dumps(cls._references_from_ids(finding))
        return finding
