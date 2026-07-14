"""Validation and sanitization for per-scanner tool configuration.

Scan profiles (quick/standard/deep) pick which scanners run, but several of
them accept additional tuning beyond that fixed bundle: Nuclei template tags
and severity filters, ZAP baseline scan duration, testssl.sh check
categories, and Nikto tuning codes. This module defines the only shape that
configuration is allowed to take and strips or clamps anything else, so
malformed or hostile input can never reach a scanner's subprocess command
line.

The sanitized dict is stored as JSON on both ``VSScanTarget`` (a reusable
default) and ``VSScan`` (a snapshot of what was actually used for that run),
and passed straight through to the scanner ``scan()`` methods.
"""

VALID_NUCLEI_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_TESTSSL_CHECKS = {"protocols", "vulnerabilities", "headers"}

_NIKTO_TUNING_CHARS = set("0123456789abcx")

_ZAP_SPIDER_MINUTES_RANGE = (1, 10)
_ZAP_MAX_MINUTES_RANGE = (1, 30)
_NIKTO_MAX_TIME_RANGE = (30, 600)


def _clamp_int(value, low: int, high: int) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return max(low, min(high, int(value)))


def sanitize_scanner_config(raw: dict | None) -> dict:
    """Return a clean ``{tool: {options}}`` dict.

    Unknown top-level tools, unknown option keys, and invalid values are
    silently dropped rather than raising, since this runs both on API input
    (where we want a 200 with the sane subset) and on data already read back
    from the database.
    """
    if not isinstance(raw, dict):
        return {}

    clean: dict = {}

    nuclei = raw.get("nuclei")
    if isinstance(nuclei, dict):
        nuclei_clean: dict = {}
        severities = nuclei.get("severity")
        if isinstance(severities, list):
            picked = sorted(
                {s.lower() for s in severities if isinstance(s, str) and s.lower() in VALID_NUCLEI_SEVERITIES}
            )
            if picked:
                nuclei_clean["severity"] = picked
        tags = nuclei.get("tags")
        if isinstance(tags, str) and tags.strip():
            picked_tags = [
                t.strip().lower()
                for t in tags.split(",")
                if t.strip() and all(c.isalnum() or c == "-" for c in t.strip().lower())
            ]
            if picked_tags:
                nuclei_clean["tags"] = ",".join(dict.fromkeys(picked_tags))
        if nuclei_clean:
            clean["nuclei"] = nuclei_clean

    zap = raw.get("zap")
    if isinstance(zap, dict):
        zap_clean: dict = {}
        spider_minutes = _clamp_int(zap.get("spider_minutes"), *_ZAP_SPIDER_MINUTES_RANGE)
        if spider_minutes is not None:
            zap_clean["spider_minutes"] = spider_minutes
        max_minutes = _clamp_int(zap.get("max_minutes"), *_ZAP_MAX_MINUTES_RANGE)
        if max_minutes is not None:
            zap_clean["max_minutes"] = max_minutes
        if zap_clean:
            clean["zap"] = zap_clean

    testssl = raw.get("testssl")
    if isinstance(testssl, dict):
        testssl_clean: dict = {}
        if isinstance(testssl.get("fast"), bool):
            testssl_clean["fast"] = testssl["fast"]
        checks = testssl.get("checks")
        if isinstance(checks, list):
            picked_checks = sorted({c for c in checks if isinstance(c, str) and c in VALID_TESTSSL_CHECKS})
            if picked_checks:
                testssl_clean["checks"] = picked_checks
        if testssl_clean:
            clean["testssl"] = testssl_clean

    nikto = raw.get("nikto")
    if isinstance(nikto, dict):
        nikto_clean: dict = {}
        tuning = nikto.get("tuning")
        if isinstance(tuning, str) and tuning.strip():
            candidate = tuning.strip().lower()
            if candidate and all(c in _NIKTO_TUNING_CHARS for c in candidate):
                nikto_clean["tuning"] = candidate
        max_time = _clamp_int(nikto.get("max_time"), *_NIKTO_MAX_TIME_RANGE)
        if max_time is not None:
            nikto_clean["max_time"] = max_time
        if nikto_clean:
            clean["nikto"] = nikto_clean

    return clean
