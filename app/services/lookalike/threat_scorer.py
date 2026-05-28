"""
Threat Scorer — TS-LAD-001 v1.1 §8.4.

21 signals → integer threat_score (0–100) and severity (1–5).
"""
from __future__ import annotations

from typing import Dict, List, Tuple

# ── 20 signal weights (total baseline = 100) ──────────────────────────────────
WEIGHTS: Dict[str, int] = {
    # DNS signals
    "S01_has_a_record":              8,   # domain resolves (has A record)
    "S02_has_mx_record":             10,  # can send/receive email
    "S03_has_ns_record":             5,   # has authoritative NS
    # HTTP signals
    "S04_http_active":               8,   # HTTP 200-399 response
    "S05_brand_in_title":            12,  # brand term in page <title>
    "S06_phishing_kw_in_title":      10,  # phishing keyword in <title>
    "S07_redirect_detected":         3,   # HTTP redirect present
    "S08_redirects_to_legitimate":   -8,  # redirects back to legitimate site (negative)
    # SSL signals
    "S09_ssl_valid":                 3,   # valid TLS cert
    "S10_ssl_lets_encrypt":          5,   # Let's Encrypt cert (common in phishing)
    "S11_ssl_self_signed":           6,   # self-signed cert
    "S12_ssl_new_cert":              5,   # cert < 30 days old
    # Domain-age / WHOIS signals
    "S13_domain_new":                10,  # domain < 30 days old
    "S14_whois_privacy":             4,   # WHOIS privacy enabled
    # GeoIP signals
    "S15_high_risk_country":         6,   # high-risk country code
    # Similarity signals
    "S16_high_similarity":           8,   # composite similarity ≥ 0.85
    "S17_very_high_similarity":      5,   # composite similarity ≥ 0.95 (additive bonus)
    "S18_levenshtein_1":             8,   # Levenshtein distance == 1 (extremely close)
    # IDN / script signal
    "S19_is_idn":                    4,   # Internationalized domain (potential homograph)
    # False-positive discount
    "S20_is_false_positive":         -100, # marked as false positive → score 0
}


def score(domain_data: dict) -> Tuple[int, int, List[str]]:
    """
    Compute threat score for a domain.

    Parameters
    ----------
    domain_data:
        Dict (or ORM-like object) with the same fields as ``LookalikeDomain``.
        Can be a plain dict or any object with attribute access.

    Returns
    -------
    (threat_score, severity, signals_fired)
    """

    def _get(field: str, default=None):
        if isinstance(domain_data, dict):
            return domain_data.get(field, default)
        return getattr(domain_data, field, default)

    signals_fired: List[str] = []
    raw_score = 0

    # S20 check first — short-circuit
    if _get("is_false_positive"):
        return 0, 1, ["S20_is_false_positive"]

    # S01: has A record
    if _get("has_a_record"):
        signals_fired.append("S01_has_a_record")
        raw_score += WEIGHTS["S01_has_a_record"]

    # S02: has MX record
    if _get("has_mx_record"):
        signals_fired.append("S02_has_mx_record")
        raw_score += WEIGHTS["S02_has_mx_record"]

    # S03: has NS record
    if _get("has_ns_record"):
        signals_fired.append("S03_has_ns_record")
        raw_score += WEIGHTS["S03_has_ns_record"]

    # S04: HTTP active (status 2xx or 3xx)
    http_status = _get("http_status")
    if http_status is not None and 200 <= http_status < 400:
        signals_fired.append("S04_http_active")
        raw_score += WEIGHTS["S04_http_active"]

    # S05: brand in title
    if _get("brand_in_title"):
        signals_fired.append("S05_brand_in_title")
        raw_score += WEIGHTS["S05_brand_in_title"]

    # S06: phishing keywords in title
    if _get("phishing_keywords_in_title"):
        signals_fired.append("S06_phishing_kw_in_title")
        raw_score += WEIGHTS["S06_phishing_kw_in_title"]

    # S07: redirect detected
    if _get("redirect_detected"):
        signals_fired.append("S07_redirect_detected")
        raw_score += WEIGHTS["S07_redirect_detected"]

    # S08: redirects to legitimate (negative)
    if _get("redirects_to_legitimate"):
        signals_fired.append("S08_redirects_to_legitimate")
        raw_score += WEIGHTS["S08_redirects_to_legitimate"]

    # S09: SSL valid
    if _get("ssl_valid"):
        signals_fired.append("S09_ssl_valid")
        raw_score += WEIGHTS["S09_ssl_valid"]

    # S10: Let's Encrypt
    if _get("ssl_uses_lets_encrypt"):
        signals_fired.append("S10_ssl_lets_encrypt")
        raw_score += WEIGHTS["S10_ssl_lets_encrypt"]

    # S11: self-signed
    if _get("ssl_is_self_signed"):
        signals_fired.append("S11_ssl_self_signed")
        raw_score += WEIGHTS["S11_ssl_self_signed"]

    # S12: cert < 30 days old
    cert_age = _get("ssl_cert_age_days")
    if cert_age is not None and 0 <= cert_age < 30:
        signals_fired.append("S12_ssl_new_cert")
        raw_score += WEIGHTS["S12_ssl_new_cert"]

    # S13: domain < 30 days old
    domain_age = _get("domain_age_days")
    if domain_age is not None and 0 <= domain_age < 30:
        signals_fired.append("S13_domain_new")
        raw_score += WEIGHTS["S13_domain_new"]

    # S14: WHOIS privacy
    if _get("whois_privacy"):
        signals_fired.append("S14_whois_privacy")
        raw_score += WEIGHTS["S14_whois_privacy"]

    # S15: high-risk country
    if _get("is_high_risk_country"):
        signals_fired.append("S15_high_risk_country")
        raw_score += WEIGHTS["S15_high_risk_country"]

    # S21: VirusTotal detections
    vt_points = 0
    vt_malicious = _get("vt_malicious")
    vt_suspicious = _get("vt_suspicious")
    if vt_malicious is not None and vt_malicious >= 3:
        vt_points += 35
    elif vt_malicious is not None and vt_malicious >= 1:
        vt_points += 15
    if vt_suspicious is not None and vt_suspicious >= 5:
        vt_points += 10
    if vt_points > 0:
        signals_fired.append("S21_vt_detected")
        raw_score += vt_points

    # S16: high similarity (≥ 0.85)
    sim = _get("similarity_score")
    if sim is not None and sim >= 0.85:
        signals_fired.append("S16_high_similarity")
        raw_score += WEIGHTS["S16_high_similarity"]

    # S17: very high similarity (≥ 0.95, additive)
    if sim is not None and sim >= 0.95:
        signals_fired.append("S17_very_high_similarity")
        raw_score += WEIGHTS["S17_very_high_similarity"]

    # S18: Levenshtein distance == 1
    lev = _get("levenshtein_distance")
    if lev is not None and lev == 1:
        signals_fired.append("S18_levenshtein_1")
        raw_score += WEIGHTS["S18_levenshtein_1"]

    # S19: IDN (homograph attack potential)
    if _get("is_idn"):
        signals_fired.append("S19_is_idn")
        raw_score += WEIGHTS["S19_is_idn"]

    # Clamp to 0–100
    threat_score = max(0, min(100, raw_score))

    # Map to severity 1–5 per §8.3
    if threat_score <= 20:
        severity = 1
    elif threat_score <= 40:
        severity = 2
    elif threat_score <= 60:
        severity = 3
    elif threat_score <= 80:
        severity = 4
    else:
        severity = 5

    return threat_score, severity, signals_fired


class ThreatScorer:
    """Wrapper class around the module-level score() function."""

    def score(self, domain_data) -> Tuple[int, int, List[str]]:
        """Compute (threat_score, severity, signals_fired)."""
        return score(domain_data)
