"""
Shared scoring helpers for the Impersonation Monitoring scanner (TS-IMP-001).

Provides reusable primitives for domain similarity, text matching, and
composite threat-score calculation used by M1, M5, M7, and M8 sub-scanners.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Sequence


def domain_label(fqdn: str) -> str:
    """Return the second-level domain label (SLD) from a fully-qualified domain name."""
    parts = str(fqdn).strip().lower().split(".")
    return parts[0] if parts else fqdn.lower()


def similarity_ratio(a: str, b: str) -> float:
    """
    Compute a 0–100 similarity ratio between two strings using rapidfuzz.

    Falls back to a simple difflib-based ratio if rapidfuzz is unavailable.
    Returns a float in the range ``[0.0, 100.0]``.
    """
    a = a.strip().lower()
    b = b.strip().lower()
    if not a and not b:
        return 100.0
    if not a or not b:
        return 0.0
    try:
        from rapidfuzz import fuzz  # type: ignore
        return float(fuzz.ratio(a, b))
    except ImportError:
        import difflib
        return difflib.SequenceMatcher(None, a, b).ratio() * 100.0


def partial_similarity_ratio(a: str, b: str) -> float:
    """
    Compute a partial (substring-aware) similarity ratio using rapidfuzz.

    Returns a float in the range ``[0.0, 100.0]``.
    """
    a = a.strip().lower()
    b = b.strip().lower()
    if not a and not b:
        return 100.0
    if not a or not b:
        return 0.0
    try:
        from rapidfuzz import fuzz  # type: ignore
        return float(fuzz.partial_ratio(a, b))
    except ImportError:
        return similarity_ratio(a, b)


def token_set_ratio(a: str, b: str) -> float:
    """
    Token-set similarity ratio for hyphenated / multi-word strings.

    Returns a float in the range ``[0.0, 100.0]``.
    """
    a_tokens = re.sub(r"[-_]", " ", a.strip().lower())
    b_tokens = re.sub(r"[-_]", " ", b.strip().lower())
    try:
        from rapidfuzz import fuzz  # type: ignore
        return float(fuzz.token_set_ratio(a_tokens, b_tokens))
    except ImportError:
        return similarity_ratio(a_tokens, b_tokens)


def best_domain_similarity(candidate_fqdn: str, reference_domains: Sequence[str]) -> tuple[float, str]:
    """
    Return the highest similarity score (0–100) and the matching reference domain
    when comparing *candidate_fqdn* against a list of *reference_domains*.

    The comparison is made against the SLD portion of each domain.
    """
    sld = domain_label(candidate_fqdn)
    best_score = 0.0
    best_ref = ""
    for ref in reference_domains:
        ref_sld = domain_label(ref)
        score = max(
            similarity_ratio(sld, ref_sld),
            token_set_ratio(sld, ref_sld),
        )
        if score > best_score:
            best_score = score
            best_ref = ref
    return best_score, best_ref


def contains_keywords(text: str, keywords: Sequence[str]) -> list[str]:
    """Return the subset of *keywords* found (case-insensitively) in *text*."""
    text_lower = text.lower()
    return [kw for kw in keywords if kw.lower() in text_lower]


def score_badge(threat_score: int) -> str:
    """Return an emoji badge for a given threat score (for alert messages)."""
    if threat_score >= 80:
        return "🔴"
    if threat_score >= 50:
        return "🟡"
    return "🟢"
