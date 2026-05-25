"""
Similarity Calculator — TS-LAD-001 v1.1 §6.5.2.

Composite score = max(levenshtein_ratio, unicode_skeleton_ratio).
"""
from __future__ import annotations

import unicodedata
from typing import Dict

# ── Confusable map: Unicode char → ASCII equivalent ───────────────────────────
# Covers all Cyrillic↔Latin and Greek↔Latin mappings derived from
# UNICODE_HOMOGLYPHS in generators.py (reverse mapping).
CONFUSABLE_MAP: Dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a",   # Cyrillic а → a
    "\u0432": "b",   # Cyrillic в → b
    "\u0441": "c",   # Cyrillic с → c
    "\u0435": "e",   # Cyrillic е → e
    "\u04bd": "e",   # Cyrillic Ё-like → e
    "\u0570": "h",   # Armenian հ → h
    "\u0456": "i",   # Cyrillic і → i
    "\u04cf": "i",   # Cyrillic lowercase palochka → i
    "\u0458": "j",   # Cyrillic je → j
    "\u043a": "k",   # Cyrillic к → k
    "\u04c0": "l",   # Cyrillic palochka → l
    "\u043c": "m",   # Cyrillic м → m
    "\u0578": "n",   # Armenian vo → n
    "\u0459": "n",   # Cyrillic lje → n
    "\u043e": "o",   # Cyrillic о → o
    "\u03bf": "o",   # Greek ο → o
    "\u0440": "p",   # Cyrillic р → p
    "\u03c1": "p",   # Greek ρ → p
    "\u0563": "q",   # Armenian ben → q
    "\u0433": "r",   # Cyrillic г → r
    "\u0455": "s",   # Cyrillic dze → s
    "\u0442": "t",   # Cyrillic т → t
    "\u0446": "u",   # Cyrillic ц → u
    "\u03c5": "u",   # Greek υ → u
    "\u03bd": "v",   # Greek ν → v
    "\u0448": "w",   # Cyrillic ш → w
    "\u0445": "x",   # Cyrillic х → x
    "\u03c7": "x",   # Greek χ → x
    "\u0443": "y",   # Cyrillic у → y
    "\u03b3": "y",   # Greek γ → y
    "\u0290": "z",   # Latin z with retroflex → z
    "\u0261": "g",   # Latin g with hook → g
    "\u04bb": "h",   # Cyrillic shha → h
    "\u0501": "d",   # Cyrillic d-like → d
    # Greek lowercase additional
    "\u03b1": "a",   # Greek α → a
    "\u03b2": "b",   # Greek β → b
    "\u03b5": "e",   # Greek ε → e
    "\u03b9": "i",   # Greek ι → i
    "\u03ba": "k",   # Greek κ → k
    "\u03bc": "m",   # Greek μ → m
    "\u03bd": "n",   # Greek ν → n (alt)
    "\u03be": "x",   # Greek ξ → x (rough)
    "\u03c0": "p",   # Greek π → p (rough)
    "\u03c4": "t",   # Greek τ → t
    # Digit lookalikes
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
}


class SimilarityCalculator:
    """
    Compute composite similarity between two domain labels (§6.5.2).

    Score = max(levenshtein_ratio, unicode_skeleton_ratio), 0.0–1.0.
    """

    def compute(self, candidate_label: str, protected_label: str) -> float:
        """Return similarity score 0.0–1.0."""
        c_norm = self._normalise(candidate_label)
        p_norm = self._normalise(protected_label)

        # Metric 1: Levenshtein ratio via rapidfuzz
        lev_score = self._lev_ratio(c_norm, p_norm)

        # Metric 2: Unicode skeleton comparison
        c_skel = self._to_skeleton(c_norm)
        p_skel = self._to_skeleton(p_norm)
        skel_score = self._lev_ratio(c_skel, p_skel)

        return max(lev_score, skel_score)

    def _lev_ratio(self, s1: str, s2: str) -> float:
        """Levenshtein similarity ratio using rapidfuzz (or fallback)."""
        if not s1 and not s2:
            return 1.0
        if not s1 or not s2:
            return 0.0
        try:
            from rapidfuzz import fuzz  # type: ignore
            return fuzz.ratio(s1, s2) / 100.0
        except ImportError:
            # Pure-Python fallback
            from app.services.lookalike.generators import _simple_levenshtein
            dist = _simple_levenshtein(s1, s2)
            max_len = max(len(s1), len(s2))
            return 1.0 - dist / max_len if max_len else 1.0

    def _normalise(self, label: str) -> str:
        """Lowercase and NFKD-normalise."""
        return unicodedata.normalize("NFKD", label.lower())

    def _to_skeleton(self, label: str) -> str:
        """
        Map confusable Unicode chars to their ASCII equivalents,
        then strip diacritics via NFKD decomposition.
        """
        mapped = "".join(CONFUSABLE_MAP.get(ch, ch) for ch in label)
        # Strip combining diacritical marks
        decomposed = unicodedata.normalize("NFD", mapped)
        ascii_only = "".join(ch for ch in decomposed if unicodedata.category(ch) != "Mn")
        return ascii_only
