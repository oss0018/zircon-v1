"""
Trusted Domain Matcher — TS-LAD-001 v1.1 §10.5.3.

Supports exact, wildcard (*.domain.tld), and suffix match types.
"""
from __future__ import annotations

from typing import List


class TrustedDomainMatcher:
    """
    Classify domains as trusted or untrusted based on a registry of patterns.

    Match types:
    - ``exact``:    fqdn must exactly equal the pattern.
    - ``wildcard``: pattern of the form ``*.domain.tld``; matches any
                    single-label subdomain of ``domain.tld``.
    - ``suffix``:   any fqdn ending with ``.pattern`` or equal to ``pattern``.
    """

    def __init__(self, trusted_entries: List[dict]) -> None:
        """
        Parameters
        ----------
        trusted_entries:
            List of dicts with keys ``fqdn_pattern``, ``match_type``,
            and (optionally) ``expires_at``.
        """
        from datetime import datetime, timezone

        self._exact: set[str] = set()
        self._wildcard_bases: list[str] = []   # e.g. "domain.tld" from "*.domain.tld"
        self._suffix_patterns: list[str] = []  # e.g. "domain.tld"

        now = datetime.now(timezone.utc)

        for entry in trusted_entries:
            # Skip expired entries
            expires_at = entry.get("expires_at")
            if expires_at is not None:
                try:
                    if isinstance(expires_at, str):
                        from datetime import datetime
                        exp = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
                    else:
                        exp = expires_at
                    if exp.tzinfo is None:
                        from datetime import timezone
                        exp = exp.replace(tzinfo=timezone.utc)
                    if exp < now:
                        continue
                except Exception:
                    pass

            pattern = (entry.get("fqdn_pattern") or "").lower().strip()
            match_type = (entry.get("match_type") or "exact").lower()

            if not pattern:
                continue

            if match_type == "exact":
                self._exact.add(pattern)
            elif match_type == "wildcard":
                if pattern.startswith("*."):
                    self._wildcard_bases.append(pattern[2:])
                else:
                    # Treat as suffix if not properly formed
                    self._suffix_patterns.append(pattern)
            elif match_type == "suffix":
                self._suffix_patterns.append(pattern)

    def is_trusted(self, fqdn: str) -> bool:
        """Return True if *fqdn* matches any trusted pattern."""
        fqdn = fqdn.lower().strip().rstrip(".")
        if not fqdn:
            return False

        # Exact match
        if fqdn in self._exact:
            return True

        # Wildcard match: *.domain.tld matches sub.domain.tld
        for base in self._wildcard_bases:
            if fqdn.endswith("." + base):
                # Ensure only one label before the base
                prefix = fqdn[: len(fqdn) - len(base) - 1]
                if "." not in prefix:
                    return True

        # Suffix match: any fqdn that IS or ENDS WITH .pattern
        for pat in self._suffix_patterns:
            if fqdn == pat or fqdn.endswith("." + pat):
                return True

        return False

    def classify(self, fqdn: str) -> str:
        """Return ``'trusted'`` or ``'unregistered'``."""
        return "trusted" if self.is_trusted(fqdn) else "unregistered"
