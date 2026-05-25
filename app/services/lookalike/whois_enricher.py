"""
WHOIS enrichment — Look-alike Domains Phase 2.

Uses python-whois (whois) via asyncio run_in_executor to avoid blocking the
event loop.  Returns a dict with standardised fields; all values are None on
any error so callers can treat the result unconditionally.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Optional


# Privacy / proxy registrar keywords (lower-case)
_PRIVACY_KEYWORDS = {"privacy", "proxy", "redacted", "whoisguard", "withheld", "protection", "private"}


def _epoch_days(dt: Optional[datetime]) -> Optional[int]:
    """Return the age of *dt* in full days, or None."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    return max(0, delta.days)


def _as_datetime(value) -> Optional[datetime]:
    """Normalise a whois creation/expiry value to a single datetime or None."""
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if isinstance(value, datetime):
        return value
    return None


def _has_privacy(raw: dict) -> bool:
    """Return True if any registrant field hints at a privacy/proxy service."""
    fields = [
        raw.get("registrar", ""),
        raw.get("org", ""),
        raw.get("name", ""),
        raw.get("emails", ""),
    ]
    combined = " ".join(str(f) if f else "" for f in fields).lower()
    return any(kw in combined for kw in _PRIVACY_KEYWORDS)


def _enrich_sync(fqdn: str) -> dict:
    """Blocking WHOIS look-up — run inside an executor."""
    try:
        import whois  # python-whois

        w = whois.whois(fqdn)
        if not w or not w.domain_name:
            return _null_result()

        raw = w if isinstance(w, dict) else dict(w)

        creation_date = _as_datetime(w.creation_date)
        expiry_date = _as_datetime(w.expiration_date)

        registrar = str(w.registrar).strip() if w.registrar else None
        registrant_org = (
            str(w.org).strip() if getattr(w, "org", None) else
            str(w.registrant_org).strip() if getattr(w, "registrant_org", None) else
            None
        )

        return {
            "registrar": registrar,
            "domain_age_days": _epoch_days(creation_date),
            "whois_privacy": _has_privacy(raw),
            "creation_date": creation_date,
            "expiry_date": expiry_date,
            "registrant_org": registrant_org,
        }
    except Exception:
        return _null_result()


def _null_result() -> dict:
    return {
        "registrar": None,
        "domain_age_days": None,
        "whois_privacy": None,
        "creation_date": None,
        "expiry_date": None,
        "registrant_org": None,
    }


async def enrich_whois(fqdn: str) -> dict:
    """
    Async WHOIS enrichment for *fqdn*.

    Returns a dict with keys: registrar, domain_age_days, whois_privacy,
    creation_date, expiry_date, registrant_org.  All values are None on error.
    """
    try:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _enrich_sync, fqdn)
    except Exception:
        return _null_result()
