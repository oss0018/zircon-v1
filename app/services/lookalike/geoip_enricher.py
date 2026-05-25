"""
GeoIP enrichment — Look-alike Domains Phase 2.

Uses the free ip-api.com JSON endpoint (no API key required).
Private/loopback addresses are skipped via the ipaddress stdlib module.
All values are None on error so callers can treat the result unconditionally.
"""
from __future__ import annotations

import ipaddress
from typing import Optional

import httpx

HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR", "BY", "SY", "CU", "VE", "NG", "PK"}

_IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,org,as"
_TIMEOUT = 5.0


def _null_result() -> dict:
    return {
        "country_code": None,
        "asn": None,
        "org": None,
        "is_high_risk_country": None,
    }


def _is_private(ip: str) -> bool:
    """Return True if *ip* is a private, loopback, or link-local address."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
    except ValueError:
        return False


async def enrich_geoip(ip: Optional[str]) -> dict:
    """
    Async GeoIP enrichment for *ip*.

    Returns a dict with keys: country_code, asn, org, is_high_risk_country.
    All values are None when ip is absent, private, or the request fails.
    """
    if not ip:
        return _null_result()

    if _is_private(ip):
        return _null_result()

    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            resp = await client.get(_IP_API_URL.format(ip=ip))
            if resp.status_code != 200:
                return _null_result()

            data = resp.json()
            if data.get("status") != "success":
                return _null_result()

            country_code = data.get("countryCode") or None
            asn = data.get("as") or None
            org = data.get("org") or None

            return {
                "country_code": country_code,
                "asn": asn,
                "org": org,
                "is_high_risk_country": country_code in HIGH_RISK_COUNTRIES if country_code else None,
            }
    except Exception:
        return _null_result()
