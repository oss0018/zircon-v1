"""
Evidence Generator — Impersonation Monitoring Phase 2 (TS-IMP-001 v2).

Builds a UDRP evidence package for a TakedownRequest.  The package is a
structured dict that can be serialised to JSON (for storage) or rendered
to HTML/PDF by a downstream template engine.

Components collected (all optional and gated by the caller's flags):
- Screenshot via URLScan.io
- WHOIS data
- DNS A/MX/NS records
- Archive.org availability check
- Narrative / claim text supplied by the requester

Usage::

    from app.services.impersonation.evidence_generator import build_evidence_package
    package = await build_evidence_package(
        takedown_id=7,
        include_screenshot=True,
        include_whois=True,
        include_dns=True,
        include_archive=True,
        narrative="This domain infringes our registered trademark …",
    )
"""
from __future__ import annotations

import logging
import os
import socket
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_URLSCAN_API = "https://urlscan.io/api/v1"
_ARCHIVE_API = "https://archive.org/wayback/available"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def _urlscan_submit(url: str) -> dict:
    """Submit a URL to URLScan.io and return the scan metadata."""
    api_key = os.environ.get("URLSCAN_API_KEY", "")
    if not api_key:
        logger.info("[EvidenceGen] URLSCAN_API_KEY not set — screenshot skipped.")
        return {}
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{_URLSCAN_API}/scan/",
                headers={"API-Key": api_key, "Content-Type": "application/json"},
                json={"url": url, "visibility": "private"},
            )
            resp.raise_for_status()
            data = resp.json()
            return {
                "uuid": data.get("uuid"),
                "result_url": data.get("result"),
                "api_result": data.get("api"),
                "visibility": data.get("visibility"),
                "submitted_at": _utcnow().isoformat(),
            }
    except Exception as exc:  # noqa: BLE001
        logger.warning("[EvidenceGen] URLScan submit failed for %s: %s", url, exc)
        return {"error": str(exc)}


async def _whois_lookup(domain: str) -> dict:
    """Fetch WHOIS data via the WhoisXML API."""
    api_key = os.environ.get("WHOISXML_API_KEY", "")
    if not api_key:
        logger.info("[EvidenceGen] WHOISXML_API_KEY not set — WHOIS skipped.")
        return {}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                "https://www.whoisxmlapi.com/whoisserver/WhoisService",
                params={
                    "apiKey": api_key,
                    "domainName": domain,
                    "outputFormat": "JSON",
                },
            )
            resp.raise_for_status()
            return resp.json()
    except Exception as exc:  # noqa: BLE001
        logger.warning("[EvidenceGen] WHOIS lookup failed for %s: %s", domain, exc)
        return {"error": str(exc)}


def _dns_resolve(domain: str) -> dict:
    """Resolve A, MX, and NS records for *domain* using stdlib socket."""
    result: dict[str, Any] = {}
    try:
        a_records = socket.getaddrinfo(domain, None, socket.AF_INET)
        result["a"] = list({addr[-1][0] for addr in a_records})
    except Exception as exc:  # noqa: BLE001
        result["a_error"] = str(exc)

    # MX / NS require a proper DNS library; use dnspython if available, else skip
    try:
        import dns.resolver  # type: ignore

        for rtype in ("MX", "NS"):
            try:
                answers = dns.resolver.resolve(domain, rtype)
                result[rtype.lower()] = [str(r) for r in answers]
            except Exception:  # noqa: BLE001
                result[rtype.lower()] = []
    except ImportError:
        logger.debug("[EvidenceGen] dnspython not installed; MX/NS resolution skipped.")

    return result


async def _archive_check(url: str) -> dict:
    """Check if a URL is archived on the Wayback Machine."""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(_ARCHIVE_API, params={"url": url})
            resp.raise_for_status()
            data = resp.json()
            snapshot = (data.get("archived_snapshots") or {}).get("closest") or {}
            return {
                "available": snapshot.get("available", False),
                "url": snapshot.get("url"),
                "timestamp": snapshot.get("timestamp"),
                "status": snapshot.get("status"),
            }
    except Exception as exc:  # noqa: BLE001
        logger.warning("[EvidenceGen] Archive check failed for %s: %s", url, exc)
        return {"error": str(exc)}


async def _http_headers_snapshot(url: str) -> dict:
    """Capture response headers for evidentiary context."""
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url)
            headers = {k: v for k, v in resp.headers.items()}
            return {"status_code": resp.status_code, "headers": headers}
    except Exception as exc:  # noqa: BLE001
        logger.warning("[EvidenceGen] Header capture failed for %s: %s", url, exc)
        return {"error": str(exc)}


async def build_evidence_package(
    takedown_id: int,
    include_screenshot: bool = True,
    include_whois: bool = True,
    include_dns: bool = True,
    include_archive: bool = True,
    narrative: str = "",
) -> dict:
    """
    Assemble a UDRP evidence package for *takedown_id*.

    Parameters
    ----------
    takedown_id:
        ID of the TakedownRequest to build evidence for.
    include_screenshot:
        Submit URL to URLScan.io and capture screenshot metadata.
    include_whois:
        Fetch WHOIS registration data.
    include_dns:
        Resolve DNS records (A, MX, NS).
    include_archive:
        Check Wayback Machine availability.
    narrative:
        Claim narrative text to embed in the package.

    Returns
    -------
    dict with fields: takedown_id, target_url, domain, generated_at, components, narrative.
    Suitable for JSON serialisation and PDF rendering.
    """
    from app.database import AsyncSessionLocal
    from app.models import TakedownRequest

    package: dict[str, Any] = {
        "takedown_id": takedown_id,
        "target_url": "",
        "domain": "",
        "generated_at": _utcnow().isoformat(),
        "narrative": narrative,
        "components": {},
    }

    async with AsyncSessionLocal() as db:
        from sqlalchemy import select
        row = (
            await db.execute(
                select(TakedownRequest).where(TakedownRequest.id == takedown_id)
            )
        ).scalar_one_or_none()

        if not row:
            logger.warning("[EvidenceGen] TakedownRequest %s not found", takedown_id)
            return package

        target_url: str = row.target_url or ""
        package["target_url"] = target_url

        # Derive domain from URL
        domain = ""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            domain = parsed.hostname or parsed.path.split("/")[0]
            domain = domain.lstrip("www.").strip()
        except Exception:  # noqa: BLE001
            domain = target_url
        package["domain"] = domain

    if include_screenshot and target_url:
        package["components"]["screenshot"] = await _urlscan_submit(target_url)

    if include_whois and domain:
        package["components"]["whois"] = await _whois_lookup(domain)

    if include_dns and domain:
        package["components"]["dns"] = _dns_resolve(domain)

    if include_archive and target_url:
        package["components"]["archive"] = await _archive_check(target_url)
    if target_url:
        package["components"]["headers"] = await _http_headers_snapshot(target_url)

    return package
