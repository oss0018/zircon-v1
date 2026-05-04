"""
Threat Intelligence (TI) API — part of the CSINT section.

Endpoints:
  GET  /integrations           — list active TI integrations
  POST /lookup                 — perform IoC lookup across active TI integrations
  POST /search                 — perform IoC lookup with normalized results
  GET  /history                — recent IoC lookup history
  GET  /history/{id}           — detail for a history entry
  GET  /stats                  — per-integration lookup counts for last 7 days
  GET  /free-sources           — list free (no-key) TI sources available
"""
import json
from datetime import datetime, timezone, timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import Integration, TILookupHistory, User
from app.services.crypto import decrypt
from app.services.osint import get_client
from app.services.threat_intel.normalizer import normalize
from app.utils.sanitize import sanitize_search_query

router = APIRouter()

# Service types that belong to the Threat Intelligence category
TI_SERVICE_TYPES = {
    "shodan", "virustotal", "abuseipdb", "alienvault",
    "urlscan", "urlhaus", "phishtank", "censys", "securitytrails",
    "hibp", "intelx",
    # Free / no-key connectors
    "malwarebazaar", "threatfox",
}

# Free sources that work without an API key (always available)
TI_FREE_SOURCES = {"urlhaus", "phishtank", "malwarebazaar", "threatfox"}

# Human-readable labels and external URLs for each TI service
TI_SERVICE_META = {
    "shodan": {"name": "Shodan", "url": "https://shodan.io"},
    "virustotal": {"name": "VirusTotal", "url": "https://virustotal.com"},
    "abuseipdb": {"name": "AbuseIPDB", "url": "https://abuseipdb.com"},
    "alienvault": {"name": "AlienVault OTX", "url": "https://otx.alienvault.com"},
    "urlscan": {"name": "urlscan.io", "url": "https://urlscan.io"},
    "urlhaus": {"name": "URLhaus (abuse.ch)", "url": "https://urlhaus.abuse.ch"},
    "phishtank": {"name": "PhishTank", "url": "https://phishtank.org"},
    "censys": {"name": "Censys", "url": "https://censys.io"},
    "securitytrails": {"name": "SecurityTrails", "url": "https://securitytrails.com"},
    "hibp": {"name": "Have I Been Pwned", "url": "https://haveibeenpwned.com"},
    "intelx": {"name": "Intelligence X", "url": "https://intelx.io"},
    "malwarebazaar": {"name": "MalwareBazaar (abuse.ch)", "url": "https://bazaar.abuse.ch"},
    "threatfox": {"name": "ThreatFox (abuse.ch)", "url": "https://threatfox.abuse.ch"},
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@router.get("/integrations")
async def list_ti_integrations(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return all configured (active) TI integrations."""
    result = await db.execute(
        select(Integration).where(
            Integration.service_type.in_(TI_SERVICE_TYPES),
            Integration.is_active.is_(True),
        )
    )
    integrations = result.scalars().all()
    configured = [
        {
            "id": i.id,
            "service_type": i.service_type,
            "name": TI_SERVICE_META.get(i.service_type, {}).get("name", i.name),
            "is_active": i.is_active,
            "url": TI_SERVICE_META.get(i.service_type, {}).get("url", ""),
            "free": i.service_type in TI_FREE_SOURCES,
        }
        for i in integrations
    ]
    # Always include free sources (no key required) if not already in the list
    configured_types = {i["service_type"] for i in configured}
    for svc in sorted(TI_FREE_SOURCES):
        if svc not in configured_types:
            meta = TI_SERVICE_META.get(svc, {})
            configured.append({
                "id": None,
                "service_type": svc,
                "name": meta.get("name", svc),
                "is_active": True,
                "url": meta.get("url", ""),
                "free": True,
            })
    return configured


@router.get("/free-sources")
async def list_free_sources(_: User = Depends(get_current_user)):
    """Return list of free (no API key required) TI sources."""
    return [
        {
            "service_type": svc,
            "name": TI_SERVICE_META.get(svc, {}).get("name", svc),
            "url": TI_SERVICE_META.get(svc, {}).get("url", ""),
        }
        for svc in sorted(TI_FREE_SOURCES)
    ]


@router.post("/lookup")
async def ti_lookup(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Perform IoC lookup across all active TI integrations (including free sources).
    Returns raw per-source results.

    Body: {"ioc": "...", "ioc_type": "ip|domain|hash|url|email", "sources": [...optional...]}
    """
    import asyncio

    raw_ioc = str(body.get("ioc", "")).strip()
    ioc = sanitize_search_query(raw_ioc)
    if not ioc:
        raise HTTPException(status_code=400, detail="ioc must not be empty")

    ioc_type = str(body.get("ioc_type", "general")).strip().lower()
    if ioc_type not in ("ip", "domain", "hash", "url", "email", "general"):
        ioc_type = "general"

    # Determine which sources to query
    requested_sources = body.get("sources")
    if requested_sources and isinstance(requested_sources, list):
        requested_sources = {str(s) for s in requested_sources} & TI_SERVICE_TYPES
    else:
        requested_sources = None  # means: all active TI integrations + free sources

    # Fetch active TI integrations from DB
    q = select(Integration).where(
        Integration.service_type.in_(TI_SERVICE_TYPES),
        Integration.is_active.is_(True),
    )
    result = await db.execute(q)
    integrations = result.scalars().all()

    # Build source list: configured integrations + free sources
    # Free sources are always included unless specific sources are requested
    configured_types = {i.service_type for i in integrations}
    sources_to_query: list[tuple[str, str]] = []  # (service_type, api_key)

    for i in integrations:
        if requested_sources is None or i.service_type in requested_sources:
            api_key = decrypt(i.api_key_encrypted) if i.api_key_encrypted else ""
            sources_to_query.append((i.service_type, api_key))

    for svc in sorted(TI_FREE_SOURCES):
        if svc not in configured_types:
            if requested_sources is None or svc in requested_sources:
                sources_to_query.append((svc, ""))

    if not sources_to_query:
        raise HTTPException(status_code=400, detail="No active TI integrations configured")

    async def _query(svc_type: str, api_key: str) -> tuple[str, dict]:
        client = get_client(svc_type, api_key)
        if not client:
            return svc_type, {"error": "Client not available"}
        try:
            data = await client.search(ioc, ioc_type)
            return svc_type, data
        except Exception as exc:
            return svc_type, {"error": str(exc)}

    pairs = await asyncio.gather(*[_query(svc, key) for svc, key in sources_to_query])
    results = {svc: data for svc, data in pairs}

    # Persist to history
    sources_used = list(results.keys())
    history_entry = TILookupHistory(
        ioc_value=ioc,
        ioc_type=ioc_type,
        sources_json=json.dumps(sources_used),
        results_json=json.dumps(results),
        user_id=current_user.id,
    )
    db.add(history_entry)
    await db.commit()
    await db.refresh(history_entry)

    # Build response with metadata for each service
    response_results = []
    for svc, data in results.items():
        meta = TI_SERVICE_META.get(svc, {})
        response_results.append({
            "source": svc,
            "name": meta.get("name", svc),
            "url": meta.get("url", ""),
            "data": data,
            "error": data.get("error") if isinstance(data, dict) else None,
        })

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "history_id": history_entry.id,
        "results": response_results,
    }


@router.post("/search")
async def ti_search(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Perform IoC lookup and return NORMALIZED, human-readable results.
    This is the primary endpoint for the Threat Intelligence dashboard.

    Body: {
        "query": "...",         (alias: "ioc")
        "query_type": "...",    (alias: "ioc_type") ip|domain|hash|url|email|general
        "sources": [...]        optional list of source service_type values
    }
    Response: normalized result + per-source raw data + history_id
    """
    import asyncio

    raw_ioc = str(body.get("query", body.get("ioc", ""))).strip()
    ioc = sanitize_search_query(raw_ioc)
    if not ioc:
        raise HTTPException(status_code=400, detail="query must not be empty")

    ioc_type = str(body.get("query_type", body.get("ioc_type", "general"))).strip().lower()
    if ioc_type not in ("ip", "domain", "hash", "url", "email", "general"):
        ioc_type = "general"

    # Determine which sources to query
    requested_sources = body.get("sources")
    if requested_sources and isinstance(requested_sources, list):
        requested_sources = {str(s) for s in requested_sources} & TI_SERVICE_TYPES
    else:
        requested_sources = None

    # Fetch active TI integrations from DB
    q = select(Integration).where(
        Integration.service_type.in_(TI_SERVICE_TYPES),
        Integration.is_active.is_(True),
    )
    db_result = await db.execute(q)
    integrations = db_result.scalars().all()

    configured_types = {i.service_type for i in integrations}
    sources_to_query: list[tuple[str, str]] = []

    for i in integrations:
        if requested_sources is None or i.service_type in requested_sources:
            api_key = decrypt(i.api_key_encrypted) if i.api_key_encrypted else ""
            sources_to_query.append((i.service_type, api_key))

    for svc in sorted(TI_FREE_SOURCES):
        if svc not in configured_types:
            if requested_sources is None or svc in requested_sources:
                sources_to_query.append((svc, ""))

    if not sources_to_query:
        raise HTTPException(status_code=400, detail="No active TI integrations configured")

    async def _query(svc_type: str, api_key: str) -> tuple[str, dict]:
        client = get_client(svc_type, api_key)
        if not client:
            return svc_type, {"error": "Client not available"}
        try:
            data = await client.search(ioc, ioc_type)
            return svc_type, data
        except Exception as exc:
            return svc_type, {"error": str(exc)}

    pairs = await asyncio.gather(*[_query(svc, key) for svc, key in sources_to_query])
    raw_results = {svc: data for svc, data in pairs}

    # Normalize results
    normalized = normalize(ioc, ioc_type, raw_results)

    # Persist to history
    sources_used = list(raw_results.keys())
    history_entry = TILookupHistory(
        ioc_value=ioc,
        ioc_type=ioc_type,
        sources_json=json.dumps(sources_used),
        results_json=json.dumps(raw_results),
        user_id=current_user.id,
    )
    db.add(history_entry)
    await db.commit()
    await db.refresh(history_entry)

    # Build per-source result list for the UI
    per_source = []
    for svc, data in raw_results.items():
        meta = TI_SERVICE_META.get(svc, {})
        per_source.append({
            "source": svc,
            "name": meta.get("name", svc),
            "url": meta.get("url", ""),
            "data": data,
            "error": data.get("error") if isinstance(data, dict) else None,
            "free": svc in TI_FREE_SOURCES,
        })

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "history_id": history_entry.id,
        "queried_at": _utcnow().isoformat(),
        "normalized": normalized,
        "per_source": per_source,
    }


@router.get("/history")
async def ti_history(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return recent IoC lookup history (most recent first)."""
    result = await db.execute(
        select(TILookupHistory)
        .order_by(TILookupHistory.created_at.desc())
        .limit(min(limit, 200))
    )
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "ioc_value": r.ioc_value,
            "ioc_type": r.ioc_type,
            "sources": json.loads(r.sources_json or "[]"),
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.get("/history/{history_id}")
async def ti_history_detail(
    history_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return full results for a specific history entry, with normalized view."""
    result = await db.execute(
        select(TILookupHistory).where(TILookupHistory.id == history_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    raw_results = json.loads(row.results_json or "{}")
    normalized = normalize(row.ioc_value, row.ioc_type, raw_results)
    return {
        "id": row.id,
        "ioc_value": row.ioc_value,
        "ioc_type": row.ioc_type,
        "sources": json.loads(row.sources_json or "[]"),
        "results": raw_results,
        "normalized": normalized,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/stats")
async def ti_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Return per-integration lookup counts grouped by day for the last 7 days.
    Also returns total lookups and active integration count.
    """
    since = _utcnow() - timedelta(days=7)
    result = await db.execute(
        select(TILookupHistory).where(TILookupHistory.created_at >= since)
    )
    rows = result.scalars().all()

    # Build a dict: service_type -> {date_str -> count}
    from collections import defaultdict
    per_service: dict = defaultdict(lambda: defaultdict(int))
    for row in rows:
        sources = json.loads(row.sources_json or "[]")
        day = row.created_at.strftime("%Y-%m-%d") if row.created_at else "unknown"
        for svc in sources:
            per_service[svc][day] += 1

    # Build 7-day date range (last 7 days, most recent last)
    days = [(_utcnow() - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(6, -1, -1)]

    service_stats = []
    for svc, day_counts in per_service.items():
        meta = TI_SERVICE_META.get(svc, {})
        service_stats.append({
            "service_type": svc,
            "name": meta.get("name", svc),
            "url": meta.get("url", ""),
            "days": days,
            "counts": [day_counts.get(d, 0) for d in days],
            "total": sum(day_counts.values()),
        })

    # Total lookups in last 7 days
    total_result = await db.execute(
        select(func.count(TILookupHistory.id)).where(TILookupHistory.created_at >= since)
    )
    total_lookups = total_result.scalar() or 0

    # Active integrations count (configured + free sources)
    active_result = await db.execute(
        select(func.count(Integration.id)).where(
            Integration.service_type.in_(TI_SERVICE_TYPES),
            Integration.is_active.is_(True),
        )
    )
    active_configured = active_result.scalar() or 0
    # Free sources are always available
    active_count = active_configured + len(TI_FREE_SOURCES)

    return {
        "total_lookups_7d": total_lookups,
        "active_ti_integrations": active_count,
        "service_stats": service_stats,
        "days": days,
    }
