"""
Threat Intelligence (TI) API — part of the CSINT section.

Endpoints:
  GET  /integrations   — list active TI integrations
  POST /lookup         — perform IoC lookup across active TI integrations
  GET  /history        — recent IoC lookup history
  GET  /stats          — per-integration lookup counts for last 7 days
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
from app.utils.sanitize import sanitize_search_query

router = APIRouter()

# Service types that belong to the Threat Intelligence category
TI_SERVICE_TYPES = {
    "shodan", "virustotal", "abuseipdb", "alienvault",
    "urlscan", "urlhaus", "phishtank", "censys", "securitytrails",
    "hibp", "intelx",
}

# Human-readable labels and external URLs for each TI service
TI_SERVICE_META = {
    "shodan": {"name": "Shodan", "url": "https://shodan.io"},
    "virustotal": {"name": "VirusTotal", "url": "https://virustotal.com"},
    "abuseipdb": {"name": "AbuseIPDB", "url": "https://abuseipdb.com"},
    "alienvault": {"name": "AlienVault OTX", "url": "https://otx.alienvault.com"},
    "urlscan": {"name": "urlscan.io", "url": "https://urlscan.io"},
    "urlhaus": {"name": "URLhaus", "url": "https://urlhaus.abuse.ch"},
    "phishtank": {"name": "PhishTank", "url": "https://phishtank.org"},
    "censys": {"name": "Censys", "url": "https://censys.io"},
    "securitytrails": {"name": "SecurityTrails", "url": "https://securitytrails.com"},
    "hibp": {"name": "Have I Been Pwned", "url": "https://haveibeenpwned.com"},
    "intelx": {"name": "Intelligence X", "url": "https://intelx.io"},
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
    return [
        {
            "id": i.id,
            "service_type": i.service_type,
            "name": i.name,
            "is_active": i.is_active,
            "url": TI_SERVICE_META.get(i.service_type, {}).get("url", ""),
        }
        for i in integrations
    ]


@router.post("/lookup")
async def ti_lookup(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Perform IoC lookup across all active TI integrations.

    Body: {"ioc": "...", "ioc_type": "ip|domain|hash|url|email", "sources": [...optional...]}
    """
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
        requested_sources = None  # means: all active TI integrations

    # Fetch active TI integrations from DB
    q = select(Integration).where(
        Integration.service_type.in_(TI_SERVICE_TYPES),
        Integration.is_active.is_(True),
    )
    result = await db.execute(q)
    integrations = result.scalars().all()

    if not integrations:
        raise HTTPException(status_code=400, detail="No active TI integrations configured")

    # Filter by requested sources if specified
    if requested_sources is not None:
        integrations = [i for i in integrations if i.service_type in requested_sources]

    # Run queries in parallel
    import asyncio

    async def _query(integration: Integration) -> tuple[str, dict]:
        api_key = decrypt(integration.api_key_encrypted) if integration.api_key_encrypted else ""
        client = get_client(integration.service_type, api_key)
        if not client:
            return integration.service_type, {"error": "Client not available"}
        try:
            data = await client.search(ioc, ioc_type)
            return integration.service_type, data
        except Exception as exc:
            return integration.service_type, {"error": str(exc)}

    pairs = await asyncio.gather(*[_query(i) for i in integrations])
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
    """Return full results for a specific history entry."""
    result = await db.execute(
        select(TILookupHistory).where(TILookupHistory.id == history_id)
    )
    row = result.scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="Not found")
    return {
        "id": row.id,
        "ioc_value": row.ioc_value,
        "ioc_type": row.ioc_type,
        "sources": json.loads(row.sources_json or "[]"),
        "results": json.loads(row.results_json or "{}"),
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

    # Build 7-day date range
    days = [(since + timedelta(days=i)).strftime("%Y-%m-%d") for i in range(8)]

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

    # Active integrations count
    active_result = await db.execute(
        select(func.count(Integration.id)).where(
            Integration.service_type.in_(TI_SERVICE_TYPES),
            Integration.is_active.is_(True),
        )
    )
    active_count = active_result.scalar() or 0

    return {
        "total_lookups_7d": total_lookups,
        "active_ti_integrations": active_count,
        "service_stats": service_stats,
        "days": days,
    }
