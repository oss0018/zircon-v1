"""
Zircon FRT — Brand Protection API router.

Existing endpoints (unchanged):
  GET  /                         — list brands
  POST /                         — create brand
  GET  /{brand_id}               — get brand
  DELETE /{brand_id}             — delete brand
  POST /{brand_id}/scan          — typosquat scan (basic, synchronous)
  POST /{brand_id}/scan-from-file — upload .txt, check similarity
  GET  /{brand_id}/alerts        — alerts for brand
  GET  /alerts/all               — all alerts
  PATCH /alerts/{alert_id}       — update alert status
  POST /resolve-domains          — resolve IPs for a list of domains

New endpoints (added in this version):
  POST /generate-check           — generate typosquats + async DNS/HTTP check (SSE)
  POST /check-from-file          — upload .txt (250k domains), async check (SSE)
  POST /{target_id}/recheck-alive — re-check all alive domains for a brand
  GET  /results/{target_id}/export — export results as CSV or JSON
"""

import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import Brand, BrandAlert, User
from app.schemas import BrandAlertOut, BrandCreate, BrandOut

router = APIRouter()


# ── Internal helpers ───────────────────────────────────────────────────────────

def _levenshtein(s1: str, s2: str) -> int:
    """Compute the Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr_row = [i + 1]
        for j, c2 in enumerate(s2):
            curr_row.append(min(prev_row[j + 1] + 1, curr_row[j] + 1, prev_row[j] + (c1 != c2)))
        prev_row = curr_row
    return prev_row[-1]


def _similarity(a: str, b: str) -> float:
    """Return a 0-1 similarity score based on Levenshtein distance."""
    if not a and not b:
        return 1.0
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 1.0
    return 1.0 - _levenshtein(a.lower(), b.lower()) / max_len


def _extract_base_domain(url: str) -> str:
    """Strip protocol and path from a URL/domain string, remove leading www."""
    if "://" in url:
        url = url.split("://", 1)[1].split("/")[0]
    return re.sub(r"^www\.", "", url).strip()


def _generate_typosquats(domain: str) -> List[str]:
    """Generate common typosquat variants (basic sync version for legacy scan endpoint)."""
    candidates = set()
    parts = domain.split(".")
    name = parts[0] if parts else domain
    tld = "." + ".".join(parts[1:]) if len(parts) > 1 else ".com"

    for i in range(len(name)):
        candidates.add(name[:i] + name[i + 1:] + tld)
    for i in range(len(name) - 1):
        t = list(name)
        t[i], t[i + 1] = t[i + 1], t[i]
        candidates.add("".join(t) + tld)
    for alt_tld in [".net", ".org", ".info", ".co", ".io", ".biz"]:
        candidates.add(name + alt_tld)
    for i in range(1, len(name)):
        candidates.add(name[:i] + "-" + name[i:] + tld)
    for i in range(len(name)):
        candidates.add(name[:i] + name[i] + name[i:] + tld)

    return list(candidates - {domain})


async def _save_check_result(
    db: AsyncSession,
    brand_id: int,
    base_domain: str,
    result: dict,
) -> None:
    """Upsert a domain check result into the brand_alerts table."""
    domain = result["domain"]
    sim_score = _similarity(base_domain, domain)

    existing = await db.execute(
        select(BrandAlert).where(
            BrandAlert.brand_id == brand_id,
            BrandAlert.similar_domain == domain,
        )
    )
    alert = existing.scalar_one_or_none()

    checked_at_val: Optional[datetime] = None
    raw_ts = result.get("checked_at")
    if raw_ts:
        try:
            checked_at_val = datetime.fromisoformat(raw_ts)
        except Exception:
            checked_at_val = datetime.now(timezone.utc)

    if alert:
        alert.ip = result.get("ip")
        alert.http_status = result.get("http_status")
        alert.ssl_valid = result.get("ssl_valid")
        alert.page_title = result.get("page_title")
        alert.similarity_pct = result.get("similarity_pct")
        alert.alive = result.get("alive", False)
        alert.checked_at = checked_at_val
        details = json.loads(alert.details_json or "{}")
        details.update({"ip": result.get("ip"), "alive": result.get("alive", False)})
        alert.details_json = json.dumps(details)
    else:
        alert = BrandAlert(
            brand_id=brand_id,
            similar_domain=domain,
            similarity_score=sim_score,
            source="async_checker",
            details_json=json.dumps({
                "base": base_domain,
                "candidate": domain,
                "ip": result.get("ip"),
                "alive": result.get("alive", False),
            }),
            ip=result.get("ip"),
            http_status=result.get("http_status"),
            ssl_valid=result.get("ssl_valid"),
            page_title=result.get("page_title"),
            similarity_pct=result.get("similarity_pct"),
            alive=result.get("alive", False),
            checked_at=checked_at_val,
        )
        db.add(alert)

    await db.commit()


# ── CRUD endpoints ─────────────────────────────────────────────────────────────

@router.get("/", response_model=List[BrandOut])
async def list_brands(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Brand).order_by(Brand.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=BrandOut)
async def create_brand(data: BrandCreate, db: AsyncSession = Depends(get_db),
                       _: User = Depends(get_current_user)):
    brand = Brand(**data.model_dump())
    db.add(brand)
    await db.commit()
    await db.refresh(brand)
    return brand


@router.post("/resolve-domains")
async def resolve_domains(body: dict, _: User = Depends(get_current_user)):
    """Resolve IPs for a list of domains. Body: {"domains": ["example.com", ...]}"""
    import socket
    domains = body.get("domains", [])
    results = []
    for domain in domains[:100]:
        try:
            ip = socket.gethostbyname(domain.strip())
        except Exception:
            ip = None
        results.append({"domain": domain, "ip": ip})
    return {"results": results}


# ── New bulk-check endpoints (must come before /{brand_id} dynamic routes) ────

@router.post("/generate-check")
async def generate_and_check(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate typosquatting variants for a domain and check them asynchronously.

    Body: {"domain": "example.com", "target_id": 1, "limit": 1000}
    Returns SSE stream (text/event-stream) of check results.
    """
    from app.services.domain_checker import check_domains_async, generate_typosquats

    raw_domain = body.get("domain", "").strip()
    if not raw_domain:
        raise HTTPException(status_code=400, detail="domain is required")
    base_domain = _extract_base_domain(raw_domain)
    target_id: Optional[int] = body.get("target_id")
    limit = min(int(body.get("limit", 1000)), 10000)

    brand_name = base_domain
    if target_id:
        res = await db.execute(select(Brand).where(Brand.id == target_id))
        brand = res.scalar_one_or_none()
        if brand:
            brand_name = brand.name

    domains = generate_typosquats(base_domain, limit)
    total = len(domains)

    async def _sse_stream():
        found_alive = 0
        checked = 0
        async for result in check_domains_async(domains, brand_name):
            checked += 1
            if result.get("alive"):
                found_alive += 1
                if target_id:
                    try:
                        await _save_check_result(db, target_id, base_domain, result)
                    except Exception:
                        pass
            payload = {**result, "checked": checked, "total": total, "found_alive": found_alive}
            yield f"data: {json.dumps(payload)}\n\n"
        yield f"event: done\ndata: {json.dumps({'total': total, 'found_alive': found_alive})}\n\n"

    return StreamingResponse(_sse_stream(), media_type="text/event-stream")


@router.post("/check-from-file")
async def check_from_file(
    file: UploadFile = File(...),
    target_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Upload a .txt file with up to 250,000 domains (one per line).
    Results are streamed back as SSE events.
    """
    from app.services.domain_checker import BATCH_SIZE, check_domains_async

    content = await file.read()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Cannot decode file")

    domains = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "://" in line:
            line = line.split("://", 1)[1].split("/")[0]
        line = line.strip().strip(",").strip(";")
        if line:
            domains.append(line)
        if len(domains) >= 250_000:
            break

    brand_name = ""
    base_domain = ""
    if target_id:
        res = await db.execute(select(Brand).where(Brand.id == target_id))
        brand = res.scalar_one_or_none()
        if brand:
            brand_name = brand.name
            base_domain = _extract_base_domain(brand.url)

    total = len(domains)

    async def _sse_stream():
        found_alive = 0
        checked = 0
        for batch_start in range(0, total, BATCH_SIZE):
            batch = domains[batch_start: batch_start + BATCH_SIZE]
            async for result in check_domains_async(batch, brand_name):
                checked += 1
                if result.get("alive"):
                    found_alive += 1
                    if target_id and base_domain:
                        try:
                            await _save_check_result(db, target_id, base_domain, result)
                        except Exception:
                            pass
                payload = {**result, "checked": checked, "total": total, "found_alive": found_alive}
                yield f"data: {json.dumps(payload)}\n\n"
        yield f"event: done\ndata: {json.dumps({'total': total, 'found_alive': found_alive})}\n\n"

    return StreamingResponse(_sse_stream(), media_type="text/event-stream")


@router.get("/alerts/all", response_model=List[BrandAlertOut])
async def get_all_alerts(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(BrandAlert).order_by(BrandAlert.created_at.desc()))
    return result.scalars().all()


@router.patch("/alerts/{alert_id}")
async def update_alert_status(alert_id: int, body: dict, db: AsyncSession = Depends(get_db),
                               _: User = Depends(get_current_user)):
    result = await db.execute(select(BrandAlert).where(BrandAlert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Not found")
    status = body.get("status", "reviewed")
    if status in ("new", "reviewed", "dismissed"):
        alert.status = status
    await db.commit()
    return {"ok": True}


# ── Dynamic /{brand_id} routes (must come after static-path routes) ────────────

@router.get("/{brand_id}", response_model=BrandOut)
async def get_brand(brand_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Brand).where(Brand.id == brand_id))
    brand = result.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Not found")
    return brand


@router.delete("/{brand_id}")
async def delete_brand(brand_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Brand).where(Brand.id == brand_id))
    brand = result.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(brand)
    await db.commit()
    return {"ok": True}


@router.post("/{brand_id}/scan")
async def scan_brand(brand_id: int, body: dict = {}, db: AsyncSession = Depends(get_db),
                     _: User = Depends(get_current_user)):
    """Scan for domains similar to the brand domain (basic synchronous typosquat)."""
    result = await db.execute(select(Brand).where(Brand.id == brand_id))
    brand = result.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Not found")

    base_domain = _extract_base_domain(brand.url)
    candidates = _generate_typosquats(base_domain)
    alerts_created = 0

    for candidate in candidates:
        score = _similarity(base_domain, candidate)
        if score >= brand.similarity_threshold and candidate != base_domain:
            existing = await db.execute(
                select(BrandAlert).where(
                    BrandAlert.brand_id == brand_id,
                    BrandAlert.similar_domain == candidate
                )
            )
            if not existing.scalar_one_or_none():
                alert = BrandAlert(
                    brand_id=brand_id,
                    similar_domain=candidate,
                    similarity_score=score,
                    source="typosquat_generator",
                    details_json=json.dumps({"base": base_domain, "candidate": candidate}),
                )
                db.add(alert)
                alerts_created += 1

    await db.commit()
    return {"ok": True, "candidates_checked": len(candidates), "alerts_created": alerts_created}


@router.post("/{brand_id}/scan-from-file")
async def scan_brand_from_file(
    brand_id: int,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Upload a .txt file with one domain per line.
    For each domain: compute similarity to brand, resolve IP, save as BrandAlert.
    """
    import socket as _socket
    result = await db.execute(select(Brand).where(Brand.id == brand_id))
    brand = result.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Not found")

    content = await file.read()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Cannot read file")

    base_domain = _extract_base_domain(brand.url)

    domains = []
    for line in text.splitlines():
        line = line.strip().strip(",").strip(";")
        if not line or line.startswith("#"):
            continue
        if "://" in line:
            line = line.split("://", 1)[1].split("/")[0]
        line = line.strip()
        if line:
            domains.append(line)

    alerts_created = 0
    results = []

    for domain in domains:
        score = _similarity(base_domain, domain)

        ip_address = None
        try:
            ip_address = _socket.gethostbyname(domain)
        except Exception:
            ip_address = None

        details = {
            "base": base_domain,
            "candidate": domain,
            "ip": ip_address,
            "source_file": file.filename,
        }

        existing = await db.execute(
            select(BrandAlert).where(
                BrandAlert.brand_id == brand_id,
                BrandAlert.similar_domain == domain,
            )
        )
        existing_alert = existing.scalar_one_or_none()

        if existing_alert:
            if ip_address:
                try:
                    d = json.loads(existing_alert.details_json or "{}")
                    d["ip"] = ip_address
                    existing_alert.details_json = json.dumps(d)
                    existing_alert.ip = ip_address
                except Exception:
                    pass
        else:
            alert = BrandAlert(
                brand_id=brand_id,
                similar_domain=domain,
                similarity_score=score,
                source="file_import",
                details_json=json.dumps(details),
                ip=ip_address,
            )
            db.add(alert)
            alerts_created += 1

        results.append({
            "domain": domain,
            "similarity": round(score, 3),
            "ip": ip_address,
            "new": existing_alert is None,
        })

    await db.commit()
    return {
        "ok": True,
        "total_domains": len(domains),
        "alerts_created": alerts_created,
        "results": results,
    }


@router.post("/{target_id}/recheck-alive")
async def recheck_alive(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Re-check all previously found alive domains for a brand target.
    Returns SSE stream of updated check results.
    """
    from app.services.domain_checker import check_domain

    res = await db.execute(select(Brand).where(Brand.id == target_id))
    brand = res.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")

    base_domain = _extract_base_domain(brand.url)

    alerts_res = await db.execute(
        select(BrandAlert)
        .where(BrandAlert.brand_id == target_id, BrandAlert.alive.is_(True))
        .order_by(BrandAlert.created_at.desc())
    )
    alive_alerts = alerts_res.scalars().all()

    if not alive_alerts:
        all_res = await db.execute(
            select(BrandAlert)
            .where(BrandAlert.brand_id == target_id)
            .order_by(BrandAlert.created_at.desc())
        )
        alive_alerts = all_res.scalars().all()

    domains = [a.similar_domain for a in alive_alerts]
    total = len(domains)

    async def _sse_stream():
        import aiohttp
        found_alive = 0
        checked = 0
        connector = aiohttp.TCPConnector(ssl=False, limit=50)
        async with aiohttp.ClientSession(connector=connector) as session:
            for domain in domains:
                try:
                    result = await check_domain(domain, session, brand.name)
                except Exception:
                    result = {
                        "domain": domain, "alive": False, "ip": None,
                        "http_status": None, "ssl_valid": None,
                        "page_title": None, "similarity_pct": None,
                        "checked_at": datetime.now(timezone.utc).isoformat(),
                    }
                checked += 1
                if result.get("alive"):
                    found_alive += 1
                try:
                    await _save_check_result(db, target_id, base_domain, result)
                except Exception:
                    pass
                payload = {**result, "checked": checked, "total": total, "found_alive": found_alive}
                yield f"data: {json.dumps(payload)}\n\n"
        yield f"event: done\ndata: {json.dumps({'total': total, 'found_alive': found_alive})}\n\n"

    return StreamingResponse(_sse_stream(), media_type="text/event-stream")


@router.get("/results/{target_id}/export")
async def export_results(
    target_id: int,
    format: str = Query("csv", pattern="^(csv|json)$"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Export brand protection check results for a target brand.
    Query: format=csv|json
    """
    res = await db.execute(select(Brand).where(Brand.id == target_id))
    brand = res.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")

    alerts_res = await db.execute(
        select(BrandAlert)
        .where(BrandAlert.brand_id == target_id)
        .order_by(BrandAlert.created_at.desc())
    )
    alerts = alerts_res.scalars().all()

    if format == "json":
        rows = [
            {
                "domain": a.similar_domain,
                "alive": a.alive,
                "ip": a.ip,
                "http_status": a.http_status,
                "ssl_valid": a.ssl_valid,
                "page_title": a.page_title,
                "similarity_pct": a.similarity_pct,
                "checked_at": a.checked_at.isoformat() if a.checked_at else None,
            }
            for a in alerts
        ]
        content = json.dumps(rows, ensure_ascii=False, indent=2)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="brand_{target_id}_results.json"'},
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["domain", "alive", "ip", "http_status", "ssl_valid",
                     "page_title", "similarity_pct", "checked_at"])
    for a in alerts:
        writer.writerow([
            a.similar_domain,
            a.alive if a.alive is not None else "",
            a.ip or "",
            a.http_status if a.http_status is not None else "",
            a.ssl_valid if a.ssl_valid is not None else "",
            a.page_title or "",
            a.similarity_pct if a.similarity_pct is not None else "",
            a.checked_at.isoformat() if a.checked_at else "",
        ])
    csv_content = output.getvalue()
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="brand_{target_id}_results.csv"'},
    )


@router.get("/{brand_id}/alerts", response_model=List[BrandAlertOut])
async def get_brand_alerts(brand_id: int, db: AsyncSession = Depends(get_db),
                            _: User = Depends(get_current_user)):
    result = await db.execute(
        select(BrandAlert).where(BrandAlert.brand_id == brand_id).order_by(BrandAlert.created_at.desc())
    )
    return result.scalars().all()
