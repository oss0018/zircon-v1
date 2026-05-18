"""
Logo & Content Misuse API
=========================
Endpoints:
  POST   /brands/{brand_id}/logo            — upload brand logo
  DELETE /brands/{brand_id}/logo            — delete brand logo
  GET    /brands/{brand_id}/logo            — serve brand logo
  POST   /brands/{brand_id}/search          — RSS-based misuse search
  GET    /cases                             — list cases (filters: brand_id, status, match_type, q)
  GET    /cases/export                      — export as CSV or JSON (must be before /cases/{id})
  GET    /cases/{case_id}                   — get single case
  POST   /cases                             — create case manually
  PATCH  /cases/{case_id}                   — update case
  DELETE /cases/{case_id}                   — delete case
  POST   /cases/{case_id}/request-takedown  — set status=takedown_requested
  POST   /cases/{case_id}/dismiss           — set status=dismissed
  GET    /stats                             — counts grouped by status / match_type / brand
"""

import csv
import io
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import Brand, LogoMisuseCase, Notification, User
from app.schemas import LogoMisuseCaseCreate, LogoMisuseCaseOut, LogoMisuseCaseUpdate, LogoMisuseStats
from app.utils.sanitize import sanitize_string

logger = logging.getLogger(__name__)

router = APIRouter()

LOGOS_DIR = Path("data/logos")
ALLOWED_MIME = {"image/png", "image/jpeg", "image/webp", "image/gif", "image/svg+xml"}
MAX_LOGO_SIZE = 5 * 1024 * 1024  # 5 MB

_SAFE_FILENAME = re.compile(r"[^a-zA-Z0-9._\-]")


def _safe_filename(name: str) -> str:
    return _SAFE_FILENAME.sub("_", name)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Logo upload / serve / delete ──────────────────────────────────────────────

@router.post("/brands/{brand_id}/logo")
async def upload_logo(
    brand_id: int,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    res = await db.execute(select(Brand).where(Brand.id == brand_id))
    brand = res.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")

    if file.content_type not in ALLOWED_MIME:
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {file.content_type}")

    data = await file.read()
    if len(data) > MAX_LOGO_SIZE:
        raise HTTPException(status_code=400, detail="File too large (max 5 MB)")

    safe_name = _safe_filename(file.filename or "logo")
    dest = LOGOS_DIR / f"{brand_id}_{safe_name}"

    # Remove old logo if different path
    if brand.logo_path and brand.logo_path != str(dest):
        old = Path(brand.logo_path)
        if old.exists():
            try:
                old.unlink()
            except OSError:
                pass

    LOGOS_DIR.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)

    brand.logo_path = str(dest)
    await db.commit()

    return {
        "ok": True,
        "logo_path": str(dest),
        "url": f"/api/v1/logo-misuse/brands/{brand_id}/logo",
    }


@router.delete("/brands/{brand_id}/logo")
async def delete_logo(
    brand_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    res = await db.execute(select(Brand).where(Brand.id == brand_id))
    brand = res.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")

    if brand.logo_path:
        p = Path(brand.logo_path)
        if p.exists():
            try:
                p.unlink()
            except OSError:
                pass
        brand.logo_path = ""
        await db.commit()

    return {"ok": True}


@router.get("/brands/{brand_id}/logo")
async def get_logo(
    brand_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    res = await db.execute(select(Brand).where(Brand.id == brand_id))
    brand = res.scalar_one_or_none()
    if not brand or not brand.logo_path:
        raise HTTPException(status_code=404, detail="No logo uploaded")

    p = Path(brand.logo_path)
    if not p.exists():
        raise HTTPException(status_code=404, detail="Logo file not found")

    return FileResponse(str(p))


# ── RSS-based misuse search ────────────────────────────────────────────────────

def _parse_rss_xml(xml_text: str) -> list[dict]:
    """Fallback RSS parser using stdlib xml.etree.ElementTree."""
    import xml.etree.ElementTree as ET
    items = []
    try:
        root = ET.fromstring(xml_text)
        for item in root.iter("item"):
            title = item.findtext("title") or ""
            link = item.findtext("link") or ""
            items.append({"title": title, "link": link})
    except ET.ParseError:
        pass
    return items


async def _fetch_rss(url: str) -> list[dict]:
    """Fetch and parse an RSS feed. Returns list of {title, link} dicts."""
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": "ZirconFRT/1.0"})
            if resp.status_code != 200:
                return []
            content = resp.text
    except Exception as exc:
        logger.warning("RSS fetch failed for %s: %s", url, exc)
        return []

    try:
        import feedparser
        feed = feedparser.parse(content)
        return [{"title": e.get("title", ""), "link": e.get("link", "")} for e in feed.entries]
    except ImportError:
        return _parse_rss_xml(content)


@router.post("/brands/{brand_id}/search")
async def search_brand_misuse(
    brand_id: int,
    body: dict,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    res = await db.execute(select(Brand).where(Brand.id == brand_id))
    brand = res.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Brand not found")

    query = sanitize_string(str(body.get("query", brand.name)).strip(), max_length=200)
    max_results: int = min(int(body.get("max_results", 20)), 100)

    # Determine brand's own domain to skip
    own_domain = ""
    if brand.url:
        try:
            own_domain = urlparse(brand.url).netloc.lower()
        except Exception:
            pass

    rss_feeds = [
        f"https://news.google.com/rss/search?q={query}+logo",
        f"https://www.bing.com/news/search?q={query}+logo&format=rss",
    ]

    all_items: list[dict] = []
    for feed_url in rss_feeds:
        items = await _fetch_rss(feed_url)
        all_items.extend(items)

    brand_name_lower = brand.name.lower()
    created_cases: list[LogoMisuseCaseOut] = []
    seen_urls: set[str] = set()

    for item in all_items[:max_results * 2]:
        link = (item.get("link") or "").strip()
        title = (item.get("title") or "").strip()
        if not link:
            continue

        # Skip own domain
        try:
            item_domain = urlparse(link).netloc.lower()
        except Exception:
            item_domain = ""
        if own_domain and item_domain == own_domain:
            continue

        if link in seen_urls:
            continue
        seen_urls.add(link)

        # Confidence scoring
        url_lower = link.lower()
        if brand_name_lower in url_lower:
            confidence = 0.6
        elif brand_name_lower in title.lower():
            confidence = 0.3
        else:
            confidence = 0.4

        # Deduplicate by source_url + brand_id
        existing = await db.execute(
            select(LogoMisuseCase).where(
                LogoMisuseCase.brand_id == brand_id,
                LogoMisuseCase.source_url == link,
            )
        )
        if existing.scalar_one_or_none():
            continue

        case = LogoMisuseCase(
            brand_id=brand_id,
            source_url=link,
            page_title=sanitize_string(title, max_length=512),
            match_type="logo",
            confidence=confidence,
            detection_source="rss_search",
        )
        db.add(case)
        await db.flush()

        # Create notification
        notif = Notification(
            type="warning",
            title=f"Logo misuse detected: {brand.name}",
            message=f"Potential misuse found at {link}",
        )
        db.add(notif)

        created_cases.append(LogoMisuseCaseOut.model_validate(case))

        if len(created_cases) >= max_results:
            break

    await db.commit()

    return {"found": len(created_cases), "cases": [c.model_dump() for c in created_cases]}


# ── Cases CRUD ────────────────────────────────────────────────────────────────

@router.get("/cases", response_model=List[LogoMisuseCaseOut])
async def list_cases(
    brand_id: Optional[int] = Query(None),
    status: Optional[str] = Query(None),
    match_type: Optional[str] = Query(None),
    q: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    stmt = select(LogoMisuseCase).order_by(LogoMisuseCase.created_at.desc())
    if brand_id is not None:
        stmt = stmt.where(LogoMisuseCase.brand_id == brand_id)
    if status:
        stmt = stmt.where(LogoMisuseCase.status == status)
    if match_type:
        stmt = stmt.where(LogoMisuseCase.match_type == match_type)
    if q:
        q_like = f"%{q}%"
        stmt = stmt.where(
            LogoMisuseCase.source_url.ilike(q_like) | LogoMisuseCase.page_title.ilike(q_like)
        )
    stmt = stmt.offset(offset).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


# ── Export — MUST be registered before /cases/{case_id} ──────────────────────

@router.get("/cases/export")
async def export_cases(
    format: str = Query("csv", pattern="^(csv|json)$"),
    brand_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    stmt = select(LogoMisuseCase).order_by(LogoMisuseCase.created_at.desc())
    if brand_id is not None:
        stmt = stmt.where(LogoMisuseCase.brand_id == brand_id)
    result = await db.execute(stmt)
    cases = result.scalars().all()

    if format == "json":
        rows = [
            {
                "id": c.id,
                "brand_id": c.brand_id,
                "source_url": c.source_url,
                "page_title": c.page_title,
                "match_type": c.match_type,
                "confidence": c.confidence,
                "status": c.status,
                "detection_source": c.detection_source,
                "created_at": c.created_at.isoformat() if c.created_at else "",
            }
            for c in cases
        ]
        return StreamingResponse(
            io.BytesIO(json.dumps(rows, ensure_ascii=False).encode()),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=logo_misuse_cases.json"},
        )

    # CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "brand_id", "source_url", "page_title", "match_type",
                     "confidence", "status", "detection_source", "created_at"])
    for c in cases:
        writer.writerow([
            c.id, c.brand_id, c.source_url, c.page_title, c.match_type,
            c.confidence, c.status, c.detection_source,
            c.created_at.isoformat() if c.created_at else "",
        ])
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode()),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=logo_misuse_cases.csv"},
    )


@router.get("/cases/{case_id}", response_model=LogoMisuseCaseOut)
async def get_case(
    case_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(LogoMisuseCase).where(LogoMisuseCase.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@router.post("/cases", response_model=LogoMisuseCaseOut, status_code=201)
async def create_case(
    data: LogoMisuseCaseCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    res = await db.execute(select(Brand).where(Brand.id == data.brand_id))
    if not res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Brand not found")

    case = LogoMisuseCase(**data.model_dump())
    db.add(case)
    await db.commit()
    await db.refresh(case)
    return case


@router.patch("/cases/{case_id}", response_model=LogoMisuseCaseOut)
async def update_case(
    case_id: int,
    data: LogoMisuseCaseUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(LogoMisuseCase).where(LogoMisuseCase.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    update_data = data.model_dump(exclude_none=True)
    for field, value in update_data.items():
        setattr(case, field, value)
    await db.commit()
    await db.refresh(case)
    return case


@router.delete("/cases/{case_id}")
async def delete_case(
    case_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(LogoMisuseCase).where(LogoMisuseCase.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    await db.delete(case)
    await db.commit()
    return {"ok": True}


@router.post("/cases/{case_id}/request-takedown")
async def request_takedown(
    case_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(LogoMisuseCase).where(LogoMisuseCase.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case.status = "takedown_requested"
    case.reported_at = _utcnow()
    await db.commit()
    return {"ok": True}


@router.post("/cases/{case_id}/dismiss")
async def dismiss_case(
    case_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(LogoMisuseCase).where(LogoMisuseCase.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    case.status = "dismissed"
    case.resolved_at = _utcnow()
    await db.commit()
    return {"ok": True}


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get("/stats", response_model=LogoMisuseStats)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    total_res = await db.execute(select(func.count()).select_from(LogoMisuseCase))
    total = total_res.scalar() or 0

    status_res = await db.execute(
        select(LogoMisuseCase.status, func.count()).group_by(LogoMisuseCase.status)
    )
    by_status = {row[0]: row[1] for row in status_res.all()}

    match_res = await db.execute(
        select(LogoMisuseCase.match_type, func.count()).group_by(LogoMisuseCase.match_type)
    )
    by_match_type = {row[0]: row[1] for row in match_res.all()}

    brand_res = await db.execute(
        select(LogoMisuseCase.brand_id, func.count()).group_by(LogoMisuseCase.brand_id)
    )
    by_brand = {str(row[0]): row[1] for row in brand_res.all()}

    return LogoMisuseStats(total=total, by_status=by_status, by_match_type=by_match_type, by_brand=by_brand)
