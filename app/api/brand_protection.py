import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.auth import get_current_user
from app.database import get_db
from app.models import User, Brand, BrandAlert
from app.schemas import BrandCreate, BrandOut, BrandAlertOut

router = APIRouter()


def _levenshtein(s1: str, s2: str) -> int:
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
    if not a and not b:
        return 1.0
    max_len = max(len(a), len(b))
    if max_len == 0:
        return 1.0
    return 1.0 - _levenshtein(a.lower(), b.lower()) / max_len


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
    for domain in domains[:100]:  # limit to 100
        try:
            ip = socket.gethostbyname(domain.strip())
        except Exception:
            ip = None
        results.append({"domain": domain, "ip": ip})
    return {"results": results}


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
    """Scan for domains similar to the brand domain."""
    result = await db.execute(select(Brand).where(Brand.id == brand_id))
    brand = result.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Not found")

    import re
    # Extract base domain from URL
    base_domain = brand.url
    if "://" in base_domain:
        base_domain = base_domain.split("://", 1)[1].split("/")[0]
    base_domain = re.sub(r"^www\.", "", base_domain)

    # Generate typosquat candidates
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
    import socket, re
    result = await db.execute(select(Brand).where(Brand.id == brand_id))
    brand = result.scalar_one_or_none()
    if not brand:
        raise HTTPException(status_code=404, detail="Not found")

    content = await file.read()
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        raise HTTPException(status_code=400, detail="Cannot read file")

    # Extract base domain from brand URL
    base_domain = brand.url
    if "://" in base_domain:
        base_domain = base_domain.split("://", 1)[1].split("/")[0]
    base_domain = re.sub(r"^www\.", "", base_domain).strip()

    domains = []
    for line in text.splitlines():
        line = line.strip().strip(",").strip(";")
        if not line or line.startswith("#"):
            continue
        # Strip protocol if present
        if "://" in line:
            line = line.split("://", 1)[1].split("/")[0]
        line = line.strip()
        if line:
            domains.append(line)

    alerts_created = 0
    results = []

    for domain in domains:
        score = _similarity(base_domain, domain)

        # Resolve IP
        ip_address = None
        try:
            ip_address = socket.gethostbyname(domain)
        except Exception:
            ip_address = None

        details = {
            "base": base_domain,
            "candidate": domain,
            "ip": ip_address,
            "source_file": file.filename,
        }

        # Check if alert already exists
        existing = await db.execute(
            select(BrandAlert).where(
                BrandAlert.brand_id == brand_id,
                BrandAlert.similar_domain == domain,
            )
        )
        existing_alert = existing.scalar_one_or_none()

        if existing_alert:
            # Update IP info if resolved
            if ip_address:
                try:
                    d = json.loads(existing_alert.details_json or "{}")
                    d["ip"] = ip_address
                    existing_alert.details_json = json.dumps(d)
                except Exception:
                    pass
        else:
            alert = BrandAlert(
                brand_id=brand_id,
                similar_domain=domain,
                similarity_score=score,
                source="file_import",
                details_json=json.dumps(details),
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


def _generate_typosquats(domain: str) -> List[str]:
    """Generate common typosquat variants."""
    candidates = set()
    parts = domain.split(".")
    name = parts[0] if parts else domain
    tld = "." + ".".join(parts[1:]) if len(parts) > 1 else ".com"

    # Character omission
    for i in range(len(name)):
        candidates.add(name[:i] + name[i+1:] + tld)
    # Character transposition
    for i in range(len(name) - 1):
        t = list(name)
        t[i], t[i+1] = t[i+1], t[i]
        candidates.add("".join(t) + tld)
    # Common TLD variations
    for alt_tld in [".net", ".org", ".info", ".co", ".io", ".biz"]:
        candidates.add(name + alt_tld)
    # Hyphen insertion
    for i in range(1, len(name)):
        candidates.add(name[:i] + "-" + name[i:] + tld)
    # Double character
    for i in range(len(name)):
        candidates.add(name[:i] + name[i] + name[i:] + tld)

    return list(candidates - {domain})


@router.get("/{brand_id}/alerts", response_model=List[BrandAlertOut])
async def get_brand_alerts(brand_id: int, db: AsyncSession = Depends(get_db),
                            _: User = Depends(get_current_user)):
    result = await db.execute(
        select(BrandAlert).where(BrandAlert.brand_id == brand_id).order_by(BrandAlert.created_at.desc())
    )
    return result.scalars().all()


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
