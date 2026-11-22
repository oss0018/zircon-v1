"""User-supplied Ukrainian legal entity snapshot search."""
import asyncio
import json
import re
from datetime import date, datetime, timezone
from itertools import islice
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from sqlalchemy import delete, func, insert, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_admin_user, get_current_user
from app.config import settings
from app.database import get_db
from app.models import (Notification, UkraineCompanyChange, UkraineCompanyWatch,
                        UkraineRegistryApiSettings, UkraineRegistryCompany, UkraineRegistryState, User)
from app.services.ukraine_registry_snapshot import SnapshotError, SnapshotStats, read_company_snapshot

router = APIRouter()
MAX_UPLOAD_BYTES = 2 * 1024**3
BATCH_SIZE = 1000
WATCH_FIELDS = ("name", "short_name", "status", "signatories")


def _registry_api_url(value: str) -> str:
    value = value.strip()
    try:
        url = urlsplit(value)
        host = url.hostname or ""
        if (len(value) > 512 or any(not c.isascii() or c.isspace() or not c.isprintable() for c in value) or
                url.scheme != "https" or not re.fullmatch(
                r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.nais\.gov\.ua",
                host) or
                url.username is not None or url.password is not None or
                url.port not in (None, 443) or url.path not in ("", "/") or
                url.query or url.fragment):
            raise ValueError("Invalid NAIS API URL")
    except ValueError as exc:
        raise HTTPException(422, "Use an HTTPS NAIS API host without a path, credentials or query",
                            headers={"Cache-Control": "no-store"}) from exc
    return value.rstrip("/")


def _registry_api_fernet() -> Fernet:
    try:
        if not settings.encryption_key:
            raise ValueError("Missing encryption key")
        return Fernet(settings.encryption_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise HTTPException(503, "Configure a persistent valid ZIRCON_ENCRYPTION_KEY before saving the NAIS token",
                            headers={"Cache-Control": "no-store"}) from exc


@router.get("/api-settings")
async def registry_api_settings(response: Response, db: AsyncSession = Depends(get_db),
                                _: User = Depends(get_admin_user)):
    response.headers["Cache-Control"] = "no-store"
    saved = await db.get(UkraineRegistryApiSettings, 1)
    return {"base_url": saved.base_url if saved else "https://edr-api.edu.nais.gov.ua",
            "token_configured": bool(saved and saved.token_encrypted), "api_available": False}


@router.put("/api-settings")
async def save_registry_api_settings(request: Request, response: Response,
                                     db: AsyncSession = Depends(get_db), _: User = Depends(get_admin_user)):
    response.headers["Cache-Control"] = "no-store"
    try:
        data = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(422, "Invalid API settings", headers={"Cache-Control": "no-store"}) from exc
    if (not isinstance(data, dict) or set(data) - {"base_url", "token"} or
            not isinstance(data.get("base_url"), str) or
            ("token" in data and not isinstance(data["token"], str))):
        raise HTTPException(422, "Invalid API settings", headers={"Cache-Control": "no-store"})
    base_url = _registry_api_url(data["base_url"])
    saved = await db.get(UkraineRegistryApiSettings, 1)
    if saved is None and "token" not in data:
        raise HTTPException(422, "A NAIS API token is required", headers={"Cache-Control": "no-store"})
    if "token" in data:
        token = data["token"]
        if not token or len(token) > 4096 or any(char.isspace() or not char.isprintable() for char in token):
            raise HTTPException(422, "Token must be nonempty and contain no whitespace or control characters",
                                headers={"Cache-Control": "no-store"})
        encrypted = _registry_api_fernet().encrypt(token.encode("utf-8")).decode("ascii")
    elif saved is not None:
        encrypted = saved.token_encrypted
    else:
        raise HTTPException(422, "A NAIS API token is required", headers={"Cache-Control": "no-store"})
    if saved is None:
        saved = UkraineRegistryApiSettings(id=1, base_url=base_url, token_encrypted=encrypted)
        db.add(saved)
    else:
        saved.base_url = base_url
        saved.token_encrypted = encrypted
    await db.commit()
    return {"base_url": saved.base_url, "token_configured": True, "api_available": False}


@router.delete("/api-settings", status_code=204)
async def delete_registry_api_settings(db: AsyncSession = Depends(get_db), _: User = Depends(get_admin_user)):
    saved = await db.get(UkraineRegistryApiSettings, 1)
    if saved:
        await db.delete(saved)
        await db.commit()


def _company_values(company: UkraineRegistryCompany | None) -> dict | None:
    if company is None:
        return None
    return {
        "name": company.name, "short_name": company.short_name,
        "status": company.status, "signatories": json.loads(company.signatories_json),
    }


async def _watched_values(db: AsyncSession, watches: list[UkraineCompanyWatch]) -> dict:
    codes = {watch.edrpou for watch in watches}
    values = {}
    codes = sorted(codes)
    for start in range(0, len(codes), 500):
        subset = codes[start:start + 500]
        companies = (await db.execute(select(UkraineRegistryCompany).where(
            UkraineRegistryCompany.edrpou.in_(subset)
        ).execution_options(populate_existing=True))).scalars()
        for company in companies:
            if company.edrpou in values:
                values[company.edrpou] = None
            else:
                values[company.edrpou] = _company_values(company)
    return values


async def _locked_state(db: AsyncSession) -> UkraineRegistryState:
    state = await db.get(UkraineRegistryState, 1)
    if state is None:
        state = UkraineRegistryState(id=1, enabled=True)
        db.add(state)
        await db.flush()
    else:
        await db.execute(update(UkraineRegistryState).where(
            UkraineRegistryState.id == 1
        ).values(enabled=UkraineRegistryState.enabled))
        await db.refresh(state)
    return state


@router.get("/status")
async def status(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    state = await db.get(UkraineRegistryState, 1)
    return {
        "enabled": state.enabled if state else True,
        "snapshot_date": state.snapshot_date if state else None,
        "imported_at": state.imported_at if state else None,
        "company_count": state.company_count if state else 0,
        "missing_edrpou_count": state.missing_edrpou_count if state else 0,
        "invalid_edrpou_count": state.invalid_edrpou_count if state else 0,
        "api_available": False,
    }


@router.put("/enabled")
async def set_enabled(enabled: bool, db: AsyncSession = Depends(get_db),
                      _: User = Depends(get_admin_user)):
    try:
        state = await _locked_state(db)
        state.enabled = enabled
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "Registry settings changed concurrently; retry") from exc
    return {"enabled": enabled}


@router.post("/snapshot")
async def upload_snapshot(file: UploadFile = File(...), snapshot_date: date = Form(...),
                          db: AsyncSession = Depends(get_db), _: User = Depends(get_admin_user)):
    if snapshot_date > date.today():
        raise HTTPException(422, "Snapshot date cannot be in the future")
    file.file.seek(0, 2)
    size = file.file.tell()
    file.file.seek(0)
    if not size or size > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "Snapshot must be nonempty and no larger than 2 GiB")
    try:
        state = await _locked_state(db)
        if not state.enabled:
            raise HTTPException(409, "Snapshot source is disabled")
        if state.snapshot_date and snapshot_date.isoformat() <= state.snapshot_date:
            raise HTTPException(409, "Snapshot date must be newer than the current snapshot")
        watches = (await db.execute(select(UkraineCompanyWatch))).scalars().all()
        previous = await _watched_values(db, watches)
        await db.execute(delete(UkraineRegistryCompany))
        stats = SnapshotStats()
        records = read_company_snapshot(file.file, stats)
        count = 0
        while True:
            batch = await asyncio.to_thread(lambda: list(islice(records, BATCH_SIZE)))
            if not batch:
                break
            rows = [{
                "edrpou": row["edrpou"],
                "name": row["name"],
                "short_name": row["short_name"],
                "name_search": (row["name"] + " " + row["short_name"]).casefold(),
                "status": row["status"],
                "signatories_json": json.dumps(row["signatories"], ensure_ascii=False),
            } for row in batch]
            await db.execute(insert(UkraineRegistryCompany), rows)
            count += len(rows)
        if not count:
            raise SnapshotError("Snapshot contains no company records")
        current = await _watched_values(db, watches)
        changed_count = 0
        for watch in watches:
            old, new = previous.get(watch.edrpou), current.get(watch.edrpou)
            if old is None or new is None:
                # Missing or ambiguous records cannot be compared safely.
                continue
            changes = {field: {"before": old[field], "after": new[field]}
                       for field in WATCH_FIELDS if old[field] != new[field]}
            if changes:
                db.add(UkraineCompanyChange(watch_id=watch.id, snapshot_date=snapshot_date.isoformat(),
                                            fields_json=json.dumps(changes, ensure_ascii=False)))
                changed_count += 1
        if changed_count:
            db.add(Notification(type="info", title="Ukrainian company watch update",
                                message="Company snapshot changes were detected. Open Legal & Regulatory to review your watches."))
        state.snapshot_date = snapshot_date.isoformat()
        state.imported_at = datetime.now(timezone.utc)
        state.company_count = count
        state.missing_edrpou_count = stats.missing_edrpou
        state.invalid_edrpou_count = stats.invalid_edrpou
        await db.commit()
        return {"company_count": count, "snapshot_date": state.snapshot_date,
                "missing_edrpou_count": state.missing_edrpou_count,
                "invalid_edrpou_count": state.invalid_edrpou_count}
    except SnapshotError as exc:
        await db.rollback()
        raise HTTPException(422, str(exc)) from exc
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "Concurrent import or invalid snapshot; snapshot was not applied") from exc
    finally:
        await file.close()


@router.get("/companies")
async def search_companies(q: str = Query(..., min_length=2, max_length=255),
                           offset: int = Query(0, ge=0),
                           db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    raw_query = q.strip()
    query = raw_query.casefold()
    if len(query) < 2:
        raise HTTPException(422, "Enter at least 2 characters")
    state = await db.get(UkraineRegistryState, 1)
    if not state or not state.enabled:
        raise HTTPException(503, "Snapshot source is unavailable or disabled")
    if not state.snapshot_date:
        raise HTTPException(503, "No company snapshot has been imported")
    stmt = select(UkraineRegistryCompany).where(
        UkraineRegistryCompany.edrpou == raw_query if len(raw_query) == 8 and raw_query.isascii() and raw_query.isdigit()
        else or_(UkraineRegistryCompany.edrpou == raw_query,
                 UkraineRegistryCompany.name_search.contains(query, autoescape=True))
    ).order_by(UkraineRegistryCompany.edrpou, UkraineRegistryCompany.id).offset(offset).limit(51)
    companies = (await db.execute(stmt)).scalars().all()
    codes = {company.edrpou for company in companies[:50] if company.edrpou}
    counts = dict((await db.execute(
        select(UkraineRegistryCompany.edrpou, func.count()).where(
            UkraineRegistryCompany.edrpou.in_(codes)
        ).group_by(UkraineRegistryCompany.edrpou)
    )).all()) if codes else {}
    return {
        "snapshot_date": state.snapshot_date, "imported_at": state.imported_at,
        "has_more": len(companies) > 50,
        "results": [{
            "id": row.id, "edrpou": row.edrpou, "ambiguous": counts.get(row.edrpou, 0) > 1,
            "watchable": bool(row.edrpou and len(row.edrpou) == 8 and
                              row.edrpou.isascii() and row.edrpou.isdigit() and
                              counts.get(row.edrpou, 0) == 1),
            "name": row.name, "short_name": row.short_name,
            "status": row.status, "signatories": json.loads(row.signatories_json),
        } for row in companies[:50]],
    }


@router.get("/watches")
async def list_watches(db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    watches = (await db.execute(select(UkraineCompanyWatch).where(
        UkraineCompanyWatch.owner_id == user.id
    ).order_by(UkraineCompanyWatch.id.desc()))).scalars().all()
    values = await _watched_values(db, watches)
    return [{"id": watch.id, "edrpou": watch.edrpou, "company": values.get(watch.edrpou),
             "match_status": ("missing" if watch.edrpou not in values else
                              "ambiguous" if values[watch.edrpou] is None else "available")}
            for watch in watches]


@router.post("/watches/{edrpou}", status_code=201)
async def create_watch(edrpou: str, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    if len(edrpou) != 8 or not edrpou.isascii() or not edrpou.isdigit():
        raise HTTPException(422, "EDRPOU must be eight digits")
    try:
        state = await _locked_state(db)
        if not state.enabled or not state.snapshot_date:
            raise HTTPException(503, "Snapshot source is unavailable or disabled")
        matches = (await db.execute(select(func.count()).select_from(UkraineRegistryCompany).where(
            UkraineRegistryCompany.edrpou == edrpou
        ))).scalar_one()
        if not matches:
            raise HTTPException(404, "Company not found in the current snapshot")
        if matches > 1:
            raise HTTPException(409, "Multiple records have this EDRPOU; monitoring is unavailable")
        watch = UkraineCompanyWatch(owner_id=user.id, edrpou=edrpou)
        db.add(watch)
        await db.commit()
        await db.refresh(watch)
        return {"id": watch.id, "edrpou": watch.edrpou}
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "This company watch already exists") from exc


@router.get("/watches/{watch_id}/changes")
async def watch_changes(watch_id: int, offset: int = Query(0, ge=0), db: AsyncSession = Depends(get_db),
                        user: User = Depends(get_current_user)):
    watch = (await db.execute(select(UkraineCompanyWatch).where(
        UkraineCompanyWatch.id == watch_id, UkraineCompanyWatch.owner_id == user.id
    ))).scalar_one_or_none()
    if watch is None:
        raise HTTPException(404, "Watch not found")
    changes = (await db.execute(select(UkraineCompanyChange).where(
        UkraineCompanyChange.watch_id == watch.id
    ).order_by(UkraineCompanyChange.id.desc()).offset(offset).limit(51))).scalars().all()
    return {"has_more": len(changes) > 50, "results": [
        {"snapshot_date": change.snapshot_date, "detected_at": change.created_at,
         "fields": json.loads(change.fields_json)} for change in changes[:50]
    ]}


@router.delete("/watches/{watch_id}", status_code=204)
async def delete_watch(watch_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    await _locked_state(db)
    watch = (await db.execute(select(UkraineCompanyWatch).where(
        UkraineCompanyWatch.id == watch_id, UkraineCompanyWatch.owner_id == user.id
    ))).scalar_one_or_none()
    if watch is None:
        raise HTTPException(404, "Watch not found")
    await db.delete(watch)
    await db.commit()
