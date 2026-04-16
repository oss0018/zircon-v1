from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.auth import get_current_user
from app.database import get_db
from app.models import User, WatchlistItem, Integration
from app.schemas import WatchlistItemCreate, WatchlistItemOut
from app.services.crypto import decrypt
from app.services.osint import get_client

router = APIRouter()


@router.get("/", response_model=List[WatchlistItemOut])
async def list_watchlist(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(WatchlistItem).order_by(WatchlistItem.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=WatchlistItemOut)
async def create_watchlist_item(data: WatchlistItemCreate, db: AsyncSession = Depends(get_db),
                                 _: User = Depends(get_current_user)):
    item = WatchlistItem(**data.model_dump())
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return item


@router.delete("/{item_id}")
async def delete_watchlist_item(item_id: int, db: AsyncSession = Depends(get_db),
                                 _: User = Depends(get_current_user)):
    result = await db.execute(select(WatchlistItem).where(WatchlistItem.id == item_id))
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(item)
    await db.commit()
    return {"ok": True}


@router.post("/{item_id}/check")
async def check_watchlist_item(item_id: int, db: AsyncSession = Depends(get_db),
                                _: User = Depends(get_current_user)):
    """Run OSINT checks for a watchlist item across configured integrations."""
    result = await db.execute(select(WatchlistItem).where(WatchlistItem.id == item_id))
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Not found")

    import json
    integrations_list = json.loads(item.integrations_json or "[]")
    results = []

    for svc in integrations_list:
        res = await db.execute(select(Integration).where(Integration.service_type == svc))
        integration = res.scalar_one_or_none()
        api_key = ""
        if integration:
            api_key = decrypt(integration.api_key_encrypted)
        client = get_client(svc, api_key)
        if client:
            try:
                osint_result = await client.search(item.value, item.type)
                results.append({"source": svc, "data": osint_result})
            except Exception as e:
                results.append({"source": svc, "data": {"error": str(e)}})

    return {"item_id": item_id, "value": item.value, "type": item.type, "results": results}
