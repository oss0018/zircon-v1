"""Owner-scoped confirmed wallet transaction watches."""
import re
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import User, WalletWatch, WalletWatchTransaction

router = APIRouter()


class WalletWatchCreate(BaseModel):
    chain: Literal["btc", "usdt_trc20"]
    address: str = Field(min_length=1, max_length=100)
    label: str = Field(min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_address(self):
        self.address = self.address.strip()
        self.label = self.label.strip()
        if not self.label:
            raise ValueError("Label must not be blank")
        base58 = r"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]"
        if self.chain == "btc":
            if self.address.upper().startswith("BC1"):
                if self.address != self.address.lower() and self.address != self.address.upper():
                    raise ValueError("Invalid BTC address")
                self.address = self.address.lower()
            valid = re.fullmatch(rf"(?:[13]{base58}{{25,34}}|bc1[ac-hj-np-z02-9]{{11,87}})", self.address)
        else:
            valid = re.fullmatch(rf"T{base58}{{33}}", self.address)
        if not valid:
            raise ValueError("Invalid address format for selected chain")
        return self


def _output(watch: WalletWatch) -> dict:
    return {
        "id": watch.id, "chain": watch.chain, "address": watch.address, "label": watch.label,
        "last_attempt": watch.last_attempt, "last_success": watch.last_success,
        "last_status": watch.last_status, "last_error": watch.last_error,
        "baseline_complete": watch.baseline_complete,
    }


@router.get("/watches")
async def list_watches(response: Response, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    watches = (await db.execute(select(WalletWatch).where(WalletWatch.owner_id == user.id)
                                .order_by(WalletWatch.created_at.desc()))).scalars().all()
    return [_output(watch) for watch in watches]


@router.post("/watches", status_code=201)
async def create_watch(request: WalletWatchCreate, response: Response,
                       db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    watch = WalletWatch(owner_id=user.id, **request.model_dump())
    db.add(watch)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(status_code=409, detail="This watch already exists") from exc
    await db.refresh(watch)
    return _output(watch)


@router.get("/watches/{watch_id}/changes")
async def changes(watch_id: int, response: Response, offset: int = Query(0, ge=0),
                  db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user)):
    response.headers["Cache-Control"] = "no-store"
    watch = (await db.execute(select(WalletWatch).where(
        WalletWatch.id == watch_id, WalletWatch.owner_id == user.id,
    ))).scalar_one_or_none()
    if watch is None:
        raise HTTPException(status_code=404, detail="Watch not found")
    transactions = (await db.execute(select(WalletWatchTransaction).where(
        WalletWatchTransaction.watch_id == watch.id,
        WalletWatchTransaction.discovered_after_baseline.is_(True),
    ).order_by(WalletWatchTransaction.first_seen.desc(), WalletWatchTransaction.id.desc())
      .offset(offset).limit(50))).scalars().all()
    prefix = "https://blockstream.info/tx/" if watch.chain == "btc" else "https://tronscan.org/#/transaction/"
    return [{"transaction_id": tx.transaction_id, "detected_at": tx.first_seen,
             "source_url": prefix + tx.transaction_id} for tx in transactions]


@router.delete("/watches/{watch_id}", status_code=204)
async def delete_watch(watch_id: int, db: AsyncSession = Depends(get_db),
                       user: User = Depends(get_current_user)):
    watch = (await db.execute(select(WalletWatch).where(
        WalletWatch.id == watch_id, WalletWatch.owner_id == user.id,
    ))).scalar_one_or_none()
    if watch is None:
        raise HTTPException(status_code=404, detail="Watch not found")
    await db.delete(watch)
    await db.commit()
