"""Confirmed-transaction monitoring through public blockchain explorers."""
import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Notification, WalletWatch, WalletWatchTransaction

logger = logging.getLogger(__name__)
USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
MAX_PAGES = 100
TXID = re.compile(r"^[0-9a-f]{64}$")


class WalletSourceError(Exception):
    pass


def normalize_address(chain: str, address: str) -> str:
    address = address.strip()
    base58 = r"[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]"
    if chain == "btc":
        if address.upper().startswith("BC1"):
            if address != address.lower() and address != address.upper():
                raise ValueError("Invalid BTC address")
            address = address.lower()
        valid = re.fullmatch(rf"(?:[13]{base58}{{25,34}}|bc1[ac-hj-np-z02-9]{{11,87}})", address)
    elif chain == "usdt_trc20":
        valid = re.fullmatch(rf"T{base58}{{33}}", address)
    else:
        raise ValueError("Unsupported chain")
    if not valid:
        raise ValueError("Invalid address format for selected chain")
    return address


async def _history(chain: str, address: str) -> list[dict]:
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
        async def fetch(cursor):
            try:
                if chain == "btc":
                    url = f"https://blockstream.info/api/address/{address}/txs/chain"
                    if cursor:
                        url += f"/{cursor}"
                    response = await client.get(url)
                else:
                    params = {"only_confirmed": "true", "contract_address": USDT_CONTRACT, "limit": 200}
                    if cursor:
                        params["fingerprint"] = cursor
                    response = await client.get(
                        f"https://api.trongrid.io/v1/accounts/{address}/transactions/trc20",
                        params=params,
                    )
                response.raise_for_status()
                data = response.json()
            except httpx.HTTPStatusError as exc:
                raise WalletSourceError(f"Provider returned HTTP {exc.response.status_code}") from exc
            except (httpx.RequestError, ValueError) as exc:
                raise WalletSourceError("Provider unavailable or returned invalid JSON") from exc
            if chain == "btc":
                if not isinstance(data, list) or len(data) > 25:
                    raise WalletSourceError("Blockstream returned an invalid transaction page")
                if any(not isinstance(item, dict) or not isinstance(item.get("status"), dict)
                       or item["status"].get("confirmed") is not True
                       for item in data):
                    raise WalletSourceError("Blockstream returned an invalid confirmed transaction")
                records = data
                ids = [item.get("txid") for item in records]
                next_cursor = ids[-1] if len(ids) == 25 else None
            else:
                if not isinstance(data, dict) or data.get("success") is not True or not isinstance(data.get("data"), list) or not isinstance(data.get("meta"), dict):
                    raise WalletSourceError("TronGrid returned an invalid transaction page")
                records = data["data"]
                if any(not isinstance(item, dict) for item in records):
                    raise WalletSourceError("TronGrid returned an invalid transaction")
                if any(not isinstance(item.get("token_info"), dict)
                       or item["token_info"].get("address") != USDT_CONTRACT
                       or not isinstance(item.get("type"), str)
                       for item in records):
                    raise WalletSourceError("TronGrid returned an unexpected token record")
                transfers = [item for item in records if item["type"] == "Transfer"]
                if any(address not in (item.get("from"), item.get("to")) for item in transfers):
                    raise WalletSourceError("TronGrid returned a transfer for another account")
                ids = [item.get("transaction_id") for item in transfers]
                records = transfers
                next_cursor = data["meta"].get("fingerprint")
                if next_cursor is not None and (not isinstance(next_cursor, str) or not next_cursor or len(next_cursor) > 2048):
                    raise WalletSourceError("TronGrid returned an invalid pagination cursor")
                if len(data["data"]) >= 200 and not next_cursor:
                    raise WalletSourceError("TronGrid returned a full page without a pagination cursor")
            if any(not isinstance(txid, str) or not TXID.fullmatch(txid) for txid in ids):
                raise WalletSourceError("Provider returned an invalid transaction ID")
            return records, next_cursor

        history = []
        cursors = set()
        cursor = None
        first = None
        for _ in range(MAX_PAGES):
            records, next_cursor = await fetch(cursor)
            if first is None:
                first = (records, next_cursor)
            history.extend(records)
            if not next_cursor:
                if cursor is not None and await fetch(None) != first:
                    raise WalletSourceError("Provider results changed during pagination")
                return history
            if next_cursor in cursors:
                raise WalletSourceError("Provider returned a repeated pagination cursor")
            cursors.add(next_cursor)
            cursor = next_cursor
        raise WalletSourceError(f"History exceeds the {MAX_PAGES}-page limit")


async def _snapshot(chain: str, address: str) -> set[str]:
    records = await _history(chain, address)
    key = "txid" if chain == "btc" else "transaction_id"
    return {record[key] for record in records}


async def run_watch(db: AsyncSession, watch_id: int) -> bool:
    now = datetime.now(timezone.utc)
    token = uuid4().hex
    result = await db.execute(update(WalletWatch).where(
        WalletWatch.id == watch_id,
        or_(WalletWatch.lease_until.is_(None), WalletWatch.lease_until < now),
        or_(WalletWatch.last_attempt.is_(None), WalletWatch.last_attempt <= now - timedelta(days=1)),
    ).values(last_attempt=now, last_status="running", last_error=None,
             lease_until=now + timedelta(minutes=15), lease_token=token)
      .execution_options(synchronize_session=False))
    await db.commit()
    if not result.rowcount:
        return False
    watch = (await db.execute(select(WalletWatch).where(
        WalletWatch.id == watch_id, WalletWatch.lease_token == token,
    ))).scalar_one_or_none()
    if watch is None:
        await db.rollback()
        return False
    chain, address = watch.chain, watch.address
    await db.rollback()
    try:
        ids = await asyncio.wait_for(_snapshot(chain, address), timeout=600)
        locked = await db.execute(update(WalletWatch).where(
            WalletWatch.id == watch_id, WalletWatch.lease_token == token,
            WalletWatch.lease_until > datetime.now(timezone.utc),
        ).values(last_status="running").execution_options(synchronize_session=False))
        if not locked.rowcount:
            await db.rollback()
            return False
        watch = (await db.execute(select(WalletWatch).where(
            WalletWatch.id == watch_id, WalletWatch.lease_token == token,
        ).execution_options(populate_existing=True))).scalar_one()
        existing = set((await db.execute(select(WalletWatchTransaction.transaction_id).where(
            WalletWatchTransaction.watch_id == watch_id,
        ))).scalars())
        new = ids - existing
        db.add_all([WalletWatchTransaction(watch_id=watch_id, transaction_id=txid,
                    discovered_after_baseline=watch.baseline_complete) for txid in new])
        if watch.baseline_complete and new:
            db.add(Notification(type="info", title="Wallet watch update",
                                message="A wallet watch has new transactions. Open Infrastructure Intelligence to review your watches."))
        watch.baseline_complete = True
        watch.last_success = datetime.now(timezone.utc)
        watch.last_status = "success"
        watch.last_error = None
        watch.lease_until = None
        watch.lease_token = None
        await db.commit()
    except (WalletSourceError, TimeoutError) as exc:
        await db.rollback()
        message = str(exc) if isinstance(exc, WalletSourceError) else "Wallet check timed out"
        await _fail_claim(db, watch_id, token, message)
    except Exception:
        await db.rollback()
        logger.exception("Wallet watch %s failed", watch_id)
        await _fail_claim(db, watch_id, token, "Wallet check failed unexpectedly; see server logs")
    return True


async def _fail_claim(db: AsyncSession, watch_id: int, token: str, message: str) -> None:
    await db.execute(update(WalletWatch).where(
        WalletWatch.id == watch_id, WalletWatch.lease_token == token,
    ).values(last_status="failed", last_error=message, lease_until=None, lease_token=None)
      .execution_options(synchronize_session=False))
    await db.commit()


async def run_due_watches(db: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    await db.execute(update(WalletWatch).where(
        WalletWatch.last_status == "running", WalletWatch.lease_until < now,
    ).values(last_status="failed", last_error="Wallet check was interrupted", lease_until=None, lease_token=None)
      .execution_options(synchronize_session=False))
    await db.commit()
    ids = (await db.execute(select(WalletWatch.id).where(
        or_(WalletWatch.last_attempt.is_(None), WalletWatch.last_attempt <= now - timedelta(days=1)),
        or_(WalletWatch.lease_until.is_(None), WalletWatch.lease_until < now),
    ))).scalars().all()
    for watch_id in ids:
        await run_watch(db, watch_id)
