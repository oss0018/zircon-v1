from __future__ import annotations

import io
import logging
import zipfile
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


def _default_feed_date() -> date:
    return (datetime.now(timezone.utc) - timedelta(days=1)).date()


def _normalize_domains(lines: list[str]) -> list[str]:
    cleaned: list[str] = []
    for line in lines:
        value = line.strip().lower()
        if not value or value.startswith("#"):
            continue
        if value.startswith("*."):
            value = value[2:]
        cleaned.append(value)
    return list(dict.fromkeys(cleaned))


async def fetch_nrd_domains(date: Optional[date] = None, feed_source: str = "whoisds") -> list[str]:
    target_date = date or _default_feed_date()
    source = (feed_source or "whoisds").strip().lower()

    try:
        if source == "local":
            local_path = Path(__file__).resolve().parents[3] / "data" / "nrd_feed.txt"
            if not local_path.exists():
                return []
            lines = local_path.read_text(encoding="utf-8").splitlines()
            return _normalize_domains(lines)

        if source != "whoisds":
            return []

        url = (
            "https://whoisds.com/whois-database/newly-registered-domains/"
            f"{target_date.isoformat()}.zip/nrd"
        )
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.get(url)
            resp.raise_for_status()

        with zipfile.ZipFile(io.BytesIO(resp.content)) as archive:
            names = archive.namelist()
            if not names:
                return []
            with archive.open(names[0]) as f:
                lines = f.read().decode("utf-8", errors="ignore").splitlines()
        return _normalize_domains(lines)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to fetch NRD feed (%s): %s", source, exc)
        return []
