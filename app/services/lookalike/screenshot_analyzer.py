"""
Screenshot analysis — Look-alike Domains Phase 2.

Two async helpers:
  - fetch_screenshot_urlscan(fqdn, api_key) — submit to URLScan.io and poll
  - compare_screenshot_phash(url1, url2)    — perceptual hash distance
"""
from __future__ import annotations

import asyncio
import io
from typing import Optional

import httpx

_URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
_URLSCAN_RESULT_URL = "https://urlscan.io/api/v1/result/{uuid}/"
_POLL_ATTEMPTS = 12
_POLL_DELAY = 5  # seconds
_HTTP_TIMEOUT = 10.0


async def fetch_screenshot_urlscan(
    fqdn: str,
    api_key: Optional[str] = None,
) -> dict:
    """
    Submit *fqdn* to URLScan.io, poll for completion up to 12 times (5 s each),
    and return a dict with screenshot_url, urlscan_uuid, urlscan_score,
    page_title_from_scan.

    Returns an empty dict if no api_key is provided or any error occurs.
    """
    if not api_key:
        return {}

    try:
        headers = {
            "API-Key": api_key,
            "Content-Type": "application/json",
        }
        payload = {"url": f"https://{fqdn}", "visibility": "public"}

        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            submit_resp = await client.post(
                _URLSCAN_SUBMIT_URL,
                headers=headers,
                json=payload,
            )
            if submit_resp.status_code not in (200, 201):
                return {}

            submit_data = submit_resp.json()
            uuid = submit_data.get("uuid")
            if not uuid:
                return {}

            # Poll for result
            result_url = _URLSCAN_RESULT_URL.format(uuid=uuid)
            for _ in range(_POLL_ATTEMPTS):
                await asyncio.sleep(_POLL_DELAY)
                try:
                    result_resp = await client.get(result_url)
                    if result_resp.status_code == 200:
                        result_data = result_resp.json()
                        screenshot_url = result_data.get("task", {}).get("screenshotURL") or None
                        score = (
                            result_data.get("verdicts", {})
                            .get("overall", {})
                            .get("score")
                        )
                        page_title = (
                            result_data.get("page", {}).get("title") or None
                        )
                        return {
                            "screenshot_url": screenshot_url,
                            "urlscan_uuid": uuid,
                            "urlscan_score": float(score) if score is not None else None,
                            "page_title_from_scan": page_title,
                        }
                except Exception:
                    continue
    except Exception:
        pass

    return {}


async def compare_screenshot_phash(url1: str, url2: str) -> dict:
    """
    Download images from *url1* and *url2* and compute perceptual hash
    (pHash) distance.

    Returns dict with keys: phash_distance, visual_similarity_pct.
    Values are None if imagehash / PIL are not installed or download fails.
    """
    null = {"phash_distance": None, "visual_similarity_pct": None}

    try:
        import imagehash  # type: ignore
        from PIL import Image  # type: ignore
    except ImportError:
        return null

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            r1, r2 = await asyncio.gather(
                client.get(url1),
                client.get(url2),
                return_exceptions=True,
            )
            if isinstance(r1, Exception) or isinstance(r2, Exception):
                return null
            if r1.status_code != 200 or r2.status_code != 200:
                return null

            img1 = Image.open(io.BytesIO(r1.content))
            img2 = Image.open(io.BytesIO(r2.content))

            h1 = imagehash.phash(img1)
            h2 = imagehash.phash(img2)

            distance = int(h1 - h2)
            # pHash distance is 0–64; convert to similarity percentage
            similarity_pct = round(max(0.0, (64 - distance) / 64.0 * 100), 1)

            return {
                "phash_distance": distance,
                "visual_similarity_pct": similarity_pct,
            }
    except Exception:
        return null
