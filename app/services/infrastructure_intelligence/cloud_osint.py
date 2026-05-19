"""
Cloud OSINT Module — S3 bucket and Azure Blob storage enumeration.
Only sends HTTP HEAD requests to cloud provider public endpoints.
"""
import asyncio
import logging
import re

import httpx

logger = logging.getLogger(__name__)

PREFIXES = [
    "dev", "staging", "prod", "backup", "archive", "test",
    "internal", "data", "files", "assets", "media", "logs",
    "analytics", "export", "db", "private", "public", "cdn", "static",
]

SUFFIXES = [
    "dev", "staging", "prod", "backup", "2023", "2024", "2025",
    "data", "files", "test", "old", "archive", "temp", "storage",
]

_MAX_PERMUTATIONS = 80
_SEMAPHORE_LIMIT = 20


def _extract_brand(target: str, target_type: str) -> str:
    if target_type == "org":
        return re.sub(r"[^a-z0-9-]", "", target.lower())
    # Strip TLD for domain
    parts = target.lower().split(".")
    return parts[0] if parts else target.lower()


class CloudOSINTModule:
    def __init__(self, keys: dict[str, str]):
        self._keys = keys

    def generate_permutations(self, brand: str) -> list[str]:
        brand = re.sub(r"[^a-z0-9-]", "", brand.lower())
        names: list[str] = [brand]
        for p in PREFIXES:
            names.append(f"{brand}-{p}")
            names.append(f"{p}-{brand}")
        for s in SUFFIXES:
            names.append(f"{brand}-{s}")
        # Limit to cap
        return list(dict.fromkeys(names))[:_MAX_PERMUTATIONS]

    async def check_s3_bucket(self, bucket_name: str) -> dict | None:
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False) as c:
                resp = await c.head(url)
                status = resp.status_code
        except Exception:
            return None

        if status == 200:
            return {
                "entity": bucket_name,
                "module": "cloud",
                "finding_type": "bucket_exposed",
                "severity": 5,
                "source": "cloud_enum",
                "data_json": {
                    "provider": "aws_s3",
                    "bucket": bucket_name,
                    "url": url,
                    "http_status": status,
                    "public": True,
                },
            }
        if status == 403:
            return {
                "entity": bucket_name,
                "module": "cloud",
                "finding_type": "bucket_exists",
                "severity": 2,
                "source": "cloud_enum",
                "data_json": {
                    "provider": "aws_s3",
                    "bucket": bucket_name,
                    "url": url,
                    "http_status": status,
                    "public": False,
                },
            }
        return None

    async def check_azure_blob(self, account: str) -> dict | None:
        url = f"https://{account}.blob.core.windows.net"
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False) as c:
                resp = await c.head(url)
                status = resp.status_code
        except Exception:
            return None

        if status == 200:
            return {
                "entity": account,
                "module": "cloud",
                "finding_type": "bucket_exposed",
                "severity": 5,
                "source": "cloud_enum",
                "data_json": {
                    "provider": "azure_blob",
                    "account": account,
                    "url": url,
                    "http_status": status,
                    "public": True,
                },
            }
        if status == 403:
            return {
                "entity": account,
                "module": "cloud",
                "finding_type": "bucket_exists",
                "severity": 2,
                "source": "cloud_enum",
                "data_json": {
                    "provider": "azure_blob",
                    "account": account,
                    "url": url,
                    "http_status": status,
                    "public": False,
                },
            }
        return None

    async def run(self, target: str, target_type: str) -> list[dict]:
        if target_type not in ("domain", "org"):
            return []

        brand = _extract_brand(target, target_type)
        if not brand:
            return []

        permutations = self.generate_permutations(brand)
        semaphore = asyncio.Semaphore(_SEMAPHORE_LIMIT)

        async def _check_s3(name: str) -> dict | None:
            async with semaphore:
                return await self.check_s3_bucket(name)

        async def _check_azure(name: str) -> dict | None:
            async with semaphore:
                return await self.check_azure_blob(name)

        tasks = []
        for name in permutations:
            tasks.append(_check_s3(name))
            tasks.append(_check_azure(name))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if r is not None and not isinstance(r, Exception)]
