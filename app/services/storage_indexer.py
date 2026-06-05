"""
Storage indexer — indexes files from external storage sources into Local Index.

Limits (defaults; per-source overrides via StorageSource.max_file_size_mb):
  MAX_FILE_SIZE_MB   = 25
  MAX_FILES_SCANNED  = 100_000
  MAX_FILES_INDEXED  = 10_000
  RUN_TIMEOUT_SEC    = 900   (15 min)
"""
import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models import StorageSource, StorageFileCatalog
from app.services.connectors import get_connector, FileEntry
from app.services.file_parsers import extract_text
from app.services.search_engine import search_engine

logger = logging.getLogger(__name__)

MAX_FILES_SCANNED = 100_000
MAX_FILES_INDEXED = 10_000
RUN_TIMEOUT_SEC = 900  # 15 minutes


@dataclass
class _CatalogUpdate:
    """Carries the result of processing a single file back to the async layer."""
    path: str
    size: int
    mtime: Optional[datetime]
    etag: str
    content_hash: str
    status: str   # indexed | error | skipped
    error: str
    doc_id: str
    doc_filename: str
    doc_text: str
    doc_file_type: str
    doc_project: str


def _doc_id(source_id: int, path: str) -> str:
    """Stable, unique document ID for the Whoosh index."""
    digest = hashlib.sha256(f"{source_id}:{path}".encode()).hexdigest()[:16]
    return f"ext_{source_id}_{digest}"


def _needs_reindex(catalog_entry: StorageFileCatalog, remote: FileEntry) -> bool:
    """Return True when the remote file has changed since last indexing."""
    if catalog_entry.last_indexed_at is None:
        return True
    if catalog_entry.status != "indexed":
        return True
    if remote.etag and catalog_entry.etag and remote.etag != catalog_entry.etag:
        return True
    if remote.size != catalog_entry.size:
        return True
    if remote.mtime and catalog_entry.mtime:
        if remote.mtime > catalog_entry.mtime:
            return True
    return False


def _extract_text_from_bytes(data: bytes, filename: str) -> str:
    """Extract text from raw bytes using existing file_parsers (via tmp file)."""
    import tempfile
    suffix = Path(filename).suffix.lower()
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        text = extract_text(tmp_path) or ""
    except Exception as exc:
        logger.warning("[storage_indexer] extract_text failed for %s: %s", filename, exc)
        text = ""
    finally:
        if tmp_path:
            try:
                Path(tmp_path).unlink(missing_ok=True)
            except Exception:
                pass
    return text


def _sync_index_source(
    source_id: int,
    source_type: str,
    config: dict,
    recursive: bool,
    max_file_size_bytes: int,
    existing_catalog: dict,  # path → StorageFileCatalog-like namedtuple
    start_time: float,
) -> tuple[list[_CatalogUpdate], int, int, int, str]:
    """
    Purely synchronous worker: lists files, downloads, extracts, indexes.
    Returns (catalog_updates, scanned, indexed, errors, error_msg).
    This function runs in a thread pool executor with no running event loop.
    """
    scanned = 0
    indexed = 0
    errors = 0
    error_msg = ""
    updates: list[_CatalogUpdate] = []

    try:
        connector = get_connector(source_type, config)
        file_entries = list(
            connector.list_files(
                path="",
                recursive=recursive,
                max_files=MAX_FILES_SCANNED,
            )
        )
    except Exception as exc:
        logger.error("[storage_indexer] list_files failed for source %d: %s", source_id, exc)
        return [], 0, 0, 1, str(exc)

    for entry in file_entries:
        if time.monotonic() - start_time > RUN_TIMEOUT_SEC:
            logger.warning("[storage_indexer] run timeout reached for source %d", source_id)
            break
        if entry.size > max_file_size_bytes:
            scanned += 1
            continue
        if indexed >= MAX_FILES_INDEXED:
            break

        scanned += 1

        # Check if up to date using in-memory catalog snapshot
        existing = existing_catalog.get(entry.path)
        if existing and not _needs_reindex(existing, entry):
            continue  # up to date

        # Download file
        try:
            data = connector.get_file_bytes(entry.path, max_bytes=max_file_size_bytes)
        except Exception as exc:
            logger.warning("[storage_indexer] download failed %s: %s", entry.path, exc)
            errors += 1
            updates.append(_CatalogUpdate(
                path=entry.path, size=entry.size, mtime=entry.mtime, etag=entry.etag or "",
                content_hash="", status="error", error=str(exc)[:512],
                doc_id="", doc_filename="", doc_text="", doc_file_type="", doc_project="",
            ))
            continue

        # Compute content hash
        content_hash = hashlib.sha256(data).hexdigest()

        # Skip unchanged content
        if existing and existing.content_hash and existing.content_hash == content_hash:
            updates.append(_CatalogUpdate(
                path=entry.path, size=entry.size, mtime=entry.mtime, etag=entry.etag or "",
                content_hash=content_hash, status="indexed", error="",
                doc_id="", doc_filename="", doc_text="", doc_file_type="", doc_project="",
            ))
            continue

        # Extract text
        filename = Path(entry.path).name
        text = _extract_text_from_bytes(data, filename)
        if not text.strip():
            updates.append(_CatalogUpdate(
                path=entry.path, size=entry.size, mtime=entry.mtime, etag=entry.etag or "",
                content_hash=content_hash, status="skipped", error="",
                doc_id="", doc_filename="", doc_text="", doc_file_type="", doc_project="",
            ))
            continue

        # Index into Whoosh
        doc_id = _doc_id(source_id, entry.path)
        file_type = Path(entry.path).suffix.lstrip(".")
        project = f"storage_source_{source_id}"
        try:
            search_engine.index_document(
                doc_id=doc_id,
                filename=filename,
                content=text,
                file_type=file_type,
                project=project,
                path=entry.path,
            )
            updates.append(_CatalogUpdate(
                path=entry.path, size=entry.size, mtime=entry.mtime, etag=entry.etag or "",
                content_hash=content_hash, status="indexed", error="",
                doc_id=doc_id, doc_filename=filename, doc_text=text,
                doc_file_type=file_type, doc_project=project,
            ))
            indexed += 1
        except Exception as exc:
            logger.warning("[storage_indexer] index_document failed %s: %s", entry.path, exc)
            errors += 1
            updates.append(_CatalogUpdate(
                path=entry.path, size=entry.size, mtime=entry.mtime, etag=entry.etag or "",
                content_hash=content_hash, status="error", error=str(exc)[:512],
                doc_id="", doc_filename="", doc_text="", doc_file_type="", doc_project="",
            ))

    return updates, scanned, indexed, errors, error_msg


async def run_source_indexing(source_id: int) -> dict:
    """
    Index (or re-index) all files from the given storage source.

    Returns a summary dict: {scanned, indexed, errors, elapsed_sec, status}.
    """
    start_time = time.monotonic()

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(StorageSource).where(StorageSource.id == source_id))
        source: Optional[StorageSource] = result.scalar_one_or_none()
        if not source or not source.is_enabled:
            return {"scanned": 0, "indexed": 0, "errors": 0, "status": "skipped"}

        # Mark as running
        source.last_run_at = datetime.now(timezone.utc).replace(tzinfo=None)
        source.last_run_status = "running"
        await db.commit()

    scanned = 0
    indexed = 0
    errors = 0
    error_msg = ""

    try:
        # Decrypt and parse config
        from app.services.crypto import decrypt
        from app.services.storage_credential_vault import StorageCredentialVault
        import json
        raw_config = json.loads(decrypt(source.config_encrypted) or "{}")
        try:
            config = StorageCredentialVault().decrypt_credentials(raw_config)
        except ValueError as exc:
            logger.warning("[storage_indexer] credential decrypt failed for source %d: %s", source_id, exc)
            config = raw_config

        max_file_size_bytes = (source.max_file_size_mb or 25) * 1024 * 1024

        # Load existing catalog into memory for the sync worker
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(StorageFileCatalog).where(StorageFileCatalog.source_id == source_id)
            )
            existing_catalog = {e.path: e for e in result.scalars().all()}

        # Run sync listing/indexing in a thread pool executor
        loop = asyncio.get_event_loop()
        updates, scanned, indexed, errors, error_msg = await loop.run_in_executor(
            None,
            _sync_index_source,
            source_id,
            source.source_type,
            config,
            source.recursive,
            max_file_size_bytes,
            existing_catalog,
            start_time,
        )

        # Apply catalog updates back in the async layer (no nested asyncio.run)
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        async with AsyncSessionLocal() as db:
            for upd in updates:
                catalog = existing_catalog.get(upd.path)
                if catalog is None:
                    catalog = StorageFileCatalog(source_id=source_id, path=upd.path)
                    db.add(catalog)
                    # Reload from DB next time via refresh; for now build fresh
                catalog.size = upd.size
                catalog.mtime = upd.mtime
                catalog.etag = upd.etag
                if upd.content_hash:
                    catalog.content_hash = upd.content_hash
                catalog.status = upd.status
                catalog.error = upd.error
                if upd.status == "indexed":
                    catalog.last_indexed_at = now
                catalog.updated_at = now
            await db.commit()

        status = "error" if errors and not indexed else "ok"

    except Exception as exc:
        logger.error("[storage_indexer] Fatal error for source %d: %s", source_id, exc)
        errors += 1
        error_msg = str(exc)[:512]
        status = "error"

    elapsed = time.monotonic() - start_time
    logger.info(
        "[storage_indexer] source %d done in %.1fs — scanned=%d indexed=%d errors=%d",
        source_id, elapsed, scanned, indexed, errors,
    )

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(StorageSource).where(StorageSource.id == source_id))
        src = result.scalar_one_or_none()
        if src:
            src.last_run_at = datetime.now(timezone.utc).replace(tzinfo=None)
            src.last_run_status = status
            src.last_run_scanned = scanned
            src.last_run_indexed = indexed
            src.last_run_errors = errors
            src.last_run_error_msg = error_msg
            await db.commit()

    return {
        "scanned": scanned,
        "indexed": indexed,
        "errors": errors,
        "elapsed_sec": round(elapsed, 1),
        "status": status,
    }
