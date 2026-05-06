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
import io
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import AsyncSessionLocal
from app.models import StorageSource, StorageFileCatalog
from app.services.connectors import get_connector, FileEntry
from app.services.file_parsers import extract_text, MAX_INDEX_BYTES
from app.services.search_engine import search_engine

logger = logging.getLogger(__name__)

MAX_FILES_SCANNED = 100_000
MAX_FILES_INDEXED = 10_000
RUN_TIMEOUT_SEC = 900  # 15 minutes


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
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        text = extract_text(tmp_path) or ""
    except Exception as exc:
        logger.warning("[storage_indexer] extract_text failed for %s: %s", filename, exc)
        text = ""
    finally:
        try:
            Path(tmp_path).unlink(missing_ok=True)
        except Exception:
            pass
    return text


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

    max_file_size_bytes = (source.max_file_size_mb or 25) * 1024 * 1024

    try:
        # Decrypt and parse config
        from app.services.crypto import decrypt
        import json
        config = json.loads(decrypt(source.config_encrypted) or "{}")

        connector = get_connector(source.source_type, config)

        # Run listing + indexing in an executor (connectors are sync)
        loop = asyncio.get_event_loop()

        def _do_index() -> tuple[int, int, int, str]:
            nonlocal scanned, indexed, errors, error_msg
            _scanned = 0
            _indexed = 0
            _errors = 0
            _error_msg = ""

            try:
                file_entries = list(
                    connector.list_files(
                        path="",
                        recursive=source.recursive,
                        max_files=MAX_FILES_SCANNED,
                    )
                )
            except Exception as exc:
                logger.error("[storage_indexer] list_files failed for source %d: %s", source_id, exc)
                return 0, 0, 1, str(exc)

            for entry in file_entries:
                if time.monotonic() - start_time > RUN_TIMEOUT_SEC:
                    logger.warning("[storage_indexer] run timeout reached for source %d", source_id)
                    break
                if entry.size > max_file_size_bytes:
                    _scanned += 1
                    continue
                if _indexed >= MAX_FILES_INDEXED:
                    break

                _scanned += 1

                # Check catalog (synchronous DB call via new session)
                import asyncio as _asyncio
                catalog = None
                try:
                    catalog = _asyncio.run(_get_catalog_entry(source_id, entry.path))
                except Exception:
                    pass  # proceed without catalog info

                if catalog and not _needs_reindex(catalog, entry):
                    continue  # up to date

                # Download file
                try:
                    data = connector.get_file_bytes(entry.path, max_bytes=max_file_size_bytes)
                except Exception as exc:
                    logger.warning("[storage_indexer] download failed %s: %s", entry.path, exc)
                    _errors += 1
                    _asyncio.run(_upsert_catalog(source_id, entry, status="error", error=str(exc)[:512]))
                    continue

                # Compute content hash
                content_hash = hashlib.sha256(data).hexdigest()

                # Skip unchanged content even if mtime/etag differ
                if catalog and catalog.content_hash and catalog.content_hash == content_hash:
                    _asyncio.run(_upsert_catalog(source_id, entry, status="indexed",
                                                  content_hash=content_hash))
                    continue

                # Extract text
                filename = Path(entry.path).name
                text = _extract_text_from_bytes(data, filename)
                if not text.strip():
                    _asyncio.run(_upsert_catalog(source_id, entry, status="skipped",
                                                  content_hash=content_hash))
                    continue

                # Index into Whoosh
                doc_id = _doc_id(source_id, entry.path)
                try:
                    search_engine.index_document(
                        doc_id=doc_id,
                        filename=filename,
                        content=text,
                        file_type=Path(entry.path).suffix.lstrip("."),
                        project=f"storage_source_{source_id}",
                        path=entry.path,
                    )
                except Exception as exc:
                    logger.warning("[storage_indexer] index_document failed %s: %s", entry.path, exc)
                    _errors += 1
                    _asyncio.run(_upsert_catalog(source_id, entry, status="error", error=str(exc)[:512]))
                    continue

                _asyncio.run(_upsert_catalog(source_id, entry, status="indexed",
                                              content_hash=content_hash))
                _indexed += 1

            return _scanned, _indexed, _errors, _error_msg

        scanned, indexed, errors, error_msg = await loop.run_in_executor(None, _do_index)
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


async def _get_catalog_entry(source_id: int, path: str) -> Optional[StorageFileCatalog]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(StorageFileCatalog).where(
                StorageFileCatalog.source_id == source_id,
                StorageFileCatalog.path == path,
            )
        )
        return result.scalar_one_or_none()


async def _upsert_catalog(
    source_id: int,
    entry: FileEntry,
    status: str = "indexed",
    content_hash: str = "",
    error: str = "",
) -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(StorageFileCatalog).where(
                StorageFileCatalog.source_id == source_id,
                StorageFileCatalog.path == entry.path,
            )
        )
        catalog = result.scalar_one_or_none()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if catalog is None:
            catalog = StorageFileCatalog(
                source_id=source_id,
                path=entry.path,
            )
            db.add(catalog)

        catalog.size = entry.size
        catalog.mtime = entry.mtime
        catalog.etag = entry.etag or ""
        catalog.content_hash = content_hash or catalog.content_hash
        catalog.status = status
        catalog.error = error
        if status == "indexed":
            catalog.last_indexed_at = now
        catalog.updated_at = now
        await db.commit()
