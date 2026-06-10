import asyncio
import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import delete, select

from app.database import AsyncSessionLocal
from app.models import DSChunk, DSFile, DSLeakRecord, DSStorageSource, StorageSource
from app.services.connectors import FileEntry, get_connector
from app.services.crypto import decrypt
from app.services.deep_search_audit import DeepSearchAuditEvent, audit_log
from app.services.deep_search_parsers import determine_parse_mode, extract_text_from_bytes
from app.services.deep_search_patterns import rollup_leak_records, scan_chunk
from app.services.security import PathTraversalError, sanitise_path
from app.services.storage_credential_vault import StorageCredentialVault

logger = logging.getLogger(__name__)

MAX_FILES_PER_RUN = 10_000
CHUNK_SIZE = 4_000
CHUNK_OVERLAP = 200
DEFAULT_INGEST_MAX_RUN_SECONDS = 1_800


@dataclass(frozen=True)
class _LoadedSource:
    id: int
    display_name: str
    source_type: str
    path: str
    enabled: bool
    max_file_size_mb: int
    include_extensions: list[str]
    exclude_extensions: list[str]
    recursive: bool


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _normalise_extensions(values: list[str] | None) -> set[str]:
    normalised: set[str] = set()
    for value in values or []:
        if not value:
            continue
        ext = value.lower().strip()
        if not ext:
            continue
        normalised.add(ext if ext.startswith(".") else f".{ext}")
    return normalised


def _crawl_path(source: _LoadedSource, config: dict) -> str:
    if source.source_type.lower() in {"local", "localfs"}:
        return ""
    return str(config.get("path") or source.path or "")


def _build_connector_config(source: _LoadedSource, config: dict) -> dict:
    merged = dict(config or {})
    if source.source_type.lower() in {"local", "localfs"}:
        merged.setdefault("base_path", merged.get("path") or source.path or ".")
    elif source.path and "path" not in merged:
        merged["path"] = source.path
    return merged


def _should_process_entry(
    entry: FileEntry,
    include_extensions: set[str],
    exclude_extensions: set[str],
    max_bytes: int,
) -> bool:
    suffix = Path(entry.path).suffix.lower()
    if include_extensions and suffix not in include_extensions:
        return False
    if suffix in exclude_extensions:
        return False
    if entry.size and entry.size > max_bytes:
        return False
    return True


def _same_file_metadata(existing: DSFile, entry: FileEntry) -> bool:
    return (
        existing.size_bytes == entry.size
        and existing.mtime == entry.mtime
        and (existing.etag or "") == (entry.etag or "")
    )


def _chunk_text(content: str) -> list[tuple[int, int, str]]:
    if not content:
        return []
    chunks: list[tuple[int, int, str]] = []
    start = 0
    while start < len(content):
        max_end = min(len(content), start + CHUNK_SIZE)
        end = max_end
        if max_end < len(content):
            split_at = content.rfind("\n", start + (CHUNK_SIZE // 2), max_end)
            if split_at > start:
                end = split_at
        if end <= start:
            end = max_end
        chunk = content[start:end]
        if chunk:
            chunks.append((start, end, chunk))
        if end >= len(content):
            break
        next_start = max(0, end - CHUNK_OVERLAP)
        if next_start <= start:
            next_start = end
        start = next_start
    return chunks


async def _write_audit(event: DeepSearchAuditEvent, user_id: int | None, details: dict) -> None:
    async with AsyncSessionLocal() as db:
        await audit_log(event, user_id, details, db)
        await db.commit()


async def _load_source_and_config(source_id: int, user_id: int | None) -> tuple[_LoadedSource | None, dict | None, str | None]:
    vault = StorageCredentialVault()
    async with AsyncSessionLocal() as db:
        ds_source = (
            await db.execute(select(DSStorageSource).where(DSStorageSource.id == source_id))
        ).scalar_one_or_none()
        if ds_source is None:
            return None, None, "Deep Search source not found"
        legacy_source = (
            await db.execute(select(StorageSource).where(StorageSource.id == source_id))
        ).scalar_one_or_none()

        now = _utcnow()
        ds_source.last_crawl_started_at = now
        ds_source.last_crawl_status = "running"
        ds_source.last_crawl_error = ""
        await audit_log(
            DeepSearchAuditEvent.SOURCE_INGEST_START,
            user_id,
            {"source_id": source_id},
            db,
        )

        raw_config = vault.parse_json_credentials(ds_source.credentials)
        if not raw_config and legacy_source is not None:
            raw_payload = json.loads(decrypt(legacy_source.config_encrypted) or "{}")
            raw_config = raw_payload if isinstance(raw_payload, dict) else {}
            ds_source.credentials = raw_config

        try:
            config = vault.decrypt_credentials(raw_config)
        except ValueError:
            message = "credential vault decryption failed — check DS_CREDENTIAL_KEK"
            ds_source.health_status = "error"
            ds_source.last_crawl_status = "error"
            ds_source.last_crawl_error = message
            ds_source.last_crawl_completed_at = now
            await audit_log(
                DeepSearchAuditEvent.SOURCE_INGEST_CREDENTIALS_ERROR,
                user_id,
                {"source_id": source_id, "error": message},
                db,
            )
            await db.commit()
            return None, None, message

        loaded_source = _LoadedSource(
            id=ds_source.id,
            display_name=ds_source.display_name,
            source_type=ds_source.source_type,
            path=ds_source.path or "",
            enabled=bool(ds_source.enabled),
            max_file_size_mb=ds_source.max_file_size_mb or 25,
            include_extensions=list(ds_source.include_extensions or []),
            exclude_extensions=list(ds_source.exclude_extensions or []),
            recursive=bool(legacy_source.recursive) if legacy_source is not None else True,
        )
        await db.commit()
        return loaded_source, _build_connector_config(loaded_source, config), None


async def _persist_file_error(
    source: _LoadedSource,
    entry: FileEntry,
    error: str,
    user_id: int | None,
    content_sha256: str = "",
) -> None:
    now = _utcnow()
    async with AsyncSessionLocal() as db:
        existing = (
            await db.execute(
                select(DSFile).where(DSFile.source_id == source.id, DSFile.file_path == entry.path)
            )
        ).scalar_one_or_none()
        if existing is None:
            existing = DSFile(source_id=source.id, file_path=entry.path, file_name=Path(entry.path).name)
            db.add(existing)
        existing.size_bytes = entry.size
        existing.mtime = entry.mtime
        existing.etag = entry.etag or ""
        existing.content_sha256 = content_sha256
        existing.index_status = "error"
        existing.last_seen_at = now
        await audit_log(
            DeepSearchAuditEvent.FILE_INGEST_ERROR,
            user_id,
            {"source_id": source.id, "file_path": entry.path, "error": error[:512]},
            db,
        )
        await db.commit()


async def _ingest_file(
    source: _LoadedSource,
    entry: FileEntry,
    connector,
    *,
    user_id: int | None,
    max_file_size_bytes: int,
) -> dict:
    now = _utcnow()
    async with AsyncSessionLocal() as db:
        existing = (
            await db.execute(
                select(DSFile).where(DSFile.source_id == source.id, DSFile.file_path == entry.path)
            )
        ).scalar_one_or_none()
        if existing is not None and _same_file_metadata(existing, entry):
            existing.last_seen_at = now
            await db.commit()
            return {"status": "skipped", "chunks_written": 0, "leaks_detected": 0}

    try:
        data = await asyncio.to_thread(connector.get_file_bytes, entry.path, max_file_size_bytes)
        content_sha256 = hashlib.sha256(data).hexdigest()
    except Exception as exc:
        await _persist_file_error(source, entry, str(exc), user_id)
        return {"status": "error", "chunks_written": 0, "leaks_detected": 0}

    async with AsyncSessionLocal() as db:
        existing = (
            await db.execute(
                select(DSFile).where(DSFile.source_id == source.id, DSFile.file_path == entry.path)
            )
        ).scalar_one_or_none()
        if existing is not None and existing.content_sha256 == content_sha256:
            existing.size_bytes = entry.size
            existing.mtime = entry.mtime
            existing.etag = entry.etag or ""
            existing.index_status = "skipped" if existing.index_status == "skipped" else "indexed"
            existing.last_seen_at = now
            await db.commit()
            return {"status": "skipped", "chunks_written": 0, "leaks_detected": 0}

        try:
            text = extract_text_from_bytes(data, Path(entry.path).name)
            parse_mode = determine_parse_mode(Path(entry.path).name, text, data)
            chunks = _chunk_text(text) if text.strip() else []

            if existing is not None:
                await db.execute(delete(DSLeakRecord).where(DSLeakRecord.file_id == existing.id))
                await db.execute(delete(DSChunk).where(DSChunk.file_id == existing.id))
                await db.delete(existing)
                await db.flush()

            file_row = DSFile(
                source_id=source.id,
                file_path=entry.path,
                file_name=Path(entry.path).name,
                size_bytes=entry.size,
                mtime=entry.mtime,
                etag=entry.etag or "",
                content_sha256=content_sha256,
                index_status="indexed" if chunks else "skipped",
                parse_mode=parse_mode,
                indexed_at=now if chunks else None,
                last_seen_at=now,
            )
            db.add(file_row)
            await db.flush()

            leak_records = []
            for chunk_index, (start_offset, end_offset, content) in enumerate(chunks):
                chunk_row = DSChunk(
                    file_id=file_row.id,
                    chunk_index=chunk_index,
                    content=content,
                    start_offset=start_offset,
                    end_offset=end_offset,
                )
                db.add(chunk_row)
                await db.flush()
                leak_records.extend(scan_chunk(content, chunk_row.id, file_row.id))

            for record in leak_records:
                db.add(
                    DSLeakRecord(
                        file_id=record.file_id,
                        chunk_id=record.chunk_id,
                        pattern_name=record.pattern_name,
                        category=record.category,
                        severity=record.severity,
                        matched_value=record.matched_value,
                        matched_value_masked=record.matched_value_masked,
                        context_before=record.context_before,
                        context_after=record.context_after,
                        line_number=record.line_number,
                        char_offset=record.char_offset,
                        email=record.email,
                        email_domain=record.email_domain,
                        password_plain=record.password_plain,
                    )
                )

            file_row.leak_count = len(leak_records)
            if leak_records:
                rollup = rollup_leak_records(leak_records)
                file_row.severity_max = rollup["severity_max"]
                file_row.has_api_keys = rollup["has_api_keys"]
                file_row.has_credentials = rollup["has_credentials"]
                file_row.has_pii = rollup["has_pii"]
                file_row.pattern_names = rollup["pattern_names"]
                await audit_log(
                    DeepSearchAuditEvent.LEAK_DETECTED,
                    user_id,
                    {
                        "source_id": source.id,
                        "file_id": file_row.id,
                        "file_path": entry.path,
                        "pattern_names": rollup["pattern_names"],
                        "severity_max": rollup["severity_max"],
                        "leak_count": rollup["leak_count"],
                    },
                    db,
                )
            else:
                file_row.severity_max = 0
                file_row.has_api_keys = False
                file_row.has_credentials = False
                file_row.has_pii = False
                file_row.pattern_names = []

            await audit_log(
                DeepSearchAuditEvent.FILE_INGESTED,
                user_id,
                {
                    "source_id": source.id,
                    "file_id": file_row.id,
                    "file_path": entry.path,
                    "index_status": file_row.index_status,
                    "parse_mode": file_row.parse_mode,
                    "chunks_written": len(chunks),
                    "leak_count": len(leak_records),
                },
                db,
            )
            await db.commit()
            return {
                "status": "indexed" if chunks else "skipped",
                "chunks_written": len(chunks),
                "leaks_detected": len(leak_records),
            }
        except Exception as exc:
            await db.rollback()
            await _persist_file_error(source, entry, str(exc), user_id, content_sha256=content_sha256)
            return {"status": "error", "chunks_written": 0, "leaks_detected": 0}


async def _finalise_source(source_id: int, stats: dict, user_id: int | None) -> None:
    now = _utcnow()
    async with AsyncSessionLocal() as db:
        source = (
            await db.execute(select(DSStorageSource).where(DSStorageSource.id == source_id))
        ).scalar_one_or_none()
        if source is None:
            return
        source.last_crawl_at = now
        source.last_crawl_completed_at = now
        source.last_crawl_status = stats["status"]
        source.last_crawl_error = stats.get("error_msg") or ""
        source.last_crawl_files_scanned = stats["files_seen"]
        source.last_crawl_files_indexed = stats["files_indexed"]
        source.health_status = "ok" if stats["status"] == "ok" else "error" if stats["status"] == "error" else "degraded"
        await audit_log(DeepSearchAuditEvent.SOURCE_INGEST_COMPLETE, user_id, stats, db)
        await db.commit()


async def ingest_source(
    source_id: int,
    *,
    triggered_by: str = "scheduler",
    user_id: int | None = None,
    max_files: int | None = None,
) -> dict:
    """Crawl → fetch → parse → chunk → leak-scan → persist for one ds_sources row."""
    started_at = time.monotonic()
    stats = {
        "source_id": source_id,
        "files_seen": 0,
        "files_indexed": 0,
        "files_skipped": 0,
        "files_errored": 0,
        "chunks_written": 0,
        "leaks_detected": 0,
        "duration_ms": 0,
        "status": "ok",
        "error_msg": "",
    }
    max_run_seconds = int(os.getenv("INGEST_MAX_RUN_SECONDS", str(DEFAULT_INGEST_MAX_RUN_SECONDS)))
    deadline = started_at + max_run_seconds

    try:
        source, config, load_error = await _load_source_and_config(source_id, user_id)
        if load_error:
            stats["status"] = "error"
            stats["files_errored"] = 1
            stats["error_msg"] = load_error
            stats["duration_ms"] = int((time.monotonic() - started_at) * 1000)
            if source_id:
                await _finalise_source(source_id, stats, user_id)
            return stats
        if source is None:
            stats["status"] = "error"
            stats["error_msg"] = "Deep Search source not found"
            stats["duration_ms"] = int((time.monotonic() - started_at) * 1000)
            return stats
        if not source.enabled:
            stats["status"] = "error"
            stats["error_msg"] = "Deep Search source is disabled"
            stats["duration_ms"] = int((time.monotonic() - started_at) * 1000)
            await _finalise_source(source_id, stats, user_id)
            return stats

        connector = get_connector(source.source_type, config or {})
        try:
            file_entries = await asyncio.to_thread(
                lambda: list(
                    connector.list_files(
                        path=_crawl_path(source, config or {}),
                        recursive=source.recursive,
                        max_files=min(max_files or MAX_FILES_PER_RUN, MAX_FILES_PER_RUN),
                    )
                )
            )
        except Exception as exc:
            stats["status"] = "error"
            stats["files_errored"] = 1
            stats["error_msg"] = str(exc)[:512]
            await _finalise_source(source_id, stats, user_id)
            stats["duration_ms"] = int((time.monotonic() - started_at) * 1000)
            return stats

        include_extensions = _normalise_extensions(source.include_extensions)
        exclude_extensions = _normalise_extensions(source.exclude_extensions)
        max_file_size_bytes = (source.max_file_size_mb or 25) * 1024 * 1024
        base_path = str((config or {}).get("base_path") or (config or {}).get("path") or source.path or "/")

        for entry in file_entries:
            if time.monotonic() >= deadline:
                stats["status"] = "partial"
                stats["error_msg"] = "ingestion timed out"
                break

            stats["files_seen"] += 1
            if not _should_process_entry(entry, include_extensions, exclude_extensions, max_file_size_bytes):
                stats["files_skipped"] += 1
                continue

            try:
                sanitise_path(entry.path, base_path=base_path)
            except PathTraversalError:
                stats["files_skipped"] += 1
                await _write_audit(
                    DeepSearchAuditEvent.FILE_PATH_REJECTED,
                    user_id,
                    {"source_id": source.id, "file_path": entry.path},
                )
                continue

            result = await _ingest_file(
                source,
                entry,
                connector,
                user_id=user_id,
                max_file_size_bytes=max_file_size_bytes,
            )
            stats["chunks_written"] += result["chunks_written"]
            stats["leaks_detected"] += result["leaks_detected"]
            if result["status"] == "indexed":
                stats["files_indexed"] += 1
            elif result["status"] == "skipped":
                stats["files_skipped"] += 1
            else:
                stats["files_errored"] += 1

        if stats["status"] == "ok" and stats["files_errored"] == stats["files_seen"] and stats["files_seen"]:
            stats["status"] = "error"
        elif stats["status"] == "ok" and stats["files_errored"]:
            stats["status"] = "partial"
    except Exception as exc:
        logger.exception("Deep Search ingestion failed for source %s", source_id)
        stats["status"] = "error"
        stats["files_errored"] += 1
        stats["error_msg"] = str(exc)[:512]

    stats["duration_ms"] = int((time.monotonic() - started_at) * 1000)
    await _finalise_source(source_id, stats, user_id)
    return stats
