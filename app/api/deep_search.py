"""
Deep Search API — upload folders, browse file trees, search content.
"""
import asyncio
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import aiofiles
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from fastapi.responses import FileResponse, Response

from app.api.auth import get_current_user, get_admin_user
from app.config import settings
from app.models import User
from app.services.indexer import index_deep_search_folder, deep_search_doc_id
from app.services.search_engine import search_engine
from app.utils.sanitize import sanitize_filename

router = APIRouter()
logger = logging.getLogger(__name__)

_MAX_FILES = 10_000
_MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500 MB
_PREVIEW_MAX_BYTES = 100 * 1024      # 100 KB
_PREVIEW_MAX_LINES = 500

_TEXT_EXTS = {'.txt', '.csv', '.log', '.json', '.xml', '.sql', '.md',
              '.cfg', '.conf', '.ini'}
_BINARY_EXTS = {'.xlsx', '.pdf', '.docx', '.xls', '.zip', '.rar', '.exe',
                '.bin', '.png', '.jpg', '.jpeg', '.gif', '.mp4', '.mp3'}


def _base_dir() -> Path:
    return Path(settings.deep_search_dir).resolve()


def _safe_resolve(base: Path, rel: str) -> Path:
    """Resolve *rel* inside *base* and raise 400 if path escapes *base*."""
    rel = str(rel or "").replace("\\", "/")
    if rel.startswith("/") or rel.startswith("../") or "/../" in f"/{rel}/":
        raise HTTPException(status_code=400, detail="Path traversal detected")
    target = (base / rel).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise HTTPException(status_code=400, detail="Path traversal detected")
    return target


def _build_tree(path: Path, base: Path) -> dict:
    """Recursively build a JSON-serialisable tree node for *path*.

    Only nodes that are strictly inside *base* are included.
    """
    # Safety: skip anything that escapes the base directory
    try:
        path.resolve().relative_to(base.resolve())
    except ValueError:
        return {"name": path.name, "type": "directory", "children": []}

    if path.is_file():
        rel = str(path.relative_to(base))
        return {
            "name": path.name,
            "type": "file",
            "size": path.stat().st_size,
            "path": rel,
            "ext": path.suffix.lower(),
        }
    children = []
    try:
        for child in sorted(path.iterdir(), key=lambda p: (p.is_file(), p.name.lower())):
            children.append(_build_tree(child, base))
    except PermissionError:
        pass
    rel_name = path.name if path != base else path.name
    return {"name": rel_name, "type": "directory", "children": children}


# ── Upload folder ──────────────────────────────────────────────────────────────

@router.post("/upload-folder")
async def upload_folder(
    folder_name: str = Form(...),
    files: List[UploadFile] = File(...),
    _: User = Depends(get_admin_user),
):
    """Upload multiple files into a named folder inside deep_search_data/."""
    safe_folder = sanitize_filename(folder_name)
    if not safe_folder:
        raise HTTPException(status_code=400, detail="Invalid folder name")

    base = _base_dir()
    dest_root = _safe_resolve(base, safe_folder)
    dest_root.mkdir(parents=True, exist_ok=True)

    if len(files) > _MAX_FILES:
        raise HTTPException(status_code=400, detail=f"Too many files (max {_MAX_FILES})")

    saved_paths: list = []
    total_size = 0

    for upload in files:
        # Sanitize the relative path provided by the browser (webkitRelativePath)
        raw_name: str = upload.filename or "file"
        # Strip any leading slashes / path components that escape the folder
        parts = [sanitize_filename(p) for p in raw_name.replace("\\", "/").split("/") if p and p != ".."]
        if not parts:
            parts = ["file"]

        rel_path = Path(*parts)
        dest_path = _safe_resolve(base, str(dest_root.relative_to(base) / rel_path))
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        chunk_size = 1024 * 1024  # 1 MB
        file_size = 0
        async with aiofiles.open(dest_path, "wb") as out:
            while True:
                chunk = await upload.read(chunk_size)
                if not chunk:
                    break
                file_size += len(chunk)
                total_size += len(chunk)
                if total_size > _MAX_TOTAL_SIZE:
                    raise HTTPException(status_code=413, detail="Upload exceeds 500 MB limit")
                await out.write(chunk)

        saved_paths.append(str(dest_path.relative_to(base)))

    asyncio.create_task(_index_uploaded_folder(str(dest_root), safe_folder))

    return {
        "folder": safe_folder,
        "files_count": len(saved_paths),
        "files": saved_paths,
        "indexing_started": True,
    }


# ── File tree ──────────────────────────────────────────────────────────────────

@router.get("/tree")
async def get_tree(_: User = Depends(get_admin_user)):
    """Return the full directory tree of deep_search_data/."""
    base = _base_dir()
    if not base.exists():
        return {"name": base.name, "type": "directory", "children": []}
    return _build_tree(base, base)


@router.get("/tree/{folder_name}")
async def get_folder_tree(
    folder_name: str,
    _: User = Depends(get_admin_user),
):
    """Return the directory tree for a specific top-level folder."""
    safe_folder = sanitize_filename(folder_name)
    base = _base_dir()
    folder_path = _safe_resolve(base, safe_folder)
    if not folder_path.exists():
        raise HTTPException(status_code=404, detail="Folder not found")
    return _build_tree(folder_path, base)


# ── File viewer ────────────────────────────────────────────────────────────────

@router.get("/file")
async def read_file(
    path: str = Query(..., description="Relative path inside deep_search_data/"),
    _: User = Depends(get_current_user),
):
    """Read and return the preview content of a file."""
    base = _base_dir()
    abs_path = _safe_resolve(base, path)

    if not abs_path.exists() or not abs_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    ext = abs_path.suffix.lower()
    size = abs_path.stat().st_size

    if ext in _BINARY_EXTS or (ext not in _TEXT_EXTS and size > _PREVIEW_MAX_BYTES):
        return {
            "path": path,
            "content": None,
            "binary": True,
            "size": size,
        }

    content = None
    lines_total = 0
    truncated = False
    encoding_used = "utf-8"

    def _read_preview(enc: str):
        nonlocal content, lines_total, truncated, encoding_used
        lines = []
        with open(abs_path, 'r', encoding=enc, errors='replace') as fh:
            bytes_read = 0
            for line in fh:
                lines_total += 1
                if len(lines) < _PREVIEW_MAX_LINES and bytes_read < _PREVIEW_MAX_BYTES:
                    lines.append(line.rstrip('\n\r'))
                    bytes_read += len(line.encode(enc, errors='replace'))
                else:
                    truncated = True
        content = "\n".join(lines)
        encoding_used = enc

    # Try chardet first for automatic encoding detection (handles ANSI/cp1251/cp1252)
    detected_enc = None
    try:
        import chardet
        with open(abs_path, 'rb') as f:
            raw_sample = f.read(min(size, 32768))
        det = chardet.detect(raw_sample)
        detected_enc = det.get('encoding') or None
    except Exception:
        pass

    encodings_to_try = []
    if detected_enc and detected_enc.lower() not in ('utf-8', 'ascii'):
        encodings_to_try.append(detected_enc)
    for _enc in ['utf-8', 'cp1251', 'cp1252', 'latin-1']:
        if _enc not in encodings_to_try:
            encodings_to_try.append(_enc)

    for enc in encodings_to_try:
        try:
            lines_total = 0
            _read_preview(enc)
            break
        except Exception:
            continue
    else:
        raise HTTPException(status_code=500, detail="Cannot read file")

    return {
        "path": path,
        "content": content,
        "lines_total": lines_total,
        "truncated": truncated,
        "encoding": encoding_used,
        "size": size,
        "ext": ext,
    }


@router.get("/download-watermark")
async def download_watermark(
    path: str = Query(..., description="Relative path inside deep_search_data/"),
    _: User = Depends(get_current_user),
):
    base = _base_dir()
    abs_path = _safe_resolve(base, path)

    if not abs_path.exists() or not abs_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    ext = abs_path.suffix.lower()
    original_name = abs_path.name

    if ext in _TEXT_EXTS:
        try:
            content = abs_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            raise HTTPException(status_code=500, detail="Cannot read file")
        watermarked = (
            "[WATERMARK: For review only. Unauthorized distribution prohibited.]\n\n"
            f"{content}\n\n"
            "[END OF WATERMARKED DOCUMENT]"
        )
        headers = {
            "Content-Disposition": f'attachment; filename="{original_name}"',
        }
        return Response(content=watermarked, media_type="text/plain; charset=utf-8", headers=headers)

    headers = {
        "X-Watermark": "CONFIDENTIAL - FOR REVIEW ONLY",
        "Content-Disposition": f'attachment; filename="[REVIEW_ONLY]_{original_name}"',
    }
    return FileResponse(
        str(abs_path),
        media_type="application/octet-stream",
        filename=f"[REVIEW_ONLY]_{original_name}",
        headers=headers,
    )


@router.get("/download")
async def download_file(
    path: str = Query(..., description="Relative path inside deep_search_data/"),
    _: User = Depends(get_current_user),
):
    base = _base_dir()
    abs_path = _safe_resolve(base, path)
    if not abs_path.exists() or not abs_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(
        str(abs_path),
        media_type="application/octet-stream",
        filename=abs_path.name,
    )


# ── Content search ─────────────────────────────────────────────────────────────

@router.post("/search")
async def search_deep(
    body: dict,
    _: User = Depends(get_current_user),
):
    """Search file names and content inside deep_search_data/.

    Body: {"query": "...", "folder": null}
    """
    from app.services.deep_search_service import search_deep_data
    from app.utils.sanitize import sanitize_search_query

    raw_query = body.get("query", "")
    query = sanitize_search_query(str(raw_query).strip())
    folder = body.get("folder") or None
    if folder:
        folder = sanitize_filename(str(folder))

    if not query:
        raise HTTPException(status_code=400, detail="Query must not be empty")

    results = await search_deep_data(query=query, folder=folder, limit=1000, use_index=True)

    total_matches = sum(r["match_count"] for r in results)
    return {
        "query": query,
        "results": results,
        "total_files_searched": len(results),
        "total_matches": total_matches,
    }


# ── Folder management ──────────────────────────────────────────────────────────

@router.get("/folders")
async def list_folders(_: User = Depends(get_current_user)):
    """List top-level folders in deep_search_data/."""
    base = _base_dir()
    if not base.exists():
        return []

    folders = []
    for item in sorted(base.iterdir(), key=lambda p: p.name.lower()):
        if not item.is_dir():
            continue
        files_count = sum(1 for _ in item.rglob("*") if _.is_file())
        size_bytes = sum(f.stat().st_size for f in item.rglob("*") if f.is_file())
        created_ts = item.stat().st_ctime
        folders.append({
            "name": item.name,
            "files_count": files_count,
            "size_bytes": size_bytes,
            "created_at": datetime.fromtimestamp(created_ts).isoformat(),
        })
    return folders


@router.delete("/folder/{folder_name}")
async def delete_folder(
    folder_name: str,
    _: User = Depends(get_admin_user),
):
    """Delete a folder and all its contents."""
    safe_folder = sanitize_filename(folder_name)
    base = _base_dir()
    folder_path = _safe_resolve(base, safe_folder)

    if not folder_path.exists():
        raise HTTPException(status_code=404, detail="Folder not found")
    if not folder_path.is_dir():
        raise HTTPException(status_code=400, detail="Not a directory")

    for item in folder_path.rglob("*"):
        if not item.is_file():
            continue
        relative_path = f"{safe_folder}/{item.relative_to(folder_path).as_posix()}"
        try:
            search_engine.delete_document(deep_search_doc_id(relative_path))
        except Exception:
            logger.warning("Failed to remove deep-search document from index: %s", relative_path, exc_info=True)

    shutil.rmtree(folder_path)
    return {"ok": True, "deleted": safe_folder}


async def _index_uploaded_folder(folder_path: str, folder_name: str) -> None:
    try:
        indexed = await index_deep_search_folder(folder_path, folder_name)
        logger.info("Indexed deep-search folder '%s': %s files", folder_name, indexed)
    except Exception:
        logger.exception("Failed to index uploaded deep-search folder '%s'", folder_name)


# ── TS-DS-001 Phase 1 — Query API (PR 3/4) ────────────────────────────────────
# New read-only endpoints that query ds_chunks / ds_files / ds_leak_records.
# Mounted on the same router (already at /api/v1/deep-search in main.py).

import sqlalchemy.exc
from datetime import datetime as _dt

from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import DSFile, User
from app.schemas import (
    ChunkListSchema,
    FileDetailSchema,
    LeakListSchema,
    SearchResponseSchema,
)
from app.services import deep_search_search as _svc
from app.services.deep_search_audit import DeepSearchAuditEvent, audit_log
from app.services.deep_search_rbac import require_role

_ds_logger = logging.getLogger(__name__)


@router.get("/query", response_model=SearchResponseSchema, tags=["deep-search-query"])
async def query_endpoint(
    q: str = Query(..., min_length=1, max_length=512),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    source_id: Optional[List[int]] = Query(None),
    severity_min: Optional[int] = Query(None, ge=0, le=100),
    severity_max: Optional[int] = Query(None, ge=0, le=100),
    has_credentials: Optional[bool] = Query(None),
    has_pii: Optional[bool] = Query(None),
    has_api_keys: Optional[bool] = Query(None),
    pattern_names: Optional[List[str]] = Query(None),
    parse_mode: Optional[List[str]] = Query(None),
    indexed_after: Optional[_dt] = Query(None),
    indexed_before: Optional[_dt] = Query(None),
    file_path_prefix: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("sec_engineer", "admin", "ti_analyst")),
) -> SearchResponseSchema:
    filters = _svc.SearchFilters(
        source_ids=source_id,
        severity_min=severity_min,
        severity_max=severity_max,
        has_credentials=has_credentials,
        has_pii=has_pii,
        has_api_keys=has_api_keys,
        pattern_names=pattern_names,
        parse_mode=parse_mode,
        indexed_after=indexed_after,
        indexed_before=indexed_before,
        file_path_prefix=file_path_prefix,
    )
    active_filters = [
        k for k, v in {
            "source_id": source_id,
            "severity_min": severity_min,
            "severity_max": severity_max,
            "has_credentials": has_credentials,
            "has_pii": has_pii,
            "has_api_keys": has_api_keys,
            "pattern_names": pattern_names,
            "parse_mode": parse_mode,
            "indexed_after": indexed_after,
            "indexed_before": indexed_before,
            "file_path_prefix": file_path_prefix,
        }.items()
        if v is not None
    ]
    try:
        result = await _svc.search(db, q, filters=filters, page=page, page_size=page_size)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except sqlalchemy.exc.OperationalError as exc:
        _ds_logger.exception("Search backend error")
        raise HTTPException(status_code=500, detail="search backend error") from exc

    await audit_log(
        DeepSearchAuditEvent.SEARCH_QUERY,
        current_user.id,
        {
            "q": q[:128],
            "filter_keys": active_filters,
            "result_count": result.total,
            "page": page,
            "page_size": page_size,
        },
        db,
    )
    await db.commit()

    return SearchResponseSchema(
        items=[
            {
                "chunk_id": h.chunk_id,
                "file_id": h.file_id,
                "source_id": h.source_id,
                "file_path": h.file_path,
                "chunk_index": h.chunk_index,
                "snippet": h.snippet,
                "rank": h.rank,
                "file_severity_max": h.file_severity_max,
                "file_has_credentials": h.file_has_credentials,
                "file_has_pii": h.file_has_pii,
                "file_has_api_keys": h.file_has_api_keys,
                "file_pattern_names": h.file_pattern_names,
                "file_indexed_at": h.file_indexed_at,
            }
            for h in result.items
        ],
        total=result.total,
        page=result.page,
        page_size=result.page_size,
        has_next=result.has_next,
    )


@router.get("/files/{file_id}", response_model=FileDetailSchema, tags=["deep-search-query"])
async def file_detail_endpoint(
    file_id: int,
    chunk_preview: int = Query(5, ge=0, le=20),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("sec_engineer", "admin", "ti_analyst")),
) -> FileDetailSchema:
    detail = await _svc.get_file_detail(db, file_id, chunk_preview=chunk_preview)
    if detail is None:
        raise HTTPException(status_code=404, detail="File not found")

    await audit_log(
        DeepSearchAuditEvent.SEARCH_FILE_READ,
        current_user.id,
        {"file_id": file_id},
        db,
    )
    await db.commit()
    return FileDetailSchema(**detail)


@router.get("/files/{file_id}/chunks", response_model=ChunkListSchema, tags=["deep-search-query"])
async def file_chunks_endpoint(
    file_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("sec_engineer", "admin", "ti_analyst")),
) -> ChunkListSchema:
    result = await _svc.list_chunks_for_file(db, file_id, offset=offset, limit=limit)
    # 404 if the parent file does not exist (total==0 and items==[])
    file_row = await db.get(DSFile, file_id)
    if file_row is None:
        raise HTTPException(status_code=404, detail="File not found")

    await audit_log(
        DeepSearchAuditEvent.SEARCH_FILE_READ,
        current_user.id,
        {"file_id": file_id, "via": "chunks"},
        db,
    )
    await db.commit()
    return ChunkListSchema(**result)


@router.get("/leaks", response_model=LeakListSchema, tags=["deep-search-query"])
async def leak_list_endpoint(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    source_id: Optional[List[int]] = Query(None),
    pattern_names: Optional[List[str]] = Query(None, alias="pattern_names"),
    category: Optional[str] = Query(None),
    severity_min: Optional[int] = Query(None, ge=0, le=100),
    has_credentials: Optional[bool] = Query(None),
    has_pii: Optional[bool] = Query(None),
    has_api_keys: Optional[bool] = Query(None),
    file_path_prefix: Optional[str] = Query(None),
    detected_after: Optional[_dt] = Query(None),
    detected_before: Optional[_dt] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("sec_engineer", "admin", "ti_analyst")),
) -> LeakListSchema:
    filters = _svc.SearchFilters(
        source_ids=source_id,
        has_credentials=has_credentials,
        has_pii=has_pii,
        has_api_keys=has_api_keys,
        file_path_prefix=file_path_prefix,
        pattern_names=pattern_names,
    )
    active_filters = [
        k for k, v in {
            "source_id": source_id,
            "pattern_names": pattern_names,
            "category": category,
            "severity_min": severity_min,
            "has_credentials": has_credentials,
            "has_pii": has_pii,
            "has_api_keys": has_api_keys,
            "file_path_prefix": file_path_prefix,
            "detected_after": detected_after,
            "detected_before": detected_before,
        }.items()
        if v is not None
    ]

    result = await _svc.list_leaks(
        db,
        filters=filters,
        page=page,
        page_size=page_size,
        category=category,
        severity_min=severity_min,
        detected_after=detected_after,
        detected_before=detected_before,
    )

    await audit_log(
        DeepSearchAuditEvent.SEARCH_LEAK_LIST_READ,
        current_user.id,
        {
            "filter_keys": active_filters,
            "result_count": result["total"],
            "page": page,
            "page_size": page_size,
        },
        db,
    )
    await db.commit()
    return LeakListSchema(**result)
