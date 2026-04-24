"""
Deep Search API — upload folders, browse file trees, search content.
"""
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import aiofiles
from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form

from app.api.auth import get_current_user
from app.config import settings
from app.models import User
from app.utils.sanitize import sanitize_filename

router = APIRouter()

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
    target = (base / rel).resolve()
    try:
        target.relative_to(base)
    except ValueError:
        raise HTTPException(status_code=400, detail="Path traversal detected")
    return target


def _build_tree(path: Path, base: Path) -> dict:
    """Recursively build a JSON-serialisable tree node for *path*."""
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
    _: User = Depends(get_current_user),
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

    return {
        "folder": safe_folder,
        "files_count": len(saved_paths),
        "files": saved_paths,
    }


# ── File tree ──────────────────────────────────────────────────────────────────

@router.get("/tree")
async def get_tree(_: User = Depends(get_current_user)):
    """Return the full directory tree of deep_search_data/."""
    base = _base_dir()
    if not base.exists():
        return {"name": base.name, "type": "directory", "children": []}
    return _build_tree(base, base)


@router.get("/tree/{folder_name}")
async def get_folder_tree(
    folder_name: str,
    _: User = Depends(get_current_user),
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

    try:
        _read_preview('utf-8')
    except Exception:
        try:
            lines_total = 0
            _read_preview('latin-1')
        except Exception:
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

    results = await search_deep_data(query=query, folder=folder, limit=1000)

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
    _: User = Depends(get_current_user),
):
    """Delete a folder and all its contents."""
    safe_folder = sanitize_filename(folder_name)
    base = _base_dir()
    folder_path = _safe_resolve(base, safe_folder)

    if not folder_path.exists():
        raise HTTPException(status_code=404, detail="Folder not found")
    if not folder_path.is_dir():
        raise HTTPException(status_code=400, detail="Not a directory")

    shutil.rmtree(folder_path)
    return {"ok": True, "deleted": safe_folder}
