"""
Async file indexer — reads files using file_parsers and indexes via search_engine.
"""
import asyncio
import hashlib
from pathlib import Path
from typing import Optional

from app.services.file_parsers import extract_text, extract_text_streaming, MAX_INDEX_BYTES
from app.services.search_engine import search_engine


async def compute_checksum(file_path: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _compute_checksum_sync, file_path)


def _compute_checksum_sync(file_path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except Exception:
        pass
    return h.hexdigest()


async def index_file(file_id: int, file_path: str, filename: str,
                     file_type: str = "", project: str = "") -> bool:
    loop = asyncio.get_event_loop()
    try:
        file_size = Path(file_path).stat().st_size if Path(file_path).exists() else 0
        if file_size > MAX_INDEX_BYTES:
            content = await loop.run_in_executor(None, extract_text_streaming, file_path)
        else:
            content = await loop.run_in_executor(None, extract_text, file_path)
        if content is None:
            content = ""
        search_engine.index_document(
            doc_id=str(file_id),
            filename=filename,
            content=content,
            file_type=file_type,
            project=project,
            path=file_path,
        )
        return True
    except Exception as e:
        print(f"[indexer] Error indexing {filename}: {e}")
        return False


async def remove_from_index(file_id: int):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, search_engine.delete_document, str(file_id))


async def scan_monitored_dir(monitored_dir: str, db_session_factory) -> int:
    """Scan monitored directory for new files and index them."""
    monitored = Path(monitored_dir)
    if not monitored.exists():
        return 0
    count = 0
    for f in monitored.rglob("*"):
        if f.is_file() and not f.name.startswith("."):
            checksum = await compute_checksum(str(f))
            file_size = f.stat().st_size if f.exists() else 0
            if file_size > MAX_INDEX_BYTES:
                content = await asyncio.get_event_loop().run_in_executor(
                    None, extract_text_streaming, str(f)
                )
            else:
                content = await asyncio.get_event_loop().run_in_executor(
                    None, extract_text, str(f)
                )
            search_engine.index_document(
                doc_id=f"monitored_{checksum}",
                filename=f.name,
                content=content or "",
                file_type=f.suffix.lstrip("."),
                project="monitored",
                path=str(f),
            )
            count += 1
    return count
