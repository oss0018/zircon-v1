"""
Deep Search Service — search through files in deep_search_data/ directory.
"""
import os
from pathlib import Path
from typing import Optional

from app.config import settings

SUPPORTED_TEXT_EXTS = {
    '.txt', '.csv', '.log', '.json', '.xml', '.sql', '.md',
    '.cfg', '.conf', '.ini',
}

_MAX_TOTAL_MATCHES = 1000


def _get_deep_search_dir() -> Path:
    return Path(settings.deep_search_dir).resolve()


def _is_safe_path(base: Path, target: Path) -> bool:
    """Return True if *target* is inside *base* (no path traversal)."""
    try:
        target.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _iter_text_files(base: Path, folder: Optional[str] = None):
    """Yield (relative_path_str, absolute_path) for text files under *base*.

    If *folder* is given, only files in that subdirectory are yielded.
    """
    if folder:
        scan_root = base / folder
        if not scan_root.exists() or not _is_safe_path(base, scan_root):
            return
    else:
        scan_root = base

    for fp in scan_root.rglob("*"):
        if not fp.is_file():
            continue
        if not _is_safe_path(base, fp):
            continue
        if fp.suffix.lower() in SUPPORTED_TEXT_EXTS:
            yield str(fp.relative_to(base)), fp


async def search_deep_data(
    query: str,
    folder: Optional[str] = None,
    limit: int = 200,
    use_index: bool = True,
) -> list:
    """Search through files in deep_search_data/ directory.

    Returns a list of result dicts compatible with DeepSearchResult.
    """
    import asyncio

    base = _get_deep_search_dir()
    if not base.exists():
        return []

    effective_limit = min(limit, _MAX_TOTAL_MATCHES)
    indexed_results = []
    indexed_paths = set()

    if use_index:
        try:
            from app.services.search_engine import search_engine
            indexed_hits = search_engine.search(
                query,
                limit=effective_limit,
                offset=0,
                fuzzy=True,
                fields=["filename", "content", "path"],
                source="deep_search",
            )
            for hit in indexed_hits:
                rel_path = str(hit.get("path") or "").replace("\\", "/")
                if folder and not rel_path.startswith(f"{folder}/"):
                    continue
                if not rel_path:
                    continue
                indexed_paths.add(rel_path)
                indexed_results.append({
                    "file_path": rel_path,
                    "file_name": hit.get("filename") or Path(rel_path).name,
                    "matches": [{"line": 0, "text": hit.get("snippet", "")}],
                    "match_count": 1,
                })
        except Exception:
            indexed_results = []
            indexed_paths = set()

    loop = asyncio.get_event_loop()
    grep_results, _ = await loop.run_in_executor(
        None, _sync_search, base, query, folder, effective_limit
    )
    merged = list(indexed_results)
    for item in grep_results:
        if item["file_path"] in indexed_paths:
            continue
        merged.append(item)
    return merged[:effective_limit]


def _sync_search(base: Path, query: str, folder: Optional[str], limit: int):
    """Synchronous search — runs in a thread pool to avoid blocking the event loop."""
    q_lower = query.lower()
    results = []
    total_matches = 0
    total_files_searched = 0

    for rel_path, abs_path in _iter_text_files(base, folder):
        if total_matches >= limit:
            break

        total_files_searched += 1
        file_name = abs_path.name
        matches = []

        # Check filename match
        if q_lower in file_name.lower():
            matches.append({"line": 0, "text": f"[filename match] {file_name}"})

        # Check content
        try:
            remaining = max(0, limit - total_matches - len(matches))
            if remaining > 0:
                matches.extend(_grep_file(abs_path, q_lower, remaining))
        except Exception:
            pass

        if matches:
            results.append({
                "file_path": rel_path,
                "file_name": file_name,
                "matches": matches,
                "match_count": len(matches),
            })
            total_matches += len(matches)

    return results, total_files_searched


def _grep_file(path: Path, q_lower: str, remaining: int) -> list:
    """Return matching lines from a single file."""
    matches = []

    def _read(encoding: str):
        with open(path, 'r', encoding=encoding, errors='replace') as fh:
            for line_num, line in enumerate(fh, 1):
                if q_lower in line.lower():
                    matches.append({
                        "line": line_num,
                        "text": line.rstrip('\n\r')[:500],
                    })
                    if len(matches) >= remaining:
                        break

    try:
        _read('utf-8')
    except Exception:
        try:
            _read('latin-1')
        except Exception:
            pass

    return matches
