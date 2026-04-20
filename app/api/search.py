import time
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.api.auth import get_current_user
from app.database import get_db
from app.models import User, SearchLog, SearchTemplate, File as FileModel, WatchedFolder
from app.schemas import SearchQuery, SearchTemplateCreate, SearchTemplateOut
from app.services.search_engine import search_engine
from app.services.osint import get_client
from app.services.crypto import decrypt

router = APIRouter()

_MAX_LINE_LENGTH = 500


@router.post("/")
async def run_search(query: SearchQuery, db: AsyncSession = Depends(get_db),
                     _: User = Depends(get_current_user)):
    start = time.time()
    results = []

    if query.source in ("local", "all"):
        try:
            local_hits = search_engine.search(query.query, limit=query.limit)
            for hit in local_hits:
                results.append({
                    "source": "local",
                    "score": hit.get("score", 0),
                    "data": hit,
                    "cached": False,
                })
        except Exception as e:
            results.append({"source": "local", "score": 0, "data": {"error": "Search error"}, "cached": False})

    if query.source in ("osint", "all") and query.integrations:
        from app.models import Integration
        for svc in query.integrations:
            res = await db.execute(select(Integration).where(Integration.service_type == svc))
            integration = res.scalar_one_or_none()
            api_key = ""
            if integration:
                api_key = decrypt(integration.api_key_encrypted)
            client = get_client(svc, api_key)
            if client:
                try:
                    osint_result = await client.search(query.query, query.query_type)
                    results.append({
                        "source": svc,
                        "score": 0,
                        "data": osint_result,
                        "cached": osint_result.get("cached", False),
                    })
                except Exception:
                    results.append({"source": svc, "score": 0, "data": {"error": "Integration request failed"}, "cached": False})

    duration_ms = int((time.time() - start) * 1000)
    log = SearchLog(
        query=query.query,
        results_count=len(results),
        duration_ms=duration_ms,
        source=query.source,
    )
    db.add(log)
    await db.commit()

    return {"results": results, "total": len(results), "duration_ms": duration_ms}


@router.get("/history")
async def search_history(limit: int = 50, db: AsyncSession = Depends(get_db),
                         _: User = Depends(get_current_user)):
    result = await db.execute(select(SearchLog).order_by(desc(SearchLog.created_at)).limit(limit))
    logs = result.scalars().all()
    return [{"id": l.id, "query": l.query, "results_count": l.results_count,
             "duration_ms": l.duration_ms, "source": l.source,
             "created_at": l.created_at.isoformat()} for l in logs]


@router.get("/templates", response_model=List[SearchTemplateOut])
async def list_templates(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(SearchTemplate).order_by(SearchTemplate.created_at.desc()))
    return result.scalars().all()


@router.post("/templates", response_model=SearchTemplateOut)
async def create_template(data: SearchTemplateCreate, db: AsyncSession = Depends(get_db),
                          _: User = Depends(get_current_user)):
    tmpl = SearchTemplate(name=data.name, query=data.query,
                          filters_json=data.filters_json, schedule=data.schedule)
    db.add(tmpl)
    await db.commit()
    await db.refresh(tmpl)
    return tmpl


@router.post("/grep")
async def grep_search(
    query: dict,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Streaming grep through all indexed files. Returns matching lines.
    Body: {"query": "kyivstar", "limit": 200, "case_sensitive": false}
    """
    import asyncio
    from pathlib import Path

    q = query.get("query", "").strip()
    limit = min(int(query.get("limit", 200)), 2000)
    case_sensitive = query.get("case_sensitive", False)

    if not q:
        return {"matches": [], "total": 0, "files_scanned": 0}

    search_str = q if case_sensitive else q.lower()

    # Collect all file paths to scan: from files table + watched folders
    file_paths = []

    # From files table
    result = await db.execute(select(FileModel).where(FileModel.indexed.is_(True)))
    db_files = result.scalars().all()
    for f in db_files:
        p = Path(f.path)
        if p.exists() and p.is_file():
            file_paths.append({"path": str(p), "name": f.original_name or f.name, "source": "indexed"})

    # From watched folders (files NOT in DB - raw directory scan)
    wf_result = await db.execute(select(WatchedFolder).where(WatchedFolder.is_active.is_(True)))
    watched = wf_result.scalars().all()
    indexed_paths = {fp["path"] for fp in file_paths}

    SUPPORTED_EXTS = {'.txt', '.csv', '.sql', '.log', '.json', '.xml', '.md', '.cfg', '.conf', '.ini'}
    for folder in watched:
        folder_path = Path(folder.path)
        if not folder_path.exists():
            continue
        for fp in folder_path.rglob("*"):
            if fp.is_file() and str(fp) not in indexed_paths:
                if fp.suffix.lower() in SUPPORTED_EXTS or fp.stat().st_size < 100 * 1024 * 1024:
                    file_paths.append({"path": str(fp), "name": fp.name, "source": folder.path})

    # Run grep in thread pool to avoid blocking the event loop
    loop = asyncio.get_event_loop()
    matches, files_scanned = await loop.run_in_executor(
        None, _grep_files, file_paths, search_str, limit, case_sensitive
    )

    return {"matches": matches, "total": len(matches), "files_scanned": files_scanned}


def _grep_files(file_paths: list, search_str: str, limit: int, case_sensitive: bool) -> tuple:
    """Synchronous grep across all files. Run in thread pool executor."""
    matches = []
    files_scanned = 0

    for file_info in file_paths:
        if len(matches) >= limit:
            break

        file_path = file_info["path"]
        file_name = file_info["name"]
        files_scanned += 1

        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                line_num = 0
                for line in f:
                    line_num += 1
                    compare = line if case_sensitive else line.lower()
                    if search_str in compare:
                        matches.append({
                            "file": file_name,
                            "path": file_path,
                            "line": line_num,
                            "text": line.rstrip('\n\r')[:_MAX_LINE_LENGTH],
                        })
                        if len(matches) >= limit:
                            break
        except Exception:
            # Binary or unreadable file — try with latin-1
            try:
                with open(file_path, 'r', encoding='latin-1', errors='replace') as f:
                    line_num = 0
                    for line in f:
                        line_num += 1
                        compare = line if case_sensitive else line.lower()
                        if search_str in compare:
                            matches.append({
                                "file": file_name,
                                "path": file_path,
                                "line": line_num,
                                "text": line.rstrip('\n\r')[:_MAX_LINE_LENGTH],
                            })
                            if len(matches) >= limit:
                                break
            except Exception:
                pass  # Skip truly unreadable files

    return matches, files_scanned


@router.delete("/templates/{template_id}")
async def delete_template(template_id: int, db: AsyncSession = Depends(get_db),
                           _: User = Depends(get_current_user)):
    result = await db.execute(select(SearchTemplate).where(SearchTemplate.id == template_id))
    tmpl = result.scalar_one_or_none()
    if not tmpl:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(tmpl)
    await db.commit()
    return {"ok": True}
