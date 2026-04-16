import time
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.api.auth import get_current_user
from app.database import get_db
from app.models import User, SearchLog, SearchTemplate
from app.schemas import SearchQuery, SearchTemplateCreate, SearchTemplateOut
from app.services.search_engine import search_engine
from app.services.osint import get_client
from app.services.crypto import decrypt

router = APIRouter()


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
