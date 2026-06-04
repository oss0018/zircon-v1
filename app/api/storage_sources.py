"""
API endpoints for External Storage Sources (Local Index integrations).

Routes:
  GET    /                     - list all sources
  POST   /                     - create source
  GET    /{id}                  - get source (config without secrets)
  PUT    /{id}                  - update source
  DELETE /{id}                  - delete source
  POST   /{id}/test             - test connection
  POST   /{id}/index            - trigger manual indexing run
  GET    /{id}/catalog          - list file catalog entries for source
"""
import json
import logging
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import User, StorageSource, StorageFileCatalog
from app.schemas import StorageSourceCreate, StorageSourceUpdate, StorageSourceOut, StorageFileCatalogOut
from app.services.crypto import encrypt, decrypt

logger = logging.getLogger(__name__)
router = APIRouter()

# Secret field names that must never be returned to the client
_SECRET_FIELDS = {
    "secret_key",
    "password",
    "private_key",
    "private_key_pem",
    "token",
    "api_token",
    "bearer_token",
    "key_passphrase",
}


def _mask_config(config: dict) -> dict:
    """Return a copy of config with secret values masked."""
    masked = {}
    for k, v in config.items():
        if k in _SECRET_FIELDS:
            masked[k] = "***" if v else ""
        else:
            masked[k] = v
    return masked


def _merge_config(existing_encrypted: str, updates: dict) -> dict:
    """Merge *updates* into the existing (decrypted) config, keeping old secrets if update is '***'."""
    try:
        existing = json.loads(decrypt(existing_encrypted) or "{}")
    except Exception:
        existing = {}
    for k, v in updates.items():
        if k in _SECRET_FIELDS and v == "***":
            continue  # keep existing secret
        existing[k] = v
    return existing


@router.get("/", response_model=List[StorageSourceOut])
async def list_storage_sources(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(StorageSource).order_by(StorageSource.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=StorageSourceOut)
async def create_storage_source(
    data: StorageSourceCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    source = StorageSource(
        name=data.name,
        source_type=data.source_type,
        config_encrypted=encrypt(json.dumps(data.config)),
        is_enabled=data.is_enabled,
        schedule=data.schedule,
        max_file_size_mb=data.max_file_size_mb,
        recursive=data.recursive,
    )
    db.add(source)
    await db.commit()
    await db.refresh(source)
    return source


@router.get("/{source_id}", response_model=StorageSourceOut)
async def get_storage_source(
    source_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(StorageSource).where(StorageSource.id == source_id))
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Storage source not found")
    return source


@router.get("/{source_id}/config")
async def get_storage_source_config(
    source_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return masked config (no secret values) for editing in the UI."""
    result = await db.execute(select(StorageSource).where(StorageSource.id == source_id))
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Storage source not found")
    try:
        config = json.loads(decrypt(source.config_encrypted) or "{}")
    except Exception:
        config = {}
    return {"config": _mask_config(config)}


@router.put("/{source_id}", response_model=StorageSourceOut)
async def update_storage_source(
    source_id: int,
    data: StorageSourceUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(StorageSource).where(StorageSource.id == source_id))
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Storage source not found")

    if data.name is not None:
        source.name = data.name
    if data.is_enabled is not None:
        source.is_enabled = data.is_enabled
    if data.schedule is not None:
        source.schedule = data.schedule
    if data.max_file_size_mb is not None:
        source.max_file_size_mb = data.max_file_size_mb
    if data.recursive is not None:
        source.recursive = data.recursive
    if data.config is not None:
        merged = _merge_config(source.config_encrypted, data.config)
        source.config_encrypted = encrypt(json.dumps(merged))

    await db.commit()
    await db.refresh(source)
    return source


@router.delete("/{source_id}")
async def delete_storage_source(
    source_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(StorageSource).where(StorageSource.id == source_id))
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Storage source not found")
    await db.delete(source)
    await db.commit()
    return {"ok": True}


@router.post("/{source_id}/test")
async def test_storage_source(
    source_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Test connectivity for a storage source (runs synchronously in executor)."""
    result = await db.execute(select(StorageSource).where(StorageSource.id == source_id))
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Storage source not found")

    import asyncio
    from app.services.connectors import get_connector

    try:
        config = json.loads(decrypt(source.config_encrypted) or "{}")
        connector = get_connector(source.source_type, config)
        loop = asyncio.get_event_loop()
        test_result = await loop.run_in_executor(None, connector.test_connection)
    except Exception:
        logger.exception("Error testing storage source %d", source_id)
        test_result = {"ok": False, "message": "Connection test failed — check server logs for details"}

    return test_result


@router.post("/{source_id}/index")
async def trigger_source_index(
    source_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Trigger a manual indexing run for a storage source (runs in background)."""
    result = await db.execute(select(StorageSource).where(StorageSource.id == source_id))
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Storage source not found")
    if not source.is_enabled:
        raise HTTPException(status_code=400, detail="Storage source is disabled")

    from app.services.storage_indexer import run_source_indexing

    background_tasks.add_task(run_source_indexing, source_id)
    return {"ok": True, "message": "Indexing started in background"}


@router.get("/{source_id}/catalog", response_model=List[StorageFileCatalogOut])
async def list_catalog(
    source_id: int,
    status: Optional[str] = Query(None, description="Filter by status: indexed|error|skipped|pending"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """List file catalog entries for a storage source."""
    q = select(StorageFileCatalog).where(StorageFileCatalog.source_id == source_id)
    if status:
        q = q.where(StorageFileCatalog.status == status)
    q = q.order_by(StorageFileCatalog.updated_at.desc()).limit(limit).offset(offset)
    result = await db.execute(q)
    return result.scalars().all()
