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
from app.models import User, StorageSource, StorageFileCatalog, DSStorageSource
from app.schemas import StorageSourceCreate, StorageSourceUpdate, StorageSourceOut, StorageFileCatalogOut
from app.services.crypto import encrypt, decrypt
from app.services.deep_search_audit import DeepSearchAuditEvent, audit_log
from app.services.deep_search_rbac import require_role
from app.services.storage_credential_vault import StorageCredentialVault

logger = logging.getLogger(__name__)
router = APIRouter()
_vault: StorageCredentialVault | None = None

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
_CREDENTIAL_METADATA_FIELDS = {"username", "access_key", "endpoint_url", "region"}


def _get_vault() -> StorageCredentialVault:
    global _vault
    if _vault is None:
        _vault = StorageCredentialVault()
    return _vault


def _decrypt_config_payload(config_encrypted: str) -> dict:
    try:
        raw = json.loads(decrypt(config_encrypted) or "{}")
    except (TypeError, json.JSONDecodeError):
        raw = {}
    try:
        return _get_vault().decrypt_credentials(raw)
    except ValueError:
        return raw


def _encrypt_config_payload(config: dict) -> str:
    encrypted_creds = _get_vault().encrypt_credentials(config or {})
    return encrypt(json.dumps(encrypted_creds))


async def _sync_ds_source(db: AsyncSession, source: StorageSource, config: dict, user: User):
    """Mirror legacy storage_sources rows into ds_sources for Deep Search phase-1 schema."""
    result = await db.execute(select(DSStorageSource).where(DSStorageSource.id == source.id))
    ds_source = result.scalar_one_or_none()
    if ds_source is None:
        ds_source = DSStorageSource(id=source.id)
        db.add(ds_source)
    ds_source.display_name = source.name
    ds_source.source_type = source.source_type
    ds_source.enabled = source.is_enabled
    ds_source.schedule_cron = source.schedule
    ds_source.max_file_size_mb = source.max_file_size_mb
    ds_source.path = str(config.get("path", "") or "")
    ds_source.host = str(config.get("host", "") or "")
    try:
        port_value = config.get("port")
        ds_source.port = int(port_value) if port_value not in (None, "") else None
    except (TypeError, ValueError):
        logger.warning("Invalid port value for source %s: %r", source.id, config.get("port"))
        ds_source.port = None
    ds_source.protocol = str(config.get("protocol", "") or "")
    ds_source.bucket_name = str(config.get("bucket_name", "") or "")
    ds_source.api_config = {
        k: v for k, v in (config or {}).items()
        if k not in _SECRET_FIELDS
    }
    ds_source.credentials = {
        k: v for k, v in (config or {}).items()
        if k in _SECRET_FIELDS or k in _CREDENTIAL_METADATA_FIELDS
    }
    ds_source.created_by = getattr(user, "id", None)


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
    existing = _decrypt_config_payload(existing_encrypted)
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
    current_user: User = Depends(require_role("sec_engineer", "admin")),
):
    encrypted_config = _encrypt_config_payload(data.config)
    source = StorageSource(
        name=data.name,
        source_type=data.source_type,
        config_encrypted=encrypted_config,
        is_enabled=data.is_enabled,
        schedule=data.schedule,
        max_file_size_mb=data.max_file_size_mb,
        recursive=data.recursive,
    )
    db.add(source)
    await db.flush()
    await _sync_ds_source(db, source, data.config or {}, current_user)
    await audit_log(
        DeepSearchAuditEvent.SOURCE_CREATE,
        current_user.id,
        {"source_id": source.id, "source_type": source.source_type},
        db,
    )
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
    config = _decrypt_config_payload(source.config_encrypted)
    return {"config": _mask_config(config)}


@router.put("/{source_id}", response_model=StorageSourceOut)
async def update_storage_source(
    source_id: int,
    data: StorageSourceUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("sec_engineer", "admin")),
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
        source.config_encrypted = _encrypt_config_payload(merged)
        await audit_log(
            DeepSearchAuditEvent.SOURCE_CREDENTIALS_EDIT,
            current_user.id,
            {"source_id": source.id},
            db,
        )

    source_config = _decrypt_config_payload(source.config_encrypted)
    await _sync_ds_source(db, source, source_config, current_user)

    await db.commit()
    await db.refresh(source)
    return source


@router.delete("/{source_id}")
async def delete_storage_source(
    source_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role("sec_engineer", "admin")),
):
    result = await db.execute(select(StorageSource).where(StorageSource.id == source_id))
    source = result.scalar_one_or_none()
    if not source:
        raise HTTPException(status_code=404, detail="Storage source not found")
    ds_row = (await db.execute(select(DSStorageSource).where(DSStorageSource.id == source_id))).scalar_one_or_none()
    if ds_row:
        await db.delete(ds_row)
    await audit_log(
        DeepSearchAuditEvent.SOURCE_DELETE,
        current_user.id,
        {"source_id": source_id},
        db,
    )
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
        config = _decrypt_config_payload(source.config_encrypted)
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
