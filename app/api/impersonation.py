"""
Backend proxy endpoint for Impersonation Monitoring (openSquat integration).
Keeps the openSquat API key server-side and never exposes it to the client.
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.auth import get_current_user
from app.database import get_db
from app.models import User, Integration
from app.services.crypto import decrypt
from app.services.osint.opensquat import OpenSquatClient

router = APIRouter()


async def _get_opensquat_client(db: AsyncSession) -> OpenSquatClient:
    """Retrieve openSquat integration and return a ready client, or raise 503."""
    result = await db.execute(
        select(Integration).where(
            Integration.service_type == "opensquat",
            Integration.is_active.is_(True),
        )
    )
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(
            status_code=503,
            detail="openSquat integration is not configured. Add it in Integrations settings.",
        )
    api_key = decrypt(integration.api_key_encrypted)
    return OpenSquatClient(api_key=api_key)


@router.get("/search")
async def search_impersonation(
    keyword: str = Query(..., min_length=1, max_length=253,
                         description="Brand or domain keyword to search for lookalike domains"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Proxy openSquat API search for lookalike/impersonating domains."""
    client = await _get_opensquat_client(db)
    data = await client.search(keyword, query_type="domain")
    return data


@router.get("/status")
async def impersonation_status(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Check whether openSquat integration is configured."""
    result = await db.execute(
        select(Integration).where(
            Integration.service_type == "opensquat",
        )
    )
    integration = result.scalar_one_or_none()
    return {
        "configured": integration is not None,
        "active": integration.is_active if integration else False,
        "name": integration.name if integration else None,
    }
