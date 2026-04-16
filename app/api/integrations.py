from typing import List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.api.auth import get_current_user
from app.database import get_db
from app.models import User, Integration
from app.schemas import IntegrationCreate, IntegrationOut, IntegrationUpdate
from app.services.crypto import encrypt, decrypt
from app.services.osint import get_client, OSINT_CLIENTS

router = APIRouter()

KNOWN_SERVICES = [
    {"type": "hibp", "name": "Have I Been Pwned", "url": "https://haveibeenpwned.com"},
    {"type": "intelx", "name": "Intelligence X", "url": "https://intelx.io"},
    {"type": "leakix", "name": "LeakIX", "url": "https://leakix.net"},
    {"type": "virustotal", "name": "VirusTotal", "url": "https://virustotal.com"},
    {"type": "urlhaus", "name": "URLhaus", "url": "https://urlhaus.abuse.ch"},
    {"type": "phishtank", "name": "PhishTank", "url": "https://phishtank.org"},
    {"type": "urlscan", "name": "urlscan.io", "url": "https://urlscan.io"},
    {"type": "shodan", "name": "Shodan", "url": "https://shodan.io"},
    {"type": "censys", "name": "Censys", "url": "https://censys.io"},
    {"type": "securitytrails", "name": "SecurityTrails", "url": "https://securitytrails.com"},
    {"type": "abuseipdb", "name": "AbuseIPDB", "url": "https://abuseipdb.com"},
    {"type": "alienvault", "name": "AlienVault OTX", "url": "https://otx.alienvault.com"},
]


@router.get("/services")
async def list_services(_: User = Depends(get_current_user)):
    return KNOWN_SERVICES


@router.get("/", response_model=List[IntegrationOut])
async def list_integrations(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Integration).order_by(Integration.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=IntegrationOut)
async def create_integration(data: IntegrationCreate, db: AsyncSession = Depends(get_db),
                              _: User = Depends(get_current_user)):
    existing = await db.execute(select(Integration).where(Integration.service_type == data.service_type))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Integration already exists for this service type")
    integration = Integration(
        name=data.name,
        service_type=data.service_type,
        api_key_encrypted=encrypt(data.api_key),
        rate_limit=data.rate_limit,
        cache_ttl=data.cache_ttl,
        is_active=bool(data.api_key),
    )
    db.add(integration)
    await db.commit()
    await db.refresh(integration)
    return integration


@router.put("/{integration_id}", response_model=IntegrationOut)
async def update_integration(integration_id: int, data: IntegrationUpdate,
                              db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Not found")
    if data.name is not None:
        integration.name = data.name
    if data.api_key is not None:
        integration.api_key_encrypted = encrypt(data.api_key)
        integration.is_active = bool(data.api_key)
    if data.rate_limit is not None:
        integration.rate_limit = data.rate_limit
    if data.cache_ttl is not None:
        integration.cache_ttl = data.cache_ttl
    if data.is_active is not None:
        integration.is_active = data.is_active
    await db.commit()
    await db.refresh(integration)
    return integration


@router.delete("/{integration_id}")
async def delete_integration(integration_id: int, db: AsyncSession = Depends(get_db),
                              _: User = Depends(get_current_user)):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Not found")
    await db.delete(integration)
    await db.commit()
    return {"ok": True}


@router.post("/{integration_id}/test")
async def test_integration(integration_id: int, db: AsyncSession = Depends(get_db),
                            _: User = Depends(get_current_user)):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Not found")
    api_key = decrypt(integration.api_key_encrypted)
    client = get_client(integration.service_type, api_key)
    if not client:
        return {"ok": False, "error": "Unknown service type"}
    try:
        # Use a harmless test query
        result_data = await client.search("test", "general")
        ok = "error" not in result_data or result_data.get("not_found", False)
        return {"ok": ok, "result": result_data}
    except Exception:
        return {"ok": False, "error": "Integration test failed"}


@router.post("/{integration_id}/query")
async def query_integration(integration_id: int, body: dict,
                             db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Integration).where(Integration.id == integration_id))
    integration = result.scalar_one_or_none()
    if not integration:
        raise HTTPException(status_code=404, detail="Not found")
    api_key = decrypt(integration.api_key_encrypted)
    client = get_client(integration.service_type, api_key)
    if not client:
        raise HTTPException(status_code=400, detail="Unknown service type")
    query = body.get("query", "")
    query_type = body.get("query_type", "general")
    result_data = await client.search(query, query_type)
    return result_data
