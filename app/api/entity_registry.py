"""Legal-entity registry search and cross-jurisdiction comparison."""
from fastapi import APIRouter, Depends, HTTPException

from app.api.auth import get_current_user
from app.config import settings
from app.models import User
from app.schemas import EntityRegistryCompareRequest
from app.services.entity_registry import (
    CompaniesHouseClient,
    RegistryLookupError,
    build_comparison,
)

router = APIRouter()


@router.post("/compare")
async def compare_entity_registries(
    request: EntityRegistryCompareRequest,
    _: User = Depends(get_current_user),
):
    if not settings.companies_house_api_key:
        raise HTTPException(
            status_code=503,
            detail="Companies House API key is not configured",
        )

    try:
        uk_results = await CompaniesHouseClient(settings.companies_house_api_key).lookup(
            request.query,
            request.uk_company_number,
        )
    except RegistryLookupError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    delaware_record = None
    if any((
        request.delaware_name,
        request.delaware_entity_number,
        request.delaware_status,
        request.delaware_incorporated_on,
        request.delaware_registered_address,
    )):
        delaware_record = {
            "name": request.delaware_name,
            "entity_number": request.delaware_entity_number,
            "status": request.delaware_status,
            "incorporated_on": request.delaware_incorporated_on,
            "registered_address": request.delaware_registered_address,
        }

    return build_comparison(
        uk_results,
        delaware_record,
        request.query,
        request.delaware_name or request.uk_company_number,
    )
