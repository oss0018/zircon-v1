"""Search regulator enforcement records from US and UK sources."""
from fastapi import APIRouter, Depends

from app.api.auth import get_current_user
from app.config import settings
from app.models import User
from app.schemas import RegulatorSearchRequest
from app.services.regulators import (
    RegulatorSourceError,
    SECLitigationReleaseClient,
    build_regulator_response,
)

router = APIRouter()


@router.post("/search")
async def search_regulator_records(
    request: RegulatorSearchRequest,
    _: User = Depends(get_current_user),
):
    try:
        sec_records = await SECLitigationReleaseClient().search(
            request.query,
            request.limit,
            settings.sec_user_agent,
        )
    except RegulatorSourceError as exc:
        sec_records = []
        sec_error = str(exc)
    else:
        sec_error = None

    fca_record = None
    if any((
        request.fca_entity_name,
        request.fca_reference,
        request.fca_action_type,
        request.fca_date,
        request.fca_summary,
        request.fca_source_url,
    )):
        fca_record = {
            "entity_name": request.fca_entity_name,
            "reference": request.fca_reference,
            "action_type": request.fca_action_type,
            "date": request.fca_date,
            "summary": request.fca_summary,
            "source_url": request.fca_source_url,
        }

    return build_regulator_response(request.query, sec_records, fca_record, sec_error)
