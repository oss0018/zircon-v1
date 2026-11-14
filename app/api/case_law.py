"""Search public court opinions and judgments in the United States and United Kingdom."""
from fastapi import APIRouter, Depends, HTTPException

from app.api.auth import get_current_user
from app.config import settings
from app.models import User
from app.schemas import CaseLawSearchRequest
from app.services.case_law import CaseLawSourceError, search_case_law

router = APIRouter()


@router.post("/search")
async def search_cases(
    request: CaseLawSearchRequest,
    _: User = Depends(get_current_user),
):
    try:
        return await search_case_law(
            request.query,
            request.limit,
            settings.courtlistener_api_token,
        )
    except CaseLawSourceError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
