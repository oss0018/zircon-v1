"""CVE search proxy — forwards requests to NIST NVD API v2."""
import httpx
from fastapi import APIRouter, Depends, Query

from app.api.auth import get_current_user
from app.models import User

router = APIRouter()
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_ALLOWED_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

_http_client = httpx.AsyncClient(timeout=30)


@router.get("/search")
async def search_cve(
    keyword: str = Query(None),
    cve_id: str = Query(None),
    severity: str = Query(None),
    limit: int = Query(20, ge=1, le=100),
    _: User = Depends(get_current_user),
):
    params: dict = {"resultsPerPage": limit}
    if cve_id:
        params["cveId"] = cve_id
    elif keyword:
        params["keywordSearch"] = keyword
    if severity and severity in _ALLOWED_SEVERITIES:
        params["cvssV3Severity"] = severity

    try:
        resp = await _http_client.get(NVD_BASE, params=params)
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {"error": f"NVD API returned {e.response.status_code}", "vulnerabilities": [], "totalResults": 0}
    except httpx.RequestError:
        return {"error": "Failed to connect to NVD API", "vulnerabilities": [], "totalResults": 0}
    except Exception:
        return {"error": "CVE search failed", "vulnerabilities": [], "totalResults": 0}
