"""Read-only search of the official NACP declaration register."""
from datetime import datetime, timezone
from uuid import UUID

import httpx


NAZK_API = "https://public-api.nazk.gov.ua/v2/documents/list"
NAZK_DOCUMENTS = "https://public.nazk.gov.ua/documents/"


class NazkSourceError(Exception):
    """The NACP register could not be searched."""


def _text(value):
    return value.strip() if isinstance(value, str) and value.strip() else None


async def search_declarations(query: str | None, workplace_edrpou: str | None, page: int,
                              declarant_id: int | None = None) -> dict:
    params = {"page": page}
    if query:
        params["query"] = query
    if workplace_edrpou:
        params["workPlaceEdrpou"] = workplace_edrpou
    if declarant_id:
        params["user_declarant_id"] = declarant_id
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
            response = await client.get(NAZK_API, params=params, headers={"Accept": "application/json"})
        response.raise_for_status()
        payload = response.json()
    except httpx.HTTPStatusError as exc:
        raise NazkSourceError(f"NACP register returned HTTP {exc.response.status_code}") from exc
    except httpx.RequestError as exc:
        raise NazkSourceError("Could not connect to the NACP register") from exc
    except ValueError as exc:
        raise NazkSourceError("NACP register returned invalid JSON") from exc

    if not isinstance(payload, dict):
        raise NazkSourceError("NACP register returned an unexpected response")
    if "error" in payload:
        raise NazkSourceError(f"NACP register returned an API error: {payload['error']}")
    if not isinstance(payload.get("data"), list) or type(payload.get("count")) is not int or payload["count"] < 0:
        raise NazkSourceError("NACP register returned an unexpected response")

    records = []
    for item in payload["data"]:
        if not isinstance(item, dict):
            raise NazkSourceError("NACP register returned an invalid record")
        try:
            document_id = str(UUID(item["id"]))
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            raise NazkSourceError("NACP register returned an invalid document ID") from exc
        data = item.get("data")
        step = data.get("step_1") if isinstance(data, dict) else None
        person = step.get("data") if isinstance(step, dict) else None
        person = person if isinstance(person, dict) else {}
        name = " ".join(filter(None, (_text(person.get(k)) for k in ("lastname", "firstname", "middlename"))))
        records.append({
            "id": document_id,
            "declarant_id": item.get("user_declarant_id") if type(item.get("user_declarant_id")) is int and 1 <= item["user_declarant_id"] <= 10000000 else None,
            "name": name or None,
            "workplace": _text(person.get("workPlace")),
            "position": _text(person.get("workPost")),
            "document_type": item.get("type"),
            "declaration_type": item.get("declaration_type"),
            "declaration_year": item.get("declaration_year"),
            "submitted_at": _text(item.get("date")),
            "source_url": NAZK_DOCUMENTS + document_id,
        })
    return {
        "results": records,
        "count": payload["count"],
        "page": page,
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }
