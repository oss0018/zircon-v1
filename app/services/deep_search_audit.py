import json
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLogEntry


class DeepSearchAuditEvent(str, Enum):
    SEARCH_QUERY = "search.query"
    FILE_VIEW = "file.view"
    FILE_DOWNLOAD = "file.download"
    LEAK_VIEW_RAW = "leak.view_raw"
    SOURCE_CREDENTIALS_EDIT = "source.credentials_edit"
    SOURCE_CREATE = "source.create"
    SOURCE_DELETE = "source.delete"


async def audit_log(event: DeepSearchAuditEvent, user_id, details: dict, db: AsyncSession):
    entry = AuditLogEntry(
        actor_user_id=user_id,
        action=event.value,
        entity_type="deep_search",
        entity_id=details.get("source_id") if isinstance(details, dict) else None,
        new_value_json=json.dumps(details or {}, ensure_ascii=False),
        notes="deep-search",
    )
    db.add(entry)
