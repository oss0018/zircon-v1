import json
from enum import Enum

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLogEntry


class DeepSearchAuditEvent(str, Enum):
    SEARCH_QUERY = "search.query"
    FILE_VIEW = "file.view"
    FILE_DOWNLOAD = "file.download"
    LEAK_VIEW_RAW = "leak.view_raw"
    LEAK_DETECTED = "leak.detected"
    FILE_PATH_REJECTED = "file.path_rejected"
    FILE_INGESTED = "file.ingested"
    FILE_INGEST_ERROR = "file.ingest_error"
    SOURCE_CREDENTIALS_EDIT = "source.credentials_edit"
    SOURCE_CREATE = "source.create"
    SOURCE_DELETE = "source.delete"
    SOURCE_INGEST_TRIGGERED_MANUAL = "source.ingest_triggered_manual"
    SOURCE_INGEST_START = "source.ingest_start"
    SOURCE_INGEST_COMPLETE = "source.ingest_complete"
    SOURCE_INGEST_CREDENTIALS_ERROR = "source.ingest_credentials_error"


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
