"""
TS-DS-001 Phase 1 — Search engine service (PR 3/4).

Postgres FTS path : uses ds_chunks.fts_vector (GIN-indexed tsvector).
SQLite fallback   : LIKE-based content search (dev / CI only).

Backend detection is lazy-cached in the module-level ``_dialect`` variable so
callers can monkeypatch it in tests without re-initialising the DB.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import cast, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import DSChunk, DSFile, DSLeakRecord

logger = logging.getLogger(__name__)

# Module-level dialect cache.  None means "not yet detected".
# Tests monkeypatch this to "postgresql" to exercise the FTS path.
_dialect: str | None = None


# ── Dialect helpers ───────────────────────────────────────────────────────────

def _get_dialect(db: AsyncSession) -> str:
    global _dialect
    if _dialect is not None:
        return _dialect
    try:
        _dialect = db.sync_session.get_bind().dialect.name
    except Exception:
        try:
            _dialect = db.bind.dialect.name  # type: ignore[union-attr]
        except Exception:
            _dialect = "sqlite"
    return _dialect


# ── Dataclasses (service-layer shapes) ───────────────────────────────────────

@dataclass
class SearchFilters:
    source_ids: list[int] | None = None
    severity_min: int | None = None
    severity_max: int | None = None
    has_credentials: bool | None = None
    has_pii: bool | None = None
    has_api_keys: bool | None = None
    pattern_names: list[str] | None = None
    parse_mode: list[str] | None = None
    indexed_after: datetime | None = None
    indexed_before: datetime | None = None
    file_path_prefix: str | None = None


@dataclass
class SearchHit:
    chunk_id: int
    file_id: int
    source_id: int
    file_path: str
    chunk_index: int
    snippet: str
    rank: float
    file_severity_max: int | None
    file_has_credentials: bool
    file_has_pii: bool
    file_has_api_keys: bool
    file_pattern_names: list[str]
    file_indexed_at: datetime | None


@dataclass
class SearchResult:
    items: list[SearchHit]
    total: int
    page: int
    page_size: int
    has_next: bool


# ── Internal helpers ──────────────────────────────────────────────────────────

def _sqlite_escape(query: str) -> str:
    """Escape % and _ for LIKE pattern matching."""
    return query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _sqlite_snippet(content: str, query: str) -> str:
    """Return a highlighted snippet for the SQLite fallback path."""
    lower_c = content.lower()
    lower_q = query.lower()
    pos = lower_c.find(lower_q)
    if pos == -1:
        return content[:120] + ("…" if len(content) > 120 else "")
    start = max(0, pos - 60)
    end = min(len(content), pos + len(query) + 60)
    snippet = content[start:end]
    rel = pos - start
    return snippet[:rel] + "«" + snippet[rel: rel + len(query)] + "»" + snippet[rel + len(query):]


def _parse_pattern_names(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(v) for v in parsed]
        except Exception:
            pass
    return []


def _build_file_filters(filters: SearchFilters | None) -> list:
    """Return a list of SQLAlchemy column expressions for file-level WHERE clauses."""
    if not filters:
        return []
    conds: list = []
    if filters.source_ids:
        conds.append(DSFile.source_id.in_(filters.source_ids))
    if filters.severity_min is not None:
        conds.append(DSFile.severity_max >= filters.severity_min)
    if filters.severity_max is not None:
        conds.append(DSFile.severity_max <= filters.severity_max)
    if filters.has_credentials is not None:
        conds.append(DSFile.has_credentials == filters.has_credentials)
    if filters.has_pii is not None:
        conds.append(DSFile.has_pii == filters.has_pii)
    if filters.has_api_keys is not None:
        conds.append(DSFile.has_api_keys == filters.has_api_keys)
    if filters.parse_mode:
        conds.append(DSFile.parse_mode.in_(filters.parse_mode))
    if filters.indexed_after is not None:
        conds.append(DSFile.indexed_at >= filters.indexed_after)
    if filters.indexed_before is not None:
        conds.append(DSFile.indexed_at <= filters.indexed_before)
    if filters.file_path_prefix is not None:
        conds.append(DSFile.file_path.like(filters.file_path_prefix + "%"))
    return conds


def _build_pattern_names_filter(dialect: str, filters: SearchFilters | None):
    """Return a single SQLAlchemy expression for pattern_names filter, or None."""
    if not filters or not filters.pattern_names:
        return None
    if dialect == "postgresql":
        from sqlalchemy import Text
        from sqlalchemy.dialects.postgresql import ARRAY as PG_ARRAY
        return DSFile.pattern_names.op("&&")(
            cast(filters.pattern_names, PG_ARRAY(Text()))
        )
    # SQLite: naive INSTR check (acceptable for dev/CI — spec §1 guidance)
    from sqlalchemy import Text
    conds = [
        func.instr(cast(DSFile.pattern_names, Text()), pn) > 0
        for pn in filters.pattern_names
    ]
    return or_(*conds)


# ── Public service functions ──────────────────────────────────────────────────

async def search(
    db: AsyncSession,
    query: str,
    *,
    filters: SearchFilters | None = None,
    page: int = 1,
    page_size: int = 25,
) -> SearchResult:
    """Full-text search across ds_chunks with file-level filters."""
    if not query.strip():
        raise ValueError("query must not be empty")
    if len(query) > 512:
        raise ValueError("query too long")

    page = max(1, page)
    page_size = max(1, min(100, page_size))
    offset = (page - 1) * page_size

    dialect = _get_dialect(db)
    file_conds = _build_file_filters(filters)
    pn_filter = _build_pattern_names_filter(dialect, filters)
    if pn_filter is not None:
        file_conds.append(pn_filter)

    if dialect == "postgresql":
        fts_q = func.websearch_to_tsquery("simple", query)
        fts_cond = DSChunk.fts_vector.op("@@")(fts_q)
        rank_col = func.ts_rank_cd(DSChunk.fts_vector, fts_q).label("rank")
        snippet_col = func.ts_headline(
            "simple",
            DSChunk.content,
            fts_q,
            "StartSel=«, StopSel=», MaxFragments=2, MaxWords=20, MinWords=5",
        ).label("snippet")

        stmt = (
            select(
                DSChunk.id.label("chunk_id"),
                DSChunk.file_id,
                DSChunk.chunk_index,
                DSFile.source_id,
                DSFile.file_path,
                DSFile.severity_max.label("file_severity_max"),
                DSFile.has_credentials.label("file_has_credentials"),
                DSFile.has_pii.label("file_has_pii"),
                DSFile.has_api_keys.label("file_has_api_keys"),
                DSFile.pattern_names.label("file_pattern_names"),
                DSFile.indexed_at.label("file_indexed_at"),
                rank_col,
                snippet_col,
            )
            .join(DSFile, DSChunk.file_id == DSFile.id)
            .where(fts_cond, *file_conds)
            .order_by(rank_col.desc(), DSChunk.id.asc())
            .offset(offset)
            .limit(page_size)
        )
        count_stmt = (
            select(func.count())
            .select_from(DSChunk)
            .join(DSFile, DSChunk.file_id == DSFile.id)
            .where(fts_cond, *file_conds)
        )

        rows = (await db.execute(stmt)).mappings().all()
        total = (await db.execute(count_stmt)).scalar_one()

        items = [
            SearchHit(
                chunk_id=r["chunk_id"],
                file_id=r["file_id"],
                source_id=r["source_id"],
                file_path=r["file_path"],
                chunk_index=r["chunk_index"],
                snippet=r["snippet"] or "",
                rank=float(r["rank"]),
                file_severity_max=r["file_severity_max"],
                file_has_credentials=bool(r["file_has_credentials"]),
                file_has_pii=bool(r["file_has_pii"]),
                file_has_api_keys=bool(r["file_has_api_keys"]),
                file_pattern_names=_parse_pattern_names(r["file_pattern_names"]),
                file_indexed_at=r["file_indexed_at"],
            )
            for r in rows
        ]

    else:
        # SQLite LIKE fallback
        escaped = _sqlite_escape(query)
        like_pattern = f"%{escaped.lower()}%"
        fts_cond = func.lower(DSChunk.content).like(like_pattern)

        stmt = (
            select(
                DSChunk.id.label("chunk_id"),
                DSChunk.file_id,
                DSChunk.chunk_index,
                DSChunk.content.label("content"),
                DSFile.source_id,
                DSFile.file_path,
                DSFile.severity_max.label("file_severity_max"),
                DSFile.has_credentials.label("file_has_credentials"),
                DSFile.has_pii.label("file_has_pii"),
                DSFile.has_api_keys.label("file_has_api_keys"),
                DSFile.pattern_names.label("file_pattern_names"),
                DSFile.indexed_at.label("file_indexed_at"),
            )
            .join(DSFile, DSChunk.file_id == DSFile.id)
            .where(fts_cond, *file_conds)
            .order_by(DSChunk.id.asc())
            .offset(offset)
            .limit(page_size)
        )
        count_stmt = (
            select(func.count())
            .select_from(DSChunk)
            .join(DSFile, DSChunk.file_id == DSFile.id)
            .where(fts_cond, *file_conds)
        )

        rows = (await db.execute(stmt)).mappings().all()
        total = (await db.execute(count_stmt)).scalar_one()

        items = [
            SearchHit(
                chunk_id=r["chunk_id"],
                file_id=r["file_id"],
                source_id=r["source_id"],
                file_path=r["file_path"],
                chunk_index=r["chunk_index"],
                snippet=_sqlite_snippet(r["content"], query),
                rank=1.0,
                file_severity_max=r["file_severity_max"],
                file_has_credentials=bool(r["file_has_credentials"]),
                file_has_pii=bool(r["file_has_pii"]),
                file_has_api_keys=bool(r["file_has_api_keys"]),
                file_pattern_names=_parse_pattern_names(r["file_pattern_names"]),
                file_indexed_at=r["file_indexed_at"],
            )
            for r in rows
        ]

    return SearchResult(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(page * page_size) < total,
    )


async def get_file_detail(
    db: AsyncSession,
    file_id: int,
    *,
    chunk_preview: int = 5,
) -> dict | None:
    """Return one ds_files row + leak roll-up summary + first N chunk previews."""
    file_row = (
        await db.execute(select(DSFile).where(DSFile.id == file_id))
    ).scalar_one_or_none()
    if file_row is None:
        return None

    # Aggregate leaks
    leak_rows = (
        await db.execute(
            select(DSLeakRecord.pattern_name, DSLeakRecord.category)
            .where(DSLeakRecord.file_id == file_id)
        )
    ).all()

    by_pattern: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for row in leak_rows:
        by_pattern[row.pattern_name] = by_pattern.get(row.pattern_name, 0) + 1
        by_category[row.category] = by_category.get(row.category, 0) + 1

    # First N chunks
    n = max(0, min(chunk_preview, 20))
    chunk_rows = (
        await db.execute(
            select(DSChunk)
            .where(DSChunk.file_id == file_id)
            .order_by(DSChunk.chunk_index.asc())
            .limit(n)
        )
    ).scalars().all()

    # Build file dict from ORM row
    file_dict: dict[str, Any] = {
        col.key: getattr(file_row, col.key)
        for col in DSFile.__table__.columns
    }
    # Normalise pattern_names for JSON serialisation
    file_dict["pattern_names"] = _parse_pattern_names(file_dict.get("pattern_names"))

    return {
        "file": file_dict,
        "leak_summary": {
            "total": file_row.leak_count,
            "severity_max": file_row.severity_max,
            "by_pattern": by_pattern,
            "by_category": by_category,
        },
        "chunks_preview": [
            {
                "chunk_id": c.id,
                "chunk_index": c.chunk_index,
                "snippet": c.content[:200],
                "start_offset": c.start_offset,
                "end_offset": c.end_offset,
            }
            for c in chunk_rows
        ],
    }


async def list_chunks_for_file(
    db: AsyncSession,
    file_id: int,
    *,
    offset: int = 0,
    limit: int = 50,
) -> dict:
    """Paginated chunk listing for a single file. Returns {items, total, has_next}."""
    limit = max(1, min(200, limit))

    file_row = (
        await db.execute(select(DSFile).where(DSFile.id == file_id))
    ).scalar_one_or_none()
    if file_row is None:
        return {"items": [], "total": 0, "has_next": False}

    total = (
        await db.execute(
            select(func.count())
            .select_from(DSChunk)
            .where(DSChunk.file_id == file_id)
        )
    ).scalar_one()

    chunk_rows = (
        await db.execute(
            select(DSChunk)
            .where(DSChunk.file_id == file_id)
            .order_by(DSChunk.chunk_index.asc())
            .offset(offset)
            .limit(limit)
        )
    ).scalars().all()

    return {
        "items": [
            {
                "chunk_id": c.id,
                "chunk_index": c.chunk_index,
                "content": c.content,
                "start_offset": c.start_offset,
                "end_offset": c.end_offset,
            }
            for c in chunk_rows
        ],
        "total": total,
        "has_next": (offset + limit) < total,
    }


async def list_leaks(
    db: AsyncSession,
    *,
    filters: SearchFilters | None = None,
    page: int = 1,
    page_size: int = 25,
    category: str | None = None,
    severity_min: int | None = None,
    detected_after: datetime | None = None,
    detected_before: datetime | None = None,
) -> dict:
    """Flat ds_leak_records listing with file-level and leak-level filters."""
    page = max(1, page)
    page_size = max(1, min(100, page_size))
    offset = (page - 1) * page_size

    conds: list = []

    if filters:
        if filters.source_ids:
            conds.append(DSFile.source_id.in_(filters.source_ids))
        if filters.has_credentials is not None:
            conds.append(DSFile.has_credentials == filters.has_credentials)
        if filters.has_pii is not None:
            conds.append(DSFile.has_pii == filters.has_pii)
        if filters.has_api_keys is not None:
            conds.append(DSFile.has_api_keys == filters.has_api_keys)
        if filters.file_path_prefix is not None:
            conds.append(DSFile.file_path.like(filters.file_path_prefix + "%"))
        if filters.pattern_names:
            conds.append(DSLeakRecord.pattern_name.in_(filters.pattern_names))

    if category is not None:
        conds.append(DSLeakRecord.category == category)

    # Leak-level severity_min takes precedence over file-level
    effective_sev = severity_min if severity_min is not None else (
        filters.severity_min if filters else None
    )
    if effective_sev is not None:
        conds.append(DSLeakRecord.severity >= effective_sev)

    if detected_after is not None:
        conds.append(DSLeakRecord.created_at >= detected_after)
    if detected_before is not None:
        conds.append(DSLeakRecord.created_at <= detected_before)

    stmt = (
        select(
            DSLeakRecord.id.label("leak_id"),
            DSLeakRecord.file_id,
            DSFile.file_path,
            DSFile.source_id,
            DSLeakRecord.pattern_name,
            DSLeakRecord.category,
            DSLeakRecord.severity,
            DSLeakRecord.matched_value_masked,
            DSLeakRecord.line_number,
            DSLeakRecord.context_before,
            DSLeakRecord.context_after,
            DSLeakRecord.email,
            DSLeakRecord.email_domain,
            DSLeakRecord.created_at.label("detected_at"),
        )
        .join(DSFile, DSLeakRecord.file_id == DSFile.id)
        .where(*conds)
        .order_by(DSLeakRecord.id.asc())
        .offset(offset)
        .limit(page_size)
    )
    count_stmt = (
        select(func.count())
        .select_from(DSLeakRecord)
        .join(DSFile, DSLeakRecord.file_id == DSFile.id)
        .where(*conds)
    )

    rows = (await db.execute(stmt)).mappings().all()
    total = (await db.execute(count_stmt)).scalar_one()

    items = [
        {
            "leak_id": r["leak_id"],
            "file_id": r["file_id"],
            "file_path": r["file_path"],
            "source_id": r["source_id"],
            "pattern_name": r["pattern_name"],
            "category": r["category"],
            "severity": r["severity"],
            "matched_value_masked": r["matched_value_masked"],
            "line_number": r["line_number"],
            "context_before": r["context_before"],
            "context_after": r["context_after"],
            "email": r["email"],
            "email_domain": r["email_domain"],
            "detected_at": r["detected_at"],
        }
        for r in rows
    ]

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_next": (page * page_size) < total,
    }
