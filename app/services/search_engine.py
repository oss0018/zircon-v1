"""
Whoosh-based full-text search engine.
"""
import logging
import os
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

import whoosh.qparser
from whoosh import index as whoosh_index
from whoosh.analysis import RegexTokenizer, LowercaseFilter
from whoosh.fields import Schema, TEXT, ID, DATETIME, STORED
from whoosh.query import Term
from whoosh.qparser import MultifieldParser
from whoosh.writing import AsyncWriter

from app.config import settings

logger = logging.getLogger(__name__)

# Analyzer that handles both Cyrillic and Latin characters
_MULTILANG_WORD_RE = re.compile(r'[а-яёА-ЯЁa-zA-Z\d]+', re.UNICODE)
cyrillic_analyzer = RegexTokenizer(_MULTILANG_WORD_RE) | LowercaseFilter()

SCHEMA = Schema(
    id=ID(stored=True, unique=True),
    filename=TEXT(stored=True, analyzer=cyrillic_analyzer),
    content=TEXT(stored=False, analyzer=cyrillic_analyzer),
    content_raw=STORED(),
    source=ID(stored=True),
    file_type=ID(stored=True),
    project=TEXT(stored=True),
    path=TEXT(stored=True, analyzer=cyrillic_analyzer),
    indexed_at=DATETIME(stored=True),
)

# Operators that indicate a structured query (skip auto-wildcard/fuzzy wrapping)
_QUERY_OPERATORS = frozenset(["AND", "OR", "NOT", '"', "*", "?", "~"])

# Maximum content size to index (10 MB of text)
_MAX_CONTENT_CHARS = 10 * 1024 * 1024

# Characters stored in content_raw snippet
_CONTENT_RAW_MAXCHARS = 2000

_SNIPPET_CONTEXT_CHARS = 100

# Edit distance used for fuzzy term matching
_FUZZY_EDIT_DISTANCE = 1


class SearchEngine:
    def __init__(self):
        self._ix = None

    def init_index(self):
        idx_dir = Path(settings.whoosh_index_dir)
        idx_dir.mkdir(parents=True, exist_ok=True)
        if whoosh_index.exists_in(str(idx_dir)):
            try:
                ix = whoosh_index.open_dir(str(idx_dir))
                existing_fields = ix.schema.names()
                # Recreate index if schema fields changed (e.g. added content_raw or cyrillic_analyzer)
                needs_migration = (
                    "content_raw" not in existing_fields
                    or "source" not in existing_fields
                    or not isinstance(ix.schema.fields().get("path"), TEXT)
                )
                if needs_migration:
                    ix.close()
                    logger.warning(
                        "[search_engine] Schema changed. Recreating index — "
                        "all documents will need to be reindexed."
                    )
                    shutil.rmtree(str(idx_dir))
                    idx_dir.mkdir(parents=True, exist_ok=True)
                    self._ix = whoosh_index.create_in(str(idx_dir), SCHEMA)
                    logger.info("[search_engine] Schema migrated successfully")
                else:
                    self._ix = ix
            except Exception:
                self._ix = whoosh_index.create_in(str(idx_dir), SCHEMA)
        else:
            self._ix = whoosh_index.create_in(str(idx_dir), SCHEMA)

    @property
    def ix(self):
        if self._ix is None:
            self.init_index()
        return self._ix

    def index_document(self, doc_id: str, filename: str, content: str,
                       file_type: str = "", project: str = "", path: str = "",
                       source: str = "local"):
        # Normalize whitespace
        content = content or ""
        content = re.sub(r'[ \t]+', ' ', content)
        content = re.sub(r'\n{3,}', '\n\n', content)
        # Truncate very long content
        if len(content) > _MAX_CONTENT_CHARS:
            content = content[:_MAX_CONTENT_CHARS]
        content_raw = content[:_CONTENT_RAW_MAXCHARS]
        writer = AsyncWriter(self.ix)
        writer.update_document(
            id=doc_id,
            filename=filename,
            content=content,
            content_raw=content_raw,
            source=source,
            file_type=file_type,
            project=project,
            path=path,
            indexed_at=datetime.now(timezone.utc),
        )
        writer.commit()

    def delete_document(self, doc_id: str):
        writer = self.ix.writer()
        writer.delete_by_term("id", doc_id)
        writer.commit()

    def _build_snippet(self, content_raw: str, query_str: str) -> str:
        content_raw = content_raw or ""
        if not content_raw:
            return ""
        query_norm = (query_str or "").strip().lower()
        search_candidates: List[str] = []
        if query_norm:
            search_candidates.append(query_norm)
            search_candidates.extend([term for term in query_norm.split() if term and term not in search_candidates])
        lower_content = content_raw.lower()
        match_idx = -1
        match_len = 0
        for candidate in search_candidates:
            idx = lower_content.find(candidate)
            if idx >= 0:
                match_idx = idx
                match_len = len(candidate)
                break

        if match_idx < 0:
            snippet = content_raw[: _SNIPPET_CONTEXT_CHARS * 2]
            return snippet + ("…" if len(content_raw) > len(snippet) else "")

        start = max(0, match_idx - _SNIPPET_CONTEXT_CHARS)
        end = min(len(content_raw), match_idx + max(match_len, 1) + _SNIPPET_CONTEXT_CHARS)
        snippet = content_raw[start:end]
        if start > 0:
            snippet = "…" + snippet
        if end < len(content_raw):
            snippet = snippet + "…"
        return snippet

    def search(self, query_str: str, limit: int = 50, offset: int = 0,
               fuzzy: bool = True, fields: Optional[List[str]] = None,
               source: Optional[str] = None) -> List[Dict[str, Any]]:
        results = []
        with self.ix.searcher() as searcher:
            search_fields = fields or ["filename", "content", "path"]
            parser = MultifieldParser(search_fields, self.ix.schema)
            parser.add_plugin(whoosh.qparser.WildcardPlugin())
            if fuzzy:
                parser.add_plugin(whoosh.qparser.FuzzyTermPlugin())
            q_str = query_str.strip()
            is_simple = q_str and not any(op in q_str for op in _QUERY_OPERATORS)
            if is_simple:
                if fuzzy and len(q_str) < 20:
                    # Fuzzy search: append ~{distance} to each term
                    fuzzy_terms = " ".join(f"{t}~{_FUZZY_EDIT_DISTANCE}" for t in q_str.split())
                    q_str = fuzzy_terms
                else:
                    # Substring wildcard search
                    q_str = f"*{q_str}*"
            try:
                query = parser.parse(q_str)
            except Exception:
                try:
                    query = parser.parse(query_str.replace(":", " "))
                except Exception:
                    return results
            source_filter = Term("source", source) if source else None
            hits = searcher.search(query, limit=offset + limit, filter=source_filter)
            for hit in list(hits)[offset:offset + limit]:
                content_raw = hit.get("content_raw", "") or ""
                snippet = self._build_snippet(content_raw, query_str)
                results.append({
                    "id": hit["id"],
                    "filename": hit.get("filename", ""),
                    "source": hit.get("source", ""),
                    "file_type": hit.get("file_type", ""),
                    "project": hit.get("project", ""),
                    "path": hit.get("path", ""),
                    "score": hit.score,
                    "snippet": snippet,
                })
        return results

    def get_doc_count(self) -> int:
        with self.ix.searcher() as s:
            return s.doc_count()


search_engine = SearchEngine()
