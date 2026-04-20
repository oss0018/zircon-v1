"""
Whoosh-based full-text search engine.
"""
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any

import whoosh.qparser
from whoosh import index as whoosh_index
from whoosh.fields import Schema, TEXT, ID, DATETIME, STORED
from whoosh.qparser import MultifieldParser, QueryParser
from whoosh.writing import AsyncWriter

from app.config import settings

SCHEMA = Schema(
    id=ID(stored=True, unique=True),
    filename=TEXT(stored=True),
    content=TEXT(stored=False),
    file_type=ID(stored=True),
    project=TEXT(stored=True),
    path=TEXT(stored=True),
    indexed_at=DATETIME(stored=True),
)


class SearchEngine:
    def __init__(self):
        self._ix = None

    def init_index(self):
        idx_dir = Path(settings.whoosh_index_dir)
        idx_dir.mkdir(parents=True, exist_ok=True)
        if whoosh_index.exists_in(str(idx_dir)):
            try:
                ix = whoosh_index.open_dir(str(idx_dir))
                # Migrate index if path field is not TEXT (searchable)
                existing_path_field = ix.schema.fields().get("path")
                if not isinstance(existing_path_field, TEXT):
                    ix.close()
                    shutil.rmtree(str(idx_dir))
                    idx_dir.mkdir(parents=True, exist_ok=True)
                    self._ix = whoosh_index.create_in(str(idx_dir), SCHEMA)
                    print("[search_engine] Schema migrated: path field is now searchable")
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
                       file_type: str = "", project: str = "", path: str = ""):
        writer = AsyncWriter(self.ix)
        writer.update_document(
            id=doc_id,
            filename=filename,
            content=content or "",
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

    def search(self, query_str: str, limit: int = 50) -> List[Dict[str, Any]]:
        results = []
        with self.ix.searcher() as searcher:
            parser = MultifieldParser(["filename", "content", "path"], self.ix.schema)
            parser.add_plugin(whoosh.qparser.WildcardPlugin())
            # Auto-wrap simple queries with wildcards for substring search
            q_str = query_str.strip()
            if q_str and not any(op in q_str for op in ["AND", "OR", "NOT", '"', "*", "?"]):
                q_str = f"*{q_str}*"
            try:
                query = parser.parse(q_str)
            except Exception:
                try:
                    query = parser.parse(query_str.replace(":", " "))
                except Exception:
                    return results
            hits = searcher.search(query, limit=limit)
            for hit in hits:
                results.append({
                    "id": hit["id"],
                    "filename": hit.get("filename", ""),
                    "file_type": hit.get("file_type", ""),
                    "project": hit.get("project", ""),
                    "path": hit.get("path", ""),
                    "score": hit.score,
                })
        return results

    def get_doc_count(self) -> int:
        with self.ix.searcher() as s:
            return s.doc_count()


search_engine = SearchEngine()
