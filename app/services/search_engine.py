"""
Whoosh-based full-text search engine.
"""
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

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
    path=STORED(),
    indexed_at=DATETIME(stored=True),
)


class SearchEngine:
    def __init__(self):
        self._ix = None

    def init_index(self):
        idx_dir = Path(settings.whoosh_index_dir)
        idx_dir.mkdir(parents=True, exist_ok=True)
        if whoosh_index.exists_in(str(idx_dir)):
            self._ix = whoosh_index.open_dir(str(idx_dir))
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
            indexed_at=datetime.utcnow(),
        )
        writer.commit()

    def delete_document(self, doc_id: str):
        writer = self.ix.writer()
        writer.delete_by_term("id", doc_id)
        writer.commit()

    def search(self, query_str: str, limit: int = 50) -> List[Dict[str, Any]]:
        results = []
        with self.ix.searcher() as searcher:
            parser = MultifieldParser(["filename", "content"], self.ix.schema)
            try:
                query = parser.parse(query_str)
            except Exception:
                query = parser.parse(query_str.replace(":", " "))
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
