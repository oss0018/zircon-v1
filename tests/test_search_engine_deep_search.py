import shutil
from pathlib import Path

from app.config import settings
from app.services.search_engine import SearchEngine


def test_snippet_uses_query_context():
    engine = SearchEngine()
    text = "A" * 180 + "needle" + "B" * 180
    snippet = engine._build_snippet(text, "needle")
    assert "needle" in snippet
    assert snippet.startswith("…")
    assert snippet.endswith("…")


def test_search_filters_by_source_and_returns_source(tmp_path, monkeypatch):
    old_index_dir = settings.whoosh_index_dir
    index_dir = tmp_path / "whoosh"
    monkeypatch.setattr(settings, "whoosh_index_dir", str(index_dir))
    engine = SearchEngine()
    try:
        engine.index_document(
            doc_id="local-1",
            filename="local.txt",
            content="find me in local source",
            source="local",
            path="local.txt",
        )
        engine.index_document(
            doc_id="ds-1",
            filename="deep.txt",
            content="find me in deep source",
            source="deep_search",
            path="folder/deep.txt",
            project="folder",
        )
        hits = engine.search("find", source="deep_search", fuzzy=False)
        assert len(hits) == 1
        assert hits[0]["id"] == "ds-1"
        assert hits[0]["source"] == "deep_search"
    finally:
        monkeypatch.setattr(settings, "whoosh_index_dir", old_index_dir)
        if Path(index_dir).exists():
            shutil.rmtree(index_dir, ignore_errors=True)
