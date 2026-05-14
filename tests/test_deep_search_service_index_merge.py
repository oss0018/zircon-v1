import asyncio

from app.config import settings
from app.services import deep_search_service


def test_search_deep_data_merges_index_and_grep_results(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "deep_search_dir", str(tmp_path))
    (tmp_path / "folder").mkdir(parents=True, exist_ok=True)

    grep_results = [
        {"file_path": "folder/a.txt", "file_name": "a.txt", "matches": [{"line": 1, "text": "alpha"}], "match_count": 1},
        {"file_path": "folder/b.txt", "file_name": "b.txt", "matches": [{"line": 1, "text": "beta"}], "match_count": 1},
    ]
    monkeypatch.setattr(deep_search_service, "_sync_search", lambda *args, **kwargs: (grep_results, 2))

    class _FakeSearchEngine:
        @staticmethod
        def search(*args, **kwargs):
            return [{
                "path": "folder/a.txt",
                "filename": "a.txt",
                "snippet": "alpha",
            }]

    monkeypatch.setattr("app.services.search_engine.search_engine", _FakeSearchEngine())

    results = asyncio.run(deep_search_service.search_deep_data("alpha", folder="folder", use_index=True, limit=10))
    paths = [item["file_path"] for item in results]
    assert paths.count("folder/a.txt") == 1
    assert "folder/b.txt" in paths
