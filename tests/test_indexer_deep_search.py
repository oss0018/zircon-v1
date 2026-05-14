import asyncio

from app.services import indexer


def test_index_deep_search_folder_indexes_text_files_only(tmp_path, monkeypatch):
    folder = tmp_path / "sample"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "a.txt").write_text("alpha", encoding="utf-8")
    (folder / "nested").mkdir()
    (folder / "nested" / "b.json").write_text('{"k":"v"}', encoding="utf-8")
    (folder / "nested" / "c.pdf").write_bytes(b"%PDF")

    monkeypatch.setattr(indexer, "extract_text", lambda path: "content")
    monkeypatch.setattr(indexer, "extract_text_streaming", lambda path: "content")

    captured = []

    def _capture_index_document(**kwargs):
        captured.append(kwargs)

    monkeypatch.setattr(indexer.search_engine, "index_document", _capture_index_document)

    indexed = asyncio.run(indexer.index_deep_search_folder(str(folder), "sample"))
    assert indexed == 2
    assert len(captured) == 2
    assert all(item["source"] == "deep_search" for item in captured)
    assert all(item["project"] == "sample" for item in captured)
    assert {item["path"] for item in captured} == {"sample/a.txt", "sample/nested/b.json"}


def test_deep_search_doc_id_normalizes_separators():
    assert indexer.deep_search_doc_id("folder\\file.txt") == "deep_search::folder/file.txt"
