from pathlib import Path

from app.schemas import StorageSourceOut
from app.services.connectors import APISourceConnector, LocalFSConnector, get_connector


def test_get_connector_supports_localfs_and_api():
    assert isinstance(get_connector("localfs", {"base_path": "."}), LocalFSConnector)
    assert isinstance(get_connector("api", {"base_url": "https://example.test/api"}), APISourceConnector)


def test_localfs_connector_lists_relative_paths(tmp_path):
    base = tmp_path / "source"
    nested = base / "nested"
    nested.mkdir(parents=True)
    (nested / "sample.txt").write_text("hello", encoding="utf-8")

    connector = LocalFSConnector({"base_path": str(base)})
    entries = list(connector.list_files())

    assert [entry.path for entry in entries] == ["nested/sample.txt"]


def test_search_page_includes_deep_search_option():
    html = Path("app/static/index.html").read_text(encoding="utf-8")
    js = Path("app/static/js/search.js").read_text(encoding="utf-8")
    assert '<option value="deep_search">Deep Search</option>' in html
    assert "this.source === 'deep_search' || this.source === 'all'" in js


def test_storage_sources_support_api_and_localfs_ui():
    js = Path("app/static/js/storage_sources.js").read_text(encoding="utf-8")
    assert "{ value: 'api',    label: 'API Source' }" in js
    assert "{ value: 'localfs', label: 'Local Filesystem' }" in js
    assert "Bearer Auth" in js


def test_storage_source_schema_exposes_last_run_error_message():
    payload = StorageSourceOut(
        id=1,
        name="Example",
        source_type="api",
        is_enabled=True,
        schedule="@hourly",
        max_file_size_mb=25,
        recursive=True,
        last_run_at=None,
        last_run_status="error",
        last_run_scanned=10,
        last_run_indexed=0,
        last_run_errors=1,
        last_run_error_msg="boom",
        created_at="2026-06-04T00:00:00Z",
        updated_at="2026-06-04T00:00:00Z",
    )
    assert payload.model_dump()["last_run_error_msg"] == "boom"


def test_deep_search_spec_reference_exists():
    assert Path("docs/specs/TS_DeepSearch_v1.0.md").exists()
