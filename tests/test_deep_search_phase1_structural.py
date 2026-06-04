from pathlib import Path

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


def test_deep_search_spec_reference_exists():
    assert Path("docs/specs/TS_DeepSearch_v1.0.md").exists()
