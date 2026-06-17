from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
INDEX_HTML = REPO_ROOT / "app" / "static" / "index.html"
DEEP_SEARCH_JS = REPO_ROOT / "app" / "static" / "js" / "deep_search.js"
DEEP_SEARCH_SPEC = REPO_ROOT / "docs" / "specs" / "TS_DeepSearch_v1.0.md"


def test_deep_search_query_ui_serializes_query_filters():
    js = DEEP_SEARCH_JS.read_text(encoding="utf-8")

    assert "async runQuery(page = 1)" in js
    assert "params.append('source_id', value)" in js
    assert "params.append('pattern_names', value)" in js
    assert "params.append('parse_mode', value)" in js
    assert "params.set('severity_min', String(this.filterSeverityMin))" in js
    assert "params.set('severity_max', String(this.filterSeverityMax))" in js
    assert "params.set('file_path_prefix', this.filterFilePathPrefix.trim())" in js
    assert "api.get(`/deep-search/query?${params.toString()}`)" in js


def test_deep_search_leak_ui_serializes_leak_filters():
    js = DEEP_SEARCH_JS.read_text(encoding="utf-8")

    assert "async loadLeaks(page = 1)" in js
    assert "params.set('category', this.leakCategory.trim())" in js
    assert "params.set('severity_min', String(this.filterSeverityMin))" in js
    assert "params.set('detected_after', detectedAfter)" in js
    assert "params.set('detected_before', detectedBefore)" in js
    assert "api.get(`/deep-search/leaks?${params.toString()}`)" in js


def test_open_file_switches_tabs_and_loads_file_endpoints():
    js = DEEP_SEARCH_JS.read_text(encoding="utf-8")

    assert "this.activeTab = 'file';" in js
    assert "await api.get(`/deep-search/files/${fileId}`)" in js
    assert "await this.loadFileChunks(fileId, 0);" in js
    assert "async loadFileChunks(fileId, offset = 0)" in js
    assert "api.get(" in js and "/deep-search/files/${numericFileId}/chunks?" in js


def test_index_renders_new_deep_search_tabs_and_actions():
    html = INDEX_HTML.read_text(encoding="utf-8")

    assert "Deep Search Query" in html
    assert "Leak Listing" in html
    assert "File metadata" in html
    assert "Open file" in html
    assert "Load more chunks" in html


def test_spec_documents_phase1_ui_completion():
    spec = DEEP_SEARCH_SPEC.read_text(encoding="utf-8")

    assert "### Phase 1 — UI (PR 4/4)" in spec
    assert "/api/v1/deep-search/query" in spec
    assert "/api/v1/deep-search/files/{file_id}/chunks" in spec
