# TS-DS-001 v1.0 — Deep Search

This repository copy preserves the Deep Search technical specification reference requested in the issue discussion.

## Scope summary

- Rework the CSINT Deep Search module while preserving its integration with the platform Search module.
- Support storage connectors for S3, SFTP, WebDAV, Local FS, and generic API sources.
- Keep Deep Search browse, preview, indexing, and search flows available from the existing CSINT entry point.
- Preserve existing public URLs and compatibility where safe.

## Repository implementation notes

- Deep Search API routes live under `/api/v1/deep-search`.
- Unified platform search routes live under `/api/v1/search`.
- Storage source management routes live under `/api/v1/storage-sources`.
- The current implementation keeps the existing Whoosh-backed search path active and prepares configuration for optional Elasticsearch deployment.

## Operational notes

- Local staging is configured with `ZIRCON_DEEP_SEARCH_STAGING_DIR`.
- Optional Elasticsearch settings are exposed through:
  - `ZIRCON_ELASTICSEARCH_URL`
  - `ZIRCON_ELASTICSEARCH_USERNAME`
  - `ZIRCON_ELASTICSEARCH_PASSWORD`
- The compose mount used by the deep-search worker can be overridden with `DEEP_SEARCH_LOCAL_MOUNT`.
- Docker Compose includes Elasticsearch, Kibana, and a `celery_deepsearch` worker profile/service entry.

## Source of truth

The original TS-DS-001 v1.0 specification was supplied with the issue request. This checked-in copy exists so future contributors have an in-repo reference point alongside the current implementation.

### Phase 1 — Ingestion pipeline (PR 2/4)

- Entry point: `app/services/deep_search_ingestion.py::ingest_source(source_id, triggered_by, user_id, max_files)`.
- The pipeline runs crawl → credential load/decrypt → connector listing → up-to-date check → fetch/hash → parse → chunk → leak-scan → persist → source status update.
- `ds_sources.credentials` is populated only through the vault-backed ingestion path and continues to use `StorageCredentialVault`.
- If `ds_sources.credentials` is empty, the ingestion service falls back to the matching `storage_sources.config_encrypted` row, decrypts it, and mirrors the encrypted payload into `ds_sources.credentials`.
- Credential decryption failures fast-fail with `source.ingest_credentials_error` and the message `credential vault decryption failed — check DS_CREDENTIAL_KEK`.
- Chunking writes `ds_chunks` rows with 4,000-character windows, 200-character overlap, and stored `start_offset` / `end_offset`.
- Leak detection lives in `app/services/deep_search_patterns.py` and uses a static in-code pattern registry for:
  - API keys (`aws_access_key_id`, `aws_secret_access_key`, `github_pat`, `slack_token`, `google_api_key`)
  - Credentials (`private_key_pem`, `jwt`, `generic_password_assign`)
  - PII (`email_address`, `us_ssn`, `credit_card`)
- Matches persist to `ds_leak_records` with masked values plus extracted `password_plain`, `email`, and `email_domain` where applicable.
- File rollups are stored on `ds_files`: `leak_count`, `severity_max`, `has_credentials`, `has_pii`, `has_api_keys`, and `pattern_names`.
- New audit events: `source.ingest_triggered_manual`, `source.ingest_start`, `source.ingest_complete`, `source.ingest_credentials_error`, `file.path_rejected`, `file.ingested`, `file.ingest_error`, `leak.detected`.
- `leak.detected` is emitted once per file with rolled-up pattern/severity/count data to avoid audit-log spam.
- Scheduler behavior is parallel-run only: legacy `run_source_indexing` still runs unchanged, and Deep Search ingestion is additionally queued for sources mirrored into `ds_sources`.
- Manual triggering is available on `POST /api/v1/storage-sources/{source_id}/deep-ingest` for `sec_engineer` and `admin`.
- Background execution uses the existing Celery app/`celery_deepsearch` queue when a broker is configured; otherwise it falls back to `asyncio.create_task`.
- Relevant env vars:
  - `DS_CREDENTIAL_KEK` for vault decryption/encryption
  - `INGEST_MAX_RUN_SECONDS` for per-run wall-clock timeout (default `1800`)

### Phase 1 — Search engine (PR 3/4)

- Backend selection: Postgres FTS is preferred (`ds_chunks.fts_vector @@ websearch_to_tsquery('simple', ...)`). SQLite `LIKE`-based fallback is used for dev/CI. Detection is lazy-cached in `app/services/deep_search_search._dialect`.
- Entry point: `app/services/deep_search_search.py` — `search()`, `get_file_detail()`, `list_chunks_for_file()`, `list_leaks()`.
- Endpoints (all require role `sec_engineer`, `admin`, or `ti_analyst`):
  - `GET /api/v1/deep-search/query` — FTS search across ds_chunks; ranked results with snippet highlighting.
  - `GET /api/v1/deep-search/files/{file_id}` — File detail + leak roll-up + chunk preview.
  - `GET /api/v1/deep-search/files/{file_id}/chunks` — Paginated chunk listing for a file.
  - `GET /api/v1/deep-search/leaks` — Flat leak record listing with file-level and leak-level filters.
- Supported filters: `source_ids`, `severity_min`, `severity_max`, `has_credentials`, `has_pii`, `has_api_keys`, `pattern_names`, `parse_mode`, `indexed_after`, `indexed_before`, `file_path_prefix`.
- Audit events added: `search.query` (SEARCH_QUERY), `search.file_read` (SEARCH_FILE_READ), `search.leak_list_read` (SEARCH_LEAK_LIST_READ). Audit payloads never log raw filter values or full query strings (truncated to 128 chars).
- Elasticsearch wiring is deferred to a possible post-Phase-1 spike — `ZIRCON_ELASTICSEARCH_URL` env var is read but not yet consumed by this PR.
- Pydantic response schemas are defined in `app/schemas.py`: `SearchResponseSchema`, `FileDetailSchema`, `ChunkListSchema`, `LeakListSchema`.
- PR 4/4 will add the UI that consumes these endpoints; the legacy Whoosh `search_engine.search()` and `deep_search_service.search_deep_data()` paths remain for the existing CSINT Deep Search UI and will be deprecated by PR 4/4.

### Phase 1 — UI (PR 4/4)

- The SPA Deep Search page now consumes:
  - `/api/v1/deep-search/query`
  - `/api/v1/deep-search/files/{file_id}`
  - `/api/v1/deep-search/files/{file_id}/chunks`
  - `/api/v1/deep-search/leaks`
- The new Alpine-driven UI adds three API-backed tabs:
  - **Search** — full-text query over indexed chunks with compact file-level filters
  - **Leaks** — filtered leak record listing with masked values and file drill-down
  - **File** — file metadata, leak roll-up, chunk preview, and paginated chunk browsing
- The existing legacy Whoosh/tree/viewer path remains available behind the Deep Search component fallback mode for backward compatibility during rollout.
- Phase 1 MVP is complete after this PR: ingestion/storage (PR 2/4), query engine/API (PR 3/4), and frontend UI (PR 4/4) are all wired end-to-end.
