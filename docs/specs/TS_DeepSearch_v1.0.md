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
- Docker Compose includes Elasticsearch, Kibana, and a `celery_deepsearch` worker profile/service entry.

## Source of truth

The original TS-DS-001 v1.0 specification was supplied with the issue request. This checked-in copy exists so future contributors have an in-repo reference point alongside the current implementation.
