# Threat Intelligence (CTI) — Operator Guide

## Overview

This MVP implements TS-CTI-001 v1.0 foundational scope under `/api/v1/cti/` with:

- CTI data model tables (`cti_*`)
- STIX 2.1 persistence (`stix_json` on CTI entities)
- Collection task scaffolding (Celery + beat schedules)
- Indicator Feed API + CSV/STIX export with TLP controls
- Actor profile + actor IoC listing
- Sentinel match ingestion + KQL rule generation
- ATT&CK blind-spot state API

## Configuration

Populate `.env` from `.env.example` and set:

- `CTI_CELERY_BROKER_URL`, `CTI_CELERY_RESULT_BACKEND`
- `MAXMIND_GEOIP_DB_PATH`
- `VIRUSTOTAL_API_KEY`, `GREYNOISE_API_KEY`, `ABUSEIPDB_API_KEY`
- `SENTINEL_WORKSPACE_ID`, `SENTINEL_SHARED_KEY`

## Migrations / Upgrade

This repository uses runtime schema migration in `app/database.py`.

On first deploy:

1. Start the application once (or run `python start.py`) to trigger `init_db()`.
2. CTI tables and indexes are created via SQLAlchemy metadata.
3. Upgrade-safe CTI column migration runs in `_migrate_cti_schema`.

For ATT&CK seed data, ingest actor/technique rows through your CTI sync job and store STIX payloads in `stix_json`.

## Celery services

`docker-compose.yml` contains:

- `celery_cti`
- `cti_beat_scheduler`
- `cti_telegram_monitor`

## RBAC

CTI endpoint operations enforce role gates for `view`, `annotate`, `export`, and `manage`.
Export endpoints additionally enforce TLP permissions by role.
