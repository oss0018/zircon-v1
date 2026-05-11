import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import (
    Brand,
    BrandAlert,
    Integration,
    MonitoringFinding,
    MonitoringJob,
    MonitoringRun,
    StorageSource,
    WatchlistItem,
)
from app.services.crypto import decrypt
from app.services.osint import get_client
from app.services.search_engine import search_engine

DEFAULT_MONITORING_CONFIG = {
    "schema_version": 2,
    "targets": [],
    "exclusions": [],
    "checks": {
        "folder_scan": {
            "enabled": False,
            "storage_source_ids": [],
            "path_prefixes": [],
        },
        "osint_check": {
            "enabled": False,
            "integration_ids": [],
            "advanced_options": {},
        },
        "watchlist_check": {
            "enabled": False,
            "watchlist_item_ids": [],
            "matching_mode": "contains",
        },
        "brand_scan": {
            "enabled": False,
            "brand_ids": [],
        },
    },
}

OSINT_SUMMARY_MAX_CHARS = 500
RUN_ERROR_MAX_CHARS = 500
FOLDER_SCAN_QUERY_LIMIT = 25
BRAND_SCAN_ALERT_LIMIT = 25


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _looks_like_domain(value: str) -> bool:
    text = (value or "").strip().lower()
    if not text or len(text) > 253 or "." not in text:
        return False

    labels = text.split(".")
    tld = labels[-1]
    if len(tld) < 2 or not tld.isalpha():
        return False

    for label in labels:
        if not label or len(label) > 63:
            return False
        if not label[0].isalnum() or not label[-1].isalnum():
            return False
        if any(not (char.isalnum() or char == "-") for char in label):
            return False

    return True


def _looks_like_email(value: str) -> bool:
    text = (value or "").strip()
    if "@" not in text or text.count("@") != 1:
        return False
    local_part, domain = text.split("@", 1)
    return bool(local_part) and _looks_like_domain(domain)


def _json_load(value: Any, default: Any) -> Any:
    if isinstance(value, (dict, list)):
        return value
    if not value:
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def infer_target_type(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return "keyword"
    if text.startswith("@"):
        return "account"
    if _looks_like_email(text):
        return "email"
    if text.lower().startswith(("http://", "https://")):
        return "url"
    if _looks_like_domain(text):
        return "domain"
    return "keyword"


def normalize_targets(raw_targets: list[Any], exclusions: Optional[list[str]] = None) -> list[dict[str, str]]:
    excluded = {(item or "").strip().lower() for item in (exclusions or []) if (item or "").strip()}
    normalized: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for raw in raw_targets or []:
        if isinstance(raw, dict):
            value = (raw.get("value") or "").strip()
            target_type = (raw.get("type") or infer_target_type(value)).strip().lower()
        else:
            value = str(raw or "").strip()
            target_type = infer_target_type(value)

        if not value or value.lower() in excluded:
            continue

        key = (target_type, value.lower())
        if key in seen:
            continue
        seen.add(key)
        normalized.append({"type": target_type, "value": value})

    return normalized


def normalize_monitoring_config(job_type: str, config_json: Any) -> dict[str, Any]:
    raw = _json_load(config_json, {})
    config = json.loads(json.dumps(DEFAULT_MONITORING_CONFIG))

    if raw.get("checks"):
        config["checks"].update(raw.get("checks", {}))
    if raw.get("schema_version"):
        config["schema_version"] = raw.get("schema_version")

    raw_exclusions = raw.get("exclusions") or raw.get("exclude") or []
    if isinstance(raw_exclusions, str):
        raw_exclusions = [line.strip() for line in raw_exclusions.splitlines()]
    config["exclusions"] = [item for item in raw_exclusions if item]

    raw_targets = raw.get("targets") or []
    if not raw_targets:
        legacy_target = raw.get("target") or raw.get("query") or raw.get("keyword")
        if legacy_target:
            raw_targets = [legacy_target]

    config["targets"] = normalize_targets(raw_targets, config["exclusions"])

    checks = config["checks"]
    legacy_type = (job_type or "").strip().lower()

    if legacy_type == "folder_scan":
        checks["folder_scan"]["enabled"] = True
        if raw.get("storage_source_ids"):
            checks["folder_scan"]["storage_source_ids"] = raw.get("storage_source_ids", [])
        if raw.get("path_prefixes"):
            checks["folder_scan"]["path_prefixes"] = raw.get("path_prefixes", [])
        if raw.get("folder"):
            checks["folder_scan"]["legacy_folder"] = raw.get("folder")
    elif legacy_type == "osint_check":
        checks["osint_check"]["enabled"] = True
        checks["osint_check"]["integration_ids"] = raw.get("integration_ids") or raw.get("integrations") or []
    elif legacy_type == "watchlist_check":
        checks["watchlist_check"]["enabled"] = True
        checks["watchlist_check"]["watchlist_item_ids"] = raw.get("watchlist_item_ids") or []
        checks["watchlist_check"]["matching_mode"] = raw.get("matching_mode") or "contains"
    elif legacy_type == "brand_scan":
        checks["brand_scan"]["enabled"] = True
        checks["brand_scan"]["brand_ids"] = raw.get("brand_ids") or []

    return config


def serialize_monitoring_config(config: dict[str, Any]) -> str:
    normalized = normalize_monitoring_config("unified", config)
    return json.dumps(normalized, ensure_ascii=False)


def calculate_next_run(schedule: str, from_dt: Optional[datetime] = None) -> Optional[datetime]:
    base = from_dt or _utcnow()
    normalized = (schedule or "manual").strip().lower()

    if normalized in {"", "manual", "disabled"}:
        return None
    if normalized in {"hourly", "@hourly", "0 * * * *"}:
        return base + timedelta(hours=1)
    if normalized in {"daily", "@daily", "0 0 * * *"}:
        return base + timedelta(days=1)

    parts = normalized.split()
    if parts:
        match = re.match(r"\*/(\d+)$", parts[0])
        if match:
            return base + timedelta(minutes=max(int(match.group(1)), 1))

    return base + timedelta(hours=1)


def is_monitoring_job_due(job: MonitoringJob, now: Optional[datetime] = None) -> bool:
    if not job.is_active:
        return False

    schedule = (job.schedule or "manual").strip().lower()
    if schedule in {"", "manual", "disabled"}:
        return False

    current = now or _utcnow()
    if job.last_run is None:
        return True

    next_run = job.next_run or calculate_next_run(job.schedule, job.last_run)
    return bool(next_run and next_run <= current)


async def list_monitoring_options(db: AsyncSession) -> dict[str, Any]:
    storage_sources = (
        await db.execute(select(StorageSource).order_by(StorageSource.name.asc()))
    ).scalars().all()
    integrations = (
        await db.execute(select(Integration).order_by(Integration.name.asc()))
    ).scalars().all()
    watchlist_items = (
        await db.execute(select(WatchlistItem).order_by(WatchlistItem.value.asc()))
    ).scalars().all()
    brands = (
        await db.execute(select(Brand).order_by(Brand.name.asc()))
    ).scalars().all()

    return {
        "storage_sources": [
            {"id": src.id, "name": src.name, "is_enabled": src.is_enabled}
            for src in storage_sources
        ],
        "integrations": [
            {
                "id": item.id,
                "name": item.name,
                "service_type": item.service_type,
                "is_active": item.is_active,
            }
            for item in integrations
        ],
        "watchlist_items": [
            {"id": item.id, "type": item.type, "value": item.value}
            for item in watchlist_items
        ],
        "brands": [
            {"id": brand.id, "name": brand.name, "url": brand.url}
            for brand in brands
        ],
    }


def _target_query_type(target: dict[str, str], override: Optional[str] = None) -> str:
    if override:
        return str(override).strip().lower()
    target_type = (target.get("type") or "general").lower()
    if target_type in {"domain", "email", "url"}:
        return target_type
    if target_type == "account":
        return "general"
    return "general"


def _extract_osint_summary(result: dict[str, Any]) -> tuple[str, str]:
    interesting = {k: v for k, v in result.items() if k not in {"cached"}}
    summary = json.dumps(interesting, ensure_ascii=False)[:OSINT_SUMMARY_MAX_CHARS]
    object_ref = ""

    for key in ("url", "domain", "host", "ip", "selectorvalue"):
        if interesting.get(key):
            object_ref = str(interesting.get(key))
            break
    if not object_ref:
        for key in ("records", "results", "selectors"):
            value = interesting.get(key)
            if isinstance(value, list) and value:
                object_ref = str(value[0])[:200]
                break

    return summary, object_ref


def _has_osint_finding(result: dict[str, Any]) -> bool:
    if not result or result.get("error") or result.get("not_found"):
        return False
    for key, value in result.items():
        if key == "cached":
            continue
        if value not in (None, "", [], {}, False):
            return True
    return False


def _make_fingerprint(check_type: str, matched_target: str, source: str, evidence_key: str) -> str:
    raw = f"{check_type}|{matched_target}|{source}|{evidence_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:64]


async def _load_watchlist_targets(db: AsyncSession, check_cfg: dict[str, Any]) -> list[dict[str, str]]:
    item_ids = [int(item) for item in check_cfg.get("watchlist_item_ids", []) if str(item).strip().isdigit()]
    stmt = select(WatchlistItem)
    if item_ids:
        stmt = stmt.where(WatchlistItem.id.in_(item_ids))
    items = (await db.execute(stmt.order_by(WatchlistItem.value.asc()))).scalars().all()
    return normalize_targets([{"type": item.type, "value": item.value} for item in items])


def _merge_targets(primary_targets: list[dict[str, str]], extra_targets: list[dict[str, str]]) -> list[dict[str, str]]:
    return normalize_targets(primary_targets + extra_targets)


async def _run_folder_scan(
    db: AsyncSession,
    targets: list[dict[str, str]],
    exclusions: list[str],
    check_cfg: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []

    source_ids = [int(item) for item in check_cfg.get("storage_source_ids", []) if str(item).strip().isdigit()]
    if source_ids:
        stmt = select(StorageSource).where(StorageSource.id.in_(source_ids))
    else:
        stmt = select(StorageSource).where(StorageSource.is_enabled.is_(True))
    sources = (await db.execute(stmt.order_by(StorageSource.name.asc()))).scalars().all()
    source_map = {src.id: src.name for src in sources}
    allowed_ids = set(source_map)

    if not allowed_ids:
        warnings.append("Folder Scan has no enabled Local Index sources configured.")
        return findings, warnings

    legacy_folder = (check_cfg.get("legacy_folder") or "").strip()
    if legacy_folder:
        warnings.append("Direct folder paths are deprecated. Folder Scan now uses Local Index storage sources only.")

    path_prefixes = [item.strip() for item in check_cfg.get("path_prefixes", []) if str(item).strip()]
    excluded_terms = [item.lower() for item in exclusions if item]

    for target in targets:
        query_value = target["value"]
        query_terms = [term for term in re.split(r"[^a-zA-Z0-9]+", query_value.lower()) if term]
        if not query_terms:
            query_terms = [query_value.lower()]

        raw_hits = []
        for term in dict.fromkeys(query_terms):
            raw_hits.extend(
                search_engine.search(
                    term,
                    limit=FOLDER_SCAN_QUERY_LIMIT,
                    offset=0,
                    fuzzy=False,
                    fields=["content"],
                )
            )

        deduped_hits = {}
        for hit in raw_hits:
            dedupe_key = f"{hit.get('project')}::{hit.get('path')}::{hit.get('filename')}"
            deduped_hits[dedupe_key] = hit

        for hit in deduped_hits.values():
            project = str(hit.get("project") or "")
            if not project.startswith("storage_source_"):
                continue
            try:
                source_id = int(project.split("_")[-1])
            except Exception:
                continue
            if source_id not in allowed_ids:
                continue

            path = str(hit.get("path") or "")
            if path_prefixes and not any(path.startswith(prefix) for prefix in path_prefixes):
                continue
            snippet = str(hit.get("snippet") or "")
            haystack = f"{path} {snippet}".lower()
            if not all(term in haystack for term in query_terms):
                continue
            if any(term in haystack for term in excluded_terms):
                continue

            source = f"storage_source:{source_id}"
            evidence_key = path or hit.get("filename") or query_value
            findings.append(
                {
                    "check_type": "folder_scan",
                    "matched_target": query_value,
                    "source": source,
                    "fingerprint": _make_fingerprint("folder_scan", query_value, source, str(evidence_key)),
                    "evidence": {
                        "source_id": source_id,
                        "source_name": source_map.get(source_id, source),
                        "path": path,
                        "filename": hit.get("filename", ""),
                        "snippet": snippet,
                    },
                }
            )

    return findings, warnings


async def _run_osint_check(
    db: AsyncSession,
    targets: list[dict[str, str]],
    check_cfg: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []

    integration_ids = [int(item) for item in check_cfg.get("integration_ids", []) if str(item).strip().isdigit()]
    if integration_ids:
        stmt = select(Integration).where(Integration.id.in_(integration_ids))
    else:
        stmt = select(Integration).where(Integration.is_active.is_(True))
    integrations = (await db.execute(stmt.order_by(Integration.name.asc()))).scalars().all()

    if not integrations:
        warnings.append("OSINT Check has no configured integrations.")
        return findings, warnings

    advanced_options = check_cfg.get("advanced_options") or {}

    for integration in integrations:
        client = get_client(
            integration.service_type,
            decrypt(integration.api_key_encrypted),
            base_url=integration.base_url or "",
        )
        if client is None:
            continue

        per_source_options = advanced_options.get(str(integration.id)) or advanced_options.get(integration.service_type) or {}

        for target in targets:
            query_type = _target_query_type(target, per_source_options.get("query_type"))
            result = await client.search(target["value"], query_type)
            if not _has_osint_finding(result):
                continue

            summary, object_ref = _extract_osint_summary(result)
            source = f"integration:{integration.id}"
            evidence_key = object_ref or target["value"]
            findings.append(
                {
                    "check_type": "osint_check",
                    "matched_target": target["value"],
                    "source": source,
                    "fingerprint": _make_fingerprint("osint_check", target["value"], source, evidence_key),
                    "evidence": {
                        "integration_id": integration.id,
                        "integration_name": integration.name,
                        "service_type": integration.service_type,
                        "object": object_ref,
                        "summary": summary,
                    },
                }
            )

    return findings, warnings


async def _run_watchlist_check(
    db: AsyncSession,
    direct_targets: list[dict[str, str]],
    check_cfg: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, str]]]:
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []
    watchlist_targets = await _load_watchlist_targets(db, check_cfg)

    if not watchlist_targets:
        warnings.append("Watchlist Check has no selected watchlist items.")
        return findings, warnings, []

    mode = (check_cfg.get("matching_mode") or "contains").strip().lower()

    for item in watchlist_targets:
        item_value = item["value"].lower()
        for target in direct_targets:
            target_value = target["value"].lower()
            if mode == "exact":
                matched = item_value == target_value
            else:
                matched = item_value in target_value or target_value in item_value
            if not matched:
                continue

            source = f"watchlist:{item['type']}"
            findings.append(
                {
                    "check_type": "watchlist_check",
                    "matched_target": target["value"],
                    "source": source,
                    "fingerprint": _make_fingerprint("watchlist_check", target["value"], source, item["value"]),
                    "evidence": {
                        "watchlist_type": item["type"],
                        "watchlist_value": item["value"],
                        "matching_mode": mode,
                        "summary": f"Matched watchlist value '{item['value']}'",
                    },
                }
            )

    return findings, warnings, watchlist_targets


async def _run_brand_scan(
    db: AsyncSession,
    targets: list[dict[str, str]],
    check_cfg: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[str]]:
    warnings: list[str] = []
    findings: list[dict[str, Any]] = []

    brand_ids = [int(item) for item in check_cfg.get("brand_ids", []) if str(item).strip().isdigit()]
    if brand_ids:
        brand_stmt = select(Brand).where(Brand.id.in_(brand_ids))
    else:
        brand_stmt = select(Brand).where(Brand.monitoring_enabled.is_(True))
    brands = (await db.execute(brand_stmt.order_by(Brand.name.asc()))).scalars().all()

    if not brands:
        warnings.append("Brand Scan has no selected brand profiles.")
        return findings, warnings

    target_terms = [item["value"].lower() for item in targets]

    for brand in brands:
        alerts = (
            await db.execute(
                select(BrandAlert)
                .where(BrandAlert.brand_id == brand.id)
                .order_by(desc(BrandAlert.checked_at), desc(BrandAlert.created_at))
                .limit(BRAND_SCAN_ALERT_LIMIT)
            )
        ).scalars().all()

        for alert in alerts:
            candidate = (alert.similar_domain or "").strip()
            if target_terms and candidate:
                candidate_lc = candidate.lower()
                if not any(term in candidate_lc or candidate_lc in term for term in target_terms):
                    continue

            source = f"brand:{brand.id}"
            evidence_key = candidate or str(alert.id)
            details = _json_load(alert.details_json, {})
            findings.append(
                {
                    "check_type": "brand_scan",
                    "matched_target": brand.name,
                    "source": source,
                    "fingerprint": _make_fingerprint("brand_scan", brand.name, source, evidence_key),
                    "evidence": {
                        "brand_id": brand.id,
                        "brand_name": brand.name,
                        "domain": alert.similar_domain,
                        "ip": alert.ip,
                        "alive": alert.alive,
                        "page_title": alert.page_title,
                        "similarity_pct": alert.similarity_pct or alert.similarity_score,
                        "summary": details or {"source": alert.source},
                    },
                }
            )

    return findings, warnings


async def _upsert_finding(
    db: AsyncSession,
    job_id: int,
    run_id: int,
    finding: dict[str, Any],
) -> MonitoringFinding:
    now = _utcnow()
    fingerprint = finding["fingerprint"]

    existing = (
        await db.execute(
            select(MonitoringFinding).where(
                MonitoringFinding.job_id == job_id,
                MonitoringFinding.fingerprint == fingerprint,
            )
        )
    ).scalar_one_or_none()

    evidence_json = json.dumps(finding.get("evidence", {}), ensure_ascii=False)

    if existing:
        existing.run_id = run_id
        existing.check_type = finding["check_type"]
        existing.matched_target = finding["matched_target"]
        existing.source = finding["source"]
        existing.evidence_json = evidence_json
        existing.last_seen = now
        return existing

    new_finding = MonitoringFinding(
        job_id=job_id,
        run_id=run_id,
        check_type=finding["check_type"],
        matched_target=finding["matched_target"],
        source=finding["source"],
        evidence_json=evidence_json,
        fingerprint=fingerprint,
        first_seen=now,
        last_seen=now,
    )
    db.add(new_finding)
    return new_finding


def serialize_run(run: MonitoringRun) -> dict[str, Any]:
    return {
        "id": run.id,
        "job_id": run.job_id,
        "trigger_type": run.trigger_type,
        "status": run.status,
        "findings_count": run.findings_count,
        "preview_count": run.preview_count,
        "summary_json": run.summary_json,
        "error_message": run.error_message,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
    }


def serialize_finding(finding: MonitoringFinding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "job_id": finding.job_id,
        "run_id": finding.run_id,
        "check_type": finding.check_type,
        "matched_target": finding.matched_target,
        "source": finding.source,
        "evidence_json": finding.evidence_json,
        "status": finding.status,
        "first_seen": finding.first_seen,
        "last_seen": finding.last_seen,
        "created_at": finding.created_at,
    }


async def execute_monitoring_job(
    db: AsyncSession,
    job: MonitoringJob,
    trigger_type: str = "manual",
    preview_limit: int = 10,
) -> dict[str, Any]:
    config = normalize_monitoring_config(job.type, job.config_json)
    direct_targets = config["targets"]
    exclusions = config.get("exclusions", [])
    checks = config["checks"]

    run = MonitoringRun(
        job_id=job.id,
        trigger_type=trigger_type,
        status="running",
        started_at=_utcnow(),
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)

    warnings: list[str] = []
    raw_findings: list[dict[str, Any]] = []

    try:
        watchlist_findings: list[dict[str, Any]] = []
        watchlist_targets: list[dict[str, str]] = []
        if checks["watchlist_check"].get("enabled"):
            watchlist_findings, watchlist_warnings, watchlist_targets = await _run_watchlist_check(
                db,
                direct_targets,
                checks["watchlist_check"],
            )
            raw_findings.extend(watchlist_findings)
            warnings.extend(watchlist_warnings)

        effective_targets = _merge_targets(direct_targets, watchlist_targets)

        if checks["folder_scan"].get("enabled"):
            findings, folder_warnings = await _run_folder_scan(
                db,
                effective_targets,
                exclusions,
                checks["folder_scan"],
            )
            raw_findings.extend(findings)
            warnings.extend(folder_warnings)

        if checks["osint_check"].get("enabled"):
            findings, osint_warnings = await _run_osint_check(
                db,
                effective_targets,
                checks["osint_check"],
            )
            raw_findings.extend(findings)
            warnings.extend(osint_warnings)

        if checks["brand_scan"].get("enabled"):
            findings, brand_warnings = await _run_brand_scan(
                db,
                effective_targets,
                checks["brand_scan"],
            )
            raw_findings.extend(findings)
            warnings.extend(brand_warnings)

        preview: list[dict[str, Any]] = []
        for raw_finding in raw_findings:
            finding = await _upsert_finding(db, job.id, run.id, raw_finding)
            if len(preview) < max(preview_limit, 1):
                await db.flush()
                preview.append(serialize_finding(finding))

        run.status = "completed"
        run.findings_count = len(raw_findings)
        run.preview_count = len(preview)
        run.summary_json = json.dumps(
            {
                "warnings": warnings,
                "checks_enabled": [
                    name for name, cfg in checks.items() if cfg.get("enabled")
                ],
                "targets_count": len(effective_targets),
            },
            ensure_ascii=False,
        )
        run.completed_at = _utcnow()
        job.last_run = run.completed_at
        job.next_run = calculate_next_run(job.schedule, run.completed_at)

        await db.commit()
        await db.refresh(run)

        return {
            "run": serialize_run(run),
            "preview": preview,
            "warnings": warnings,
        }
    except Exception as exc:
        run.status = "failed"
        run.error_message = str(exc)[:RUN_ERROR_MAX_CHARS]
        run.completed_at = _utcnow()
        await db.commit()
        raise
