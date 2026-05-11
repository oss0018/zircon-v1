from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.services.monitoring_service import (
    calculate_next_run,
    infer_target_type,
    is_monitoring_job_due,
    normalize_monitoring_config,
    normalize_targets,
    serialize_monitoring_config,
)


def test_normalize_targets_deduplicates_and_applies_exclusions():
    targets = normalize_targets(
        [
            "Example.com",
            {"value": "example.com", "type": "domain"},
            "@brand_support",
            "keyword:ignored-as-literal",
            "fireage win",
        ],
        exclusions=["fireage win"],
    )

    assert targets == [
        {"type": "domain", "value": "Example.com"},
        {"type": "account", "value": "@brand_support"},
        {"type": "keyword", "value": "keyword:ignored-as-literal"},
    ]


def test_normalize_monitoring_config_migrates_legacy_folder_scan():
    config = normalize_monitoring_config(
        "folder_scan",
        '{"query":"fireage.win","folder":"./data/old","path_prefixes":["/intel"],"exclusions":["internal"]}',
    )

    assert config["targets"] == [{"type": "domain", "value": "fireage.win"}]
    assert config["checks"]["folder_scan"]["enabled"] is True
    assert config["checks"]["folder_scan"]["path_prefixes"] == ["/intel"]
    assert config["checks"]["folder_scan"]["legacy_folder"] == "./data/old"
    assert config["exclusions"] == ["internal"]


def test_serialize_monitoring_config_keeps_structured_checks():
    serialized = serialize_monitoring_config(
        {
            "targets": [{"type": "keyword", "value": "brand phrase"}],
            "checks": {
                "osint_check": {"enabled": True, "integration_ids": [1]},
                "watchlist_check": {"enabled": True, "watchlist_item_ids": [3], "matching_mode": "exact"},
            },
        }
    )
    config = normalize_monitoring_config("unified", serialized)

    assert config["checks"]["osint_check"]["enabled"] is True
    assert config["checks"]["osint_check"]["integration_ids"] == [1]
    assert config["checks"]["watchlist_check"]["matching_mode"] == "exact"


@dataclass
class _FakeJob:
    is_active: bool
    schedule: str
    last_run: datetime | None
    next_run: datetime | None = None


def test_calculate_next_run_and_due_logic():
    now = datetime.now(timezone.utc)
    hourly = calculate_next_run("hourly", now)
    daily = calculate_next_run("daily", now)

    assert hourly == now + timedelta(hours=1)
    assert daily == now + timedelta(days=1)
    assert calculate_next_run("manual", now) is None

    assert is_monitoring_job_due(_FakeJob(True, "hourly", None), now=now) is True
    assert is_monitoring_job_due(_FakeJob(True, "manual", now - timedelta(days=1)), now=now) is False
    assert is_monitoring_job_due(
        _FakeJob(True, "hourly", now - timedelta(hours=2), now - timedelta(minutes=1)),
        now=now,
    ) is True


def test_infer_target_type_detects_supported_values():
    assert infer_target_type("test@example.com") == "email"
    assert infer_target_type("https://example.com") == "url"
    assert infer_target_type("example.com") == "domain"
    assert infer_target_type("@brand") == "account"
    assert infer_target_type("brand keyword") == "keyword"
