import json
import logging
from os import getenv

from app.config import settings
from app.models import VSFinding, VSScan, VSScanTarget
from app.services.notifications import notify

logger = logging.getLogger(__name__)

_SUPPORTED_NOTIFY_CHANNELS = {"email", "telegram"}
_SEVERE_SEVERITIES = {"CRITICAL", "HIGH"}
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _selected_channels(target: VSScanTarget) -> set[str]:
    try:
        values = json.loads(target.notify_channels_json or "[]")
    except Exception:  # noqa: BLE001
        logger.warning("vulnscan: invalid notify_channels_json for target %s", target.id)
        return set()
    return {
        str(value).strip().lower()
        for value in values
        if isinstance(value, str) and str(value).strip()
    }


def _resolve_destinations(channels: set[str]) -> tuple[str, str]:
    alert_email = ""
    alert_telegram = ""

    if "email" in channels and settings.smtp_host:
        alert_email = getenv("VULNSCAN_ALERT_EMAIL", getenv("CTI_ALERT_EMAIL", "")).strip()
    if "telegram" in channels and settings.telegram_bot_token:
        alert_telegram = getenv("VULNSCAN_ALERT_TELEGRAM", getenv("CTI_ALERT_TELEGRAM", "")).strip()

    return alert_email, alert_telegram


def _format_counts(scan: VSScan) -> str:
    return (
        f"critical={scan.findings_critical}, high={scan.findings_high}, medium={scan.findings_medium}, "
        f"low={scan.findings_low}, info={scan.findings_info}, total={scan.findings_total}"
    )


def _format_top_findings(findings: list[VSFinding], limit: int = 5) -> str:
    severe_findings = [
        finding
        for finding in findings
        if (finding.severity or "").upper() in _SEVERE_SEVERITIES
    ]
    severe_findings.sort(key=lambda finding: (_SEVERITY_RANK.get(finding.severity or "INFO", 99), finding.id or 0))
    if not severe_findings:
        return "None"

    lines = []
    for finding in severe_findings[:limit]:
        scanner_source = finding.scanner_source or "unknown"
        lines.append(f"- {finding.severity}: {finding.title} [{scanner_source}]")
    return "\n".join(lines)


async def dispatch_severe_scan_alert(scan: VSScan, target: VSScanTarget, findings: list[VSFinding]) -> dict:
    if not (scan.findings_critical or scan.findings_high):
        return {"sent": False, "reason": "not_severe"}

    channels = _selected_channels(target)
    unsupported_channels = sorted(channels - _SUPPORTED_NOTIFY_CHANNELS)
    if unsupported_channels:
        logger.info(
            "vulnscan: scan %s has unsupported alert channels configured: %s",
            scan.id,
            ", ".join(unsupported_channels),
        )

    alert_email, alert_telegram = _resolve_destinations(channels)
    if not alert_email and not alert_telegram:
        logger.info(
            "vulnscan: severe alert skipped for scan %s because no notification destination is configured",
            scan.id,
        )
        return {"sent": False, "reason": "missing_config"}

    title = f"Vuln scan {scan.overall_risk or 'HIGH'} findings: {target.name}"
    body = "\n".join(
        [
            f"Target: {target.name}",
            f"Target value: {target.target_value}",
            f"Scan ID: {scan.id}",
            f"Scan profile: {scan.profile}",
            f"Overall risk: {scan.overall_risk or 'HIGH'}",
            f"Severity counts: {_format_counts(scan)}",
            "",
            "Top severe findings:",
            _format_top_findings(findings),
        ]
    )

    await notify(title, body, alert_email, alert_telegram)
    return {"sent": True, "channels": sorted(channels & _SUPPORTED_NOTIFY_CHANNELS)}
