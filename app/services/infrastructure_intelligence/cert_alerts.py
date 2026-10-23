"""Notifications for certificates that are expired or nearing expiry."""
import html
import json
import logging

from app.config import settings
from app.services.infrastructure_intelligence.cert_intelligence import (
    CERT_EXPIRY_WARNING_DAYS,
)
from app.services.notifications import notify

logger = logging.getLogger(__name__)


def _finding_data(finding: dict) -> dict:
    data = finding.get("data_json") or {}
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            return {}
    return data if isinstance(data, dict) else {}


async def notify_expiring_certificates(target: str, findings: list[dict]) -> None:
    """Notify configured CTI channels when an investigation finds expiring certs."""
    configured_email = settings.cti_alert_email.strip()
    configured_telegram = settings.cti_alert_telegram.strip()
    alert_email = configured_email if settings.smtp_host else ""
    alert_telegram = configured_telegram if settings.telegram_bot_token else ""
    if configured_email and not alert_email:
        logger.warning("Certificate expiry email alert skipped because SMTP is not configured")
    if configured_telegram and not alert_telegram:
        logger.warning("Certificate expiry Telegram alert skipped because the bot token is not configured")
    if not alert_email and not alert_telegram:
        return

    expiring = []
    for finding in findings:
        if finding.get("module") != "cert":
            continue
        data = _finding_data(finding)
        try:
            days_until_expiry = int(data["days_until_expiry"])
        except (KeyError, TypeError, ValueError):
            continue
        if days_until_expiry <= CERT_EXPIRY_WARNING_DAYS:
            expiring.append((finding, data, days_until_expiry))

    if not expiring:
        return

    lines = [f"Target: {html.escape(target)}"]
    for finding, data, days in expiring[:20]:
        entity = html.escape(str(finding.get("entity") or "unknown"))
        expiry = html.escape(str(data.get("not_after") or "unknown"))
        days_label = "expired" if days < 0 else f"{days} days remaining"
        lines.append(f"- {entity}: expires {expiry} ({days_label})")
    if len(expiring) > 20:
        lines.append(f"- And {len(expiring) - 20} more certificate(s).")

    try:
        await notify(
            f"Certificate expiry warning for {html.escape(target)}",
            "\n".join(lines),
            alert_email,
            alert_telegram,
        )
    except Exception:
        logger.exception("Failed to send certificate expiry notification for %s", target)
