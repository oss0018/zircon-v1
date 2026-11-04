"""
Email (SMTP) and Telegram notification service.
"""
import smtplib
import httpx
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import settings

logger = logging.getLogger(__name__)


def apply_notification_settings(values: dict) -> None:
    settings.smtp_host = values["smtp_host"]
    settings.smtp_port = values["smtp_port"]
    settings.smtp_user = values["smtp_user"]
    settings.smtp_password = values["smtp_password"]
    settings.telegram_bot_token = values["telegram_bot_token"]
    settings.telegram_chat_id = values["telegram_chat_id"]


async def load_notification_settings() -> None:
    from app.database import AsyncSessionLocal
    from app.models import NotificationSettings

    async with AsyncSessionLocal() as db:
        saved = await db.get(NotificationSettings, 1)
        if saved:
            from app.services.crypto import decrypt

            apply_notification_settings({
                "smtp_host": saved.smtp_host,
                "smtp_port": saved.smtp_port,
                "smtp_user": saved.smtp_user,
                "smtp_password": decrypt(saved.smtp_password_encrypted),
                "telegram_bot_token": decrypt(saved.telegram_bot_token_encrypted),
                "telegram_chat_id": saved.telegram_chat_id,
            })


async def send_email(to: str, subject: str, body: str) -> bool:
    if not settings.smtp_host or not to:
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = settings.smtp_user
        msg["To"] = to
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            server.ehlo()
            server.starttls()
            if settings.smtp_user and settings.smtp_password:
                server.login(settings.smtp_user, settings.smtp_password)
            server.sendmail(settings.smtp_user, [to], msg.as_string())
        return True
    except Exception:
        logger.exception("Email notification failed")
        return False


async def send_telegram(chat_id: str, message: str) -> bool:
    chat_id = chat_id or settings.telegram_chat_id
    if not settings.telegram_bot_token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"})
            return resp.status_code == 200
    except Exception:
        logger.exception("Telegram notification failed")
        return False


async def notify(title: str, message: str, alert_email: str = "", alert_telegram: str = ""):
    if alert_email:
        await send_email(alert_email, f"[Zircon FRT] {title}", message)
    if alert_telegram or settings.telegram_chat_id:
        await send_telegram(alert_telegram, f"<b>[Zircon FRT] {title}</b>\n{message}")
