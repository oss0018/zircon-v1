"""
Email (SMTP) and Telegram notification service.
"""
import smtplib
import httpx
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.config import settings


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
    except Exception as e:
        print(f"[notifications] Email error: {e}")
        return False


async def send_telegram(chat_id: str, message: str) -> bool:
    if not settings.telegram_bot_token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(url, json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"})
            return resp.status_code == 200
    except Exception as e:
        print(f"[notifications] Telegram error: {e}")
        return False


async def notify(title: str, message: str, alert_email: str = "", alert_telegram: str = ""):
    if alert_email:
        await send_email(alert_email, f"[Zircon FRT] {title}", message)
    if alert_telegram:
        await send_telegram(alert_telegram, f"<b>[Zircon FRT] {title}</b>\n{message}")
