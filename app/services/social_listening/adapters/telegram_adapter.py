import json
import logging
from os import getenv

from app.models import SocialListeningRule

logger = logging.getLogger(__name__)


class TelegramAdapter:
    """
    Uses Telethon to search public telegram channels for brand terms.
    """

    _DEFAULT_CHANNELS = ["@cybersecua", "@hackersnews", "@darkwebinformer"]
    _MAX_TERMS = 20
    _MAX_MESSAGES = 20

    async def collect(self, rule: SocialListeningRule) -> list[dict]:
        try:
            from telethon import TelegramClient  # type: ignore
            from telethon.sessions import StringSession  # type: ignore
        except ImportError:
            logger.warning("social listening: telethon is not installed; telegram adapter skipped")
            return []

        api_id_raw = getenv("TELEGRAM_API_ID", "").strip()
        api_hash = getenv("TELEGRAM_API_HASH", "").strip()
        session_string = getenv("TELEGRAM_SESSION_STRING", "").strip()

        if not api_id_raw or not api_hash:
            logger.warning("social listening: telegram credentials missing; telegram adapter skipped")
            return []
        if not session_string:
            logger.warning("social listening: TELEGRAM_SESSION_STRING missing; telegram adapter skipped")
            return []

        try:
            api_id = int(api_id_raw)
        except ValueError:
            logger.warning("social listening: TELEGRAM_API_ID is invalid; telegram adapter skipped")
            return []

        try:
            terms = json.loads(rule.brand_terms or "[]")
        except Exception:
            terms = []

        channels = list(self._DEFAULT_CHANNELS)
        try:
            platforms = json.loads(rule.platforms or "[]")
            if isinstance(platforms, dict):
                candidate_channels = platforms.get("telegram_channels")
                if isinstance(candidate_channels, list):
                    sanitized = [str(item).strip() for item in candidate_channels if str(item).strip()]
                    if sanitized:
                        channels = sanitized
        except Exception:
            pass

        client = TelegramClient(StringSession(session_string), api_id, api_hash)
        collected: list[dict] = []
        try:
            await client.start()
            for term in terms[: self._MAX_TERMS]:
                term_text = str(term).strip()
                if not term_text:
                    continue
                for channel in channels:
                    try:
                        messages = await client.get_messages(channel, search=term_text, limit=self._MAX_MESSAGES)
                    except Exception as exc:
                        logger.warning(
                            "social listening: telegram search failed for term '%s' in %s: %s",
                            term_text,
                            channel,
                            exc,
                        )
                        continue

                    for message in messages:
                        content = str(getattr(message, "message", "") or "").strip()
                        if not content:
                            continue

                        source_channel = str(channel).lstrip("@")
                        chat = getattr(message, "chat", None)
                        chat_username = str(getattr(chat, "username", "") or "").strip()
                        if chat_username:
                            source_channel = chat_username
                        sender = getattr(message, "sender", None)

                        collected.append(
                            {
                                "source_platform": "telegram",
                                "source_url": f"https://t.me/{source_channel}/{getattr(message, 'id', '')}",
                                "author_id": str(getattr(message, "sender_id", "") or ""),
                                "author_username": str(getattr(sender, "username", "") or ""),
                                "content_raw": content,
                                "published_at": getattr(message, "date", None),
                            }
                        )
        finally:
            await client.disconnect()

        return collected
