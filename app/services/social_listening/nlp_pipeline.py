import html
import json
import re
from html.parser import HTMLParser
from typing import Any

from app.models import SLRawMention, SocialListeningRule

_NEGATIVE_WORDS = {
    "en": {"leak", "breach", "stolen", "fraud", "scam", "attack", "hacked", "malware", "phishing"},
    "uk": {"витік", "злам", "шахрай", "шахрайство", "атака", "фішинг", "компромат"},
    "ru": {"утечка", "взлом", "мошеннич", "атака", "фишинг", "компромат"},
}

_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_PHONE_RE = re.compile(r"\+?\d[\d\s\-()]{7,}\d")
_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_NEGATIVE_SCORE_STEP = 0.2


class _TagStripper(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str):
        self.parts.append(data)

    def get_data(self) -> str:
        return "".join(self.parts)


def _strip_tags(value: str) -> str:
    parser = _TagStripper()
    parser.feed(value or "")
    parser.close()
    return parser.get_data()


class NLPPipeline:
    """
    Simple, dependency-light NLP pipeline suitable for MVP.
    """

    def _normalize_text(self, text: str) -> str:
        plain = html.unescape(text or "")
        plain = _strip_tags(plain)
        plain = _URL_RE.sub(" URL ", plain)
        return re.sub(r"\s+", " ", plain).strip()

    def _detect_language(self, text: str) -> str:
        try:
            from langdetect import detect  # type: ignore

            detected = detect(text or "")
            normalized = (detected or "").strip().lower()
            if normalized in {"en", "uk", "ru"}:
                return normalized
        except Exception:
            pass

        lowered = (text or "").lower()
        if re.search(r"[іїєґ]", lowered):
            return "uk"
        if re.search(r"[а-яё]", lowered):
            return "ru"
        return "en"

    def _sentiment(self, text: str, language: str) -> tuple[str, float]:
        lowered = (text or "").lower()
        words = _NEGATIVE_WORDS.get(language, set()) | _NEGATIVE_WORDS["en"]
        negatives = sum(1 for w in words if w in lowered)
        if negatives == 0:
            return "NEU", 0.0
        score = max(-1.0, -_NEGATIVE_SCORE_STEP * negatives)
        if score <= -0.4:
            return "NEG", score
        return "NEU", score

    def _matched_terms(self, text: str, rule: SocialListeningRule) -> list[str]:
        try:
            terms = json.loads(rule.brand_terms or "[]")
        except Exception:
            terms = []
        lowered = (text or "").lower()
        return [str(term) for term in terms if str(term).lower() in lowered]

    def _threat_indicators(self, text: str) -> dict[str, Any]:
        return {
            "emails": list(dict.fromkeys(_EMAIL_RE.findall(text or ""))),
            "ips": list(dict.fromkeys(_IP_RE.findall(text or ""))),
            "phones": list(dict.fromkeys(_PHONE_RE.findall(text or ""))),
            "urls": list(dict.fromkeys(_URL_RE.findall(text or ""))),
        }

    def _severity(self, sentiment_score: float, indicators: dict[str, Any], matched_terms: list[str]) -> int:
        severity = 2 if matched_terms else 1
        if sentiment_score <= -0.4:
            severity += 1
        if indicators.get("emails"):
            severity += 1
        if indicators.get("ips"):
            severity += 1
        return max(1, min(5, severity))

    def process(self, raw: SLRawMention, rule: SocialListeningRule) -> dict:
        content_raw = raw.content_raw or ""
        normalized = self._normalize_text(content_raw)
        language = self._detect_language(normalized)
        sentiment_label, sentiment_score = self._sentiment(normalized, language)
        matched_terms = self._matched_terms(normalized, rule)
        threat_indicators = self._threat_indicators(normalized)
        severity = self._severity(sentiment_score, threat_indicators, matched_terms)

        return {
            "rule_id": rule.id,
            "raw_id": raw.id,
            "source_platform": raw.source_platform,
            "source_url": raw.source_url,
            "source_channel": "",
            "author_id": raw.author_id,
            "author_username": raw.author_username,
            "author_reach": 0,
            "content_raw": content_raw,
            "content_normalized": normalized,
            "content_fingerprint": raw.content_fingerprint,
            "language": language,
            "sentiment_label": sentiment_label,
            "sentiment_score": sentiment_score,
            "entities_json": "[]",
            "matched_terms_json": json.dumps(matched_terms, ensure_ascii=False),
            "threat_indicators_json": json.dumps(threat_indicators, ensure_ascii=False),
            "relevance_score": 1.0 if matched_terms else 0.5,
            "severity": severity,
            "engagement_json": "{}",
            "status": "new",
            "published_at": raw.published_at,
            "collected_at": raw.collected_at,
        }
