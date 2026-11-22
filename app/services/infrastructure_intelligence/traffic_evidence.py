"""Identify traffic-tracker leads in supplied text without network access."""
import html
import heapq
import re
from urllib.parse import parse_qsl, urlsplit


_RULES = (
    ("keitaro_tracking", "Keitaro", re.compile(
        r"\bKTracking\s*\.\s*(?:reportConversion|update|ready)\s*\(", re.I,
    ), "A KTracking method call resembles the documented Keitaro tracking script.",
     "https://docs.keitaro.io/en/campaign-integrations/tracking-script.html"),
    ("keitaro_php_client", "Keitaro", re.compile(
        r"\bnew\s+KClickClient\s*\(", re.I,
    ), "A KClickClient constructor resembles the documented Keitaro PHP integration.",
     "https://docs.keitaro.io/en/campaign-integrations/kclient-php.html"),
    ("binom_click_api", "Binom", re.compile(
        r"\bnew\s+BinomClickAPI\s*\(", re.I,
    ), "A BinomClickAPI constructor resembles the documented Binom integration.",
     "https://docs.binom.org/click-api-v2.php"),
)
_URL = re.compile(r"""https?://[^\s"'<>\\]+|/click\.php\?[^\s"'<>\\]+""", re.I)
_LOCATION = re.compile(r"^[ \t]*location[ \t]*:[ \t]*(\S+)", re.I | re.M)
MAX_SIGNALS = 100
MAX_REDIRECTS = 100


class TrafficEvidenceError(Exception):
    pass


def _line(text: str, position: int) -> int:
    return text.count("\n", 0, position) + 1


def analyze_traffic_evidence(text: str) -> dict:
    def signal(rule, platform, match, explanation, docs, hostname=None):
        return {
            "rule": rule, "platform": platform, "line": _line(text, match.start()),
            "start": match.start(), "end": match.end(), "hostname": hostname,
            "explanation": explanation, "documentation_url": docs,
        }

    def rule_signals(rule, platform, pattern, explanation, docs):
        for match in pattern.finditer(text):
            yield signal(rule, platform, match, explanation, docs)

    def url_signals():
        for match in _URL.finditer(text):
            try:
                url = urlsplit(html.unescape(match.group()))
                if not url.path.lower().endswith("/click.php"):
                    continue
                params = parse_qsl(url.query, keep_blank_values=True, max_num_fields=100)
                if any(key.lower() == "lp_type" and value.lower() == "js_redirect" for key, value in params):
                    yield signal(
                        "binom_js_redirect", "Binom", match,
                        "A click.php URL with lp_type=js_redirect resembles Binom's documented JS protection pattern.",
                        "https://docs.binom.org/js-protection.php", url.hostname,
                    )
            except ValueError as exc:
                raise TrafficEvidenceError("A supplied URL is invalid or has more than 100 query parameters") from exc

    streams = [rule_signals(*rule) for rule in _RULES] + [url_signals()]
    signals = []
    truncated = False
    for item in heapq.merge(*streams, key=lambda item: (item["start"], item["rule"])):
        if len(signals) == MAX_SIGNALS:
            truncated = True
            break
        signals.append(item)

    redirects = []
    redirect_truncated = False
    for match in _LOCATION.finditer(text):
        if len(redirects) >= MAX_REDIRECTS:
            redirect_truncated = True
            break
        target = html.unescape(match.group(1))
        try:
            parsed = urlsplit(target)
            if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
                raise ValueError("Unsupported scheme")
            if parsed.scheme and not parsed.hostname:
                raise ValueError("Missing hostname")
            redirects.append({
                "line": _line(text, match.start()), "hostname": parsed.hostname,
                "relative": not bool(parsed.netloc), "has_query": bool(parsed.query),
            })
        except ValueError as exc:
            raise TrafficEvidenceError("A supplied Location header contains an invalid target") from exc
    return {
        "source_type": "user_supplied",
        "signals": signals, "signals_truncated": truncated,
        "location_headers": redirects, "location_headers_truncated": redirect_truncated,
        "notice": (
            "Signals are possible indicators, not proof of tracker use, operator identity or wrongdoing. "
            "Headers are listed in supplied order and are not verified as a redirect chain. "
            "Renamed or obfuscated integrations may not match; absence of signals does not rule out a tracker. "
            "No URLs were requested and the submitted text was not saved."
        ),
    }
