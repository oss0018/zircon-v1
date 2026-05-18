import json
from dataclasses import dataclass

from app.services.social_listening.collector import SocialListeningCollector
from app.services.social_listening.nlp_pipeline import NLPPipeline


@dataclass
class _Raw:
    id: int
    source_platform: str
    source_url: str
    author_id: str
    author_username: str
    content_raw: str
    content_fingerprint: str
    published_at: object
    collected_at: object


@dataclass
class _Rule:
    id: int
    brand_terms: str


def test_compute_fingerprint_normalizes_whitespace_and_urls():
    collector = SocialListeningCollector()

    first = collector._compute_fingerprint("Leak at https://example.com\n now", "user-1")
    second = collector._compute_fingerprint(" leak   at  http://another.com now ", "user-1")

    assert first == second


def test_nlp_pipeline_extracts_indicators_and_terms():
    raw = _Raw(
        id=1,
        source_platform="rss",
        source_url="https://example.com/post",
        author_id="42",
        author_username="brandnews",
        content_raw="Possible leak for ACME. Contact sec@acme.com from 1.2.3.4",
        content_fingerprint="f" * 64,
        published_at=None,
        collected_at=None,
    )
    rule = _Rule(id=10, brand_terms=json.dumps(["ACME"]))

    processed = NLPPipeline().process(raw, rule)
    indicators = json.loads(processed["threat_indicators_json"])
    matched_terms = json.loads(processed["matched_terms_json"])

    assert processed["sentiment_label"] in {"NEG", "NEU"}
    assert "sec@acme.com" in indicators["emails"]
    assert "1.2.3.4" in indicators["ips"]
    assert matched_terms == ["ACME"]
    assert 1 <= processed["severity"] <= 5
