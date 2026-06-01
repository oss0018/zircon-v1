from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import LookalikeDomain, LookalikeRule, NrdFeedEntry
from app.services.lookalike.alert_engine import dispatch_lookalike_alerts
from app.services.lookalike.nrd_feed import fetch_nrd_domains
from app.services.lookalike.similarity import SimilarityCalculator
from app.services.lookalike.threat_scorer import score as threat_score

logger = logging.getLogger(__name__)

try:
    from Levenshtein import distance as _lev_distance  # type: ignore
except Exception:  # noqa: BLE001
    _lev_distance = None

_similarity_calculator = SimilarityCalculator()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def composite_score(candidate_label: str, protected_label: str) -> float:
    return _similarity_calculator.compute(candidate_label, protected_label)


def _extract_label(fqdn: str) -> str:
    text = (fqdn or "").strip().lower().rstrip(".")
    parts = [p for p in text.split(".") if p]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    return parts[-2]


def _extract_tld(fqdn: str) -> str:
    text = (fqdn or "").strip().lower().rstrip(".")
    parts = [p for p in text.split(".") if p]
    if len(parts) < 2:
        return ""
    return parts[-1]


def _levenshtein_distance(a: str, b: str) -> int:
    if _lev_distance is not None:
        return int(_lev_distance(a, b))
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current_row = [i]
        for j, cb in enumerate(b, 1):
            insertions = previous_row[j] + 1
            deletions = current_row[j - 1] + 1
            substitutions = previous_row[j - 1] + (ca != cb)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


async def run_watch_mode(rule: LookalikeRule, db: AsyncSession) -> dict:
    summary = {"checked": 0, "matched": 0, "alerted": 0, "errors": []}
    now = _utcnow()
    protected_label = _extract_label(rule.protected_domain)
    similarity_threshold = float(getattr(rule, "similarity_threshold", 0.5) or 0.5)

    feed_source = rule.watch_feed_source or "whoisds"
    domains = await fetch_nrd_domains(feed_source=feed_source)
    summary["checked"] = len(domains)

    new_domains: list[LookalikeDomain] = []
    feed_dt = datetime.combine((now - timedelta(days=1)).date(), datetime.min.time(), tzinfo=timezone.utc)

    for fqdn in domains:
        try:
            label = _extract_label(fqdn)
            tld = _extract_tld(fqdn)
            if not label or not tld:
                continue

            similarity = composite_score(label, protected_label)
            if similarity < float(similarity_threshold):
                continue
            summary["matched"] += 1

            dedup_res = await db.execute(
                select(NrdFeedEntry.id).where(
                    NrdFeedEntry.rule_id == rule.id,
                    NrdFeedEntry.fqdn == fqdn,
                )
            )
            if dedup_res.scalar_one_or_none():
                continue

            domain_res = await db.execute(
                select(LookalikeDomain).where(
                    LookalikeDomain.rule_id == rule.id,
                    LookalikeDomain.fqdn == fqdn,
                )
            )
            domain = domain_res.scalar_one_or_none()
            lev = _levenshtein_distance(label, protected_label)
            if domain is None:
                domain = LookalikeDomain(
                    rule_id=rule.id,
                    fqdn=fqdn,
                    label=label,
                    tld=tld,
                    first_seen_at=now,
                )
                db.add(domain)

            domain.label = label
            domain.tld = tld
            domain.status = "registered"
            domain.similarity_score = similarity
            domain.levenshtein_distance = lev
            domain.is_idn = "xn--" in fqdn
            domain.last_checked_at = now

            ts, sev, signals = threat_score(domain)
            domain.threat_score = ts
            domain.severity = sev
            domain.signals_fired = json.dumps(signals)
            new_domains.append(domain)

            try:
                async with db.begin_nested():
                    db.add(NrdFeedEntry(rule_id=rule.id, fqdn=fqdn, feed_date=feed_dt))
                    await db.flush()
            except IntegrityError:
                continue
        except Exception as exc:  # noqa: BLE001
            summary["errors"].append(str(exc))
            logger.warning("Watch mode domain processing failed (%s): %s", fqdn, exc)

    await db.commit()

    alert_threshold = rule.alert_threshold or 50
    high_threat_domains = [d for d in new_domains if (d.threat_score or 0) >= alert_threshold]
    if high_threat_domains:
        alert_result = await dispatch_lookalike_alerts(rule.id, high_threat_domains, db)
        summary["alerted"] = int(alert_result.get("sent", 0))

    rule.watch_last_run_at = _utcnow()
    await db.commit()
    return summary
