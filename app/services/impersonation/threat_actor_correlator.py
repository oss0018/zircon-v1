"""
Threat Actor Correlator — Impersonation Monitoring Phase 2 (TS-IMP-001 v2).

Links ImpersonationFindings to ThreatActor records by matching infrastructure
fingerprints extracted from the findings' evidence_json.

Supported correlation signals:
- Registrar name
- Hosting ASN
- Registrant email
- Payment gateway indicator

Usage::

    from app.services.impersonation.threat_actor_correlator import correlate_finding
    matches = await correlate_finding(finding_id=42)
    # returns list of (ThreatActor.id, confidence_score) tuples
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

# Minimum number of matching signals to consider a correlation hit
_MIN_SIGNALS_FOR_MATCH = 1


def _extract_signals(evidence_json: str) -> dict[str, set[str]]:
    """Parse *evidence_json* into a normalised signals dict."""
    signals: dict[str, set[str]] = {
        "registrar": set(),
        "asn": set(),
        "registrant_email": set(),
        "payment_gateway": set(),
    }
    try:
        evidence = json.loads(evidence_json or "{}")
    except Exception:  # noqa: BLE001
        return signals

    # WHOIS signals
    whois = evidence.get("whois") or {}
    registrar = (
        whois.get("registrar")
        or (whois.get("WhoisRecord") or {}).get("registrarName")
        or ""
    )
    if registrar:
        signals["registrar"].add(str(registrar).strip().lower())
    registrant = (
        whois.get("registrantEmail")
        or ((whois.get("WhoisRecord") or {}).get("registrant") or {}).get("email")
        or ""
    )
    if registrant:
        signals["registrant_email"].add(str(registrant).strip().lower())

    # ASN signals
    asn = evidence.get("asn") or evidence.get("asn_number") or ""
    if asn:
        signals["asn"].add(str(asn).strip().upper())

    # Payment gateway (application-level tag)
    pgw = evidence.get("payment_gateway") or ""
    if pgw:
        signals["payment_gateway"].add(str(pgw).strip().lower())

    return signals


def _actor_signals(actor: Any) -> dict[str, set[str]]:
    """Extract actor infrastructure signals from ORM row JSON fields."""
    def _load(raw: str) -> set[str]:
        try:
            items = json.loads(raw or "[]")
            return {str(x).strip().lower() for x in items if x}
        except Exception:  # noqa: BLE001
            return set()

    return {
        "registrar": _load(actor.registrar_names_json),
        "asn": {x.upper() for x in _load(actor.hosting_asns_json)},
        "registrant_email": _load(actor.registrant_emails_json),
        "payment_gateway": _load(actor.payment_gateways_json),
    }


def _score_overlap(finding_signals: dict[str, set[str]], actor_signals_dict: dict[str, set[str]]) -> int:
    """Return the number of signal categories that overlap between finding and actor."""
    return sum(
        1
        for key in finding_signals
        if finding_signals[key] & actor_signals_dict.get(key, set())
    )


async def correlate_finding(
    finding_id: int,
    db: AsyncSession | None = None,
) -> list[tuple[int, int]]:
    """
    Correlate a single finding against all known ThreatActors.

    Parameters
    ----------
    finding_id:
        ID of the ImpersonationFinding to correlate.
    db:
        Optional async DB session.  If not provided, a new one is created.

    Returns
    -------
    List of ``(actor_id, signal_overlap_count)`` tuples sorted by descending score,
    filtered to actors with overlap >= ``_MIN_SIGNALS_FOR_MATCH``.
    """
    from app.models import ImpersonationFinding, ThreatActor

    _own_session = db is None
    if _own_session:
        from app.database import AsyncSessionLocal
        db = AsyncSessionLocal()

    results: list[tuple[int, int]] = []

    try:
        finding_row = (
            await db.execute(
                select(ImpersonationFinding).where(ImpersonationFinding.id == finding_id)
            )
        ).scalar_one_or_none()

        if not finding_row:
            logger.warning("[ThreatActorCorrelator] Finding %s not found", finding_id)
            return results

        finding_sigs = _extract_signals(finding_row.evidence_json or "{}")

        actors = (await db.execute(select(ThreatActor))).scalars().all()
        for actor in actors:
            actor_sigs = _actor_signals(actor)
            score = _score_overlap(finding_sigs, actor_sigs)
            if score >= _MIN_SIGNALS_FOR_MATCH:
                results.append((actor.id, score))

        results.sort(key=lambda x: x[1], reverse=True)

    finally:
        if _own_session:
            await db.close()

    return results


async def link_finding_to_actor(
    finding_id: int,
    actor_id: int,
    db: AsyncSession | None = None,
) -> bool:
    """
    Append *finding_id* to the ``linked_finding_ids_json`` list of *actor_id*.

    Returns True on success, False if either record was not found.
    """
    from app.models import ThreatActor

    _own_session = db is None
    if _own_session:
        from app.database import AsyncSessionLocal
        db = AsyncSessionLocal()

    try:
        actor = (
            await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id))
        ).scalar_one_or_none()

        if not actor:
            logger.warning("[ThreatActorCorrelator] ThreatActor %s not found", actor_id)
            return False

        try:
            ids: list[int] = json.loads(actor.linked_finding_ids_json or "[]")
        except Exception:  # noqa: BLE001
            ids = []

        if finding_id not in ids:
            ids.append(finding_id)
            actor.linked_finding_ids_json = json.dumps(ids)
            await db.commit()

        return True

    finally:
        if _own_session:
            await db.close()
