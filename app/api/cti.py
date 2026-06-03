import csv
import io
import json
from datetime import datetime, timezone
from sqlalchemy import or_

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import CTIActor, CTIIndicator, CTISIEMMatch, CTISentinelCoverage, User
from app.services.cti.alerts import dispatch_cti_alert
from app.services.cti.attack_matrix import ATTACK_STATES, compute_attack_cell_state
from app.services.cti.scorer import compute_ioc_score
from app.services.cti.sentinel import generate_sentinel_kql_rule
from app.services.cti.stix_factory import STIXFactory
from app.services.cti.tlp import can_export_for_role

router = APIRouter()

CTI_RBAC = {
    "view": {"L1", "L2", "TI_ANALYST", "IR", "SEC_ENG", "CISO", "ADMIN", "USER"},
    "annotate": {"L2", "TI_ANALYST", "IR", "SEC_ENG", "CISO", "ADMIN"},
    "export": {"TI_ANALYST", "IR", "SEC_ENG", "CISO", "ADMIN"},
    "manage": {"SEC_ENG", "CISO", "ADMIN"},
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_role(role: str) -> str:
    role_u = (role or "").strip().upper()
    mapped = {
        "ANALYST_L1": "L1",
        "ANALYST_L2": "L2",
        "TI_ANALYST": "TI_ANALYST",
        "IR": "IR",
        "SECURITY_ENGINEER": "SEC_ENG",
        "SEC_ENG": "SEC_ENG",
        "CISO": "CISO",
        "ADMIN": "ADMIN",
        "USER": "USER",
    }
    return mapped.get(role_u, role_u or "USER")


def _assert_cti_role(user: User, action: str) -> None:
    role = _normalize_role(getattr(user, "role", "user"))
    if role not in CTI_RBAC.get(action, set()):
        raise HTTPException(status_code=403, detail=f"Role '{role}' is not allowed to {action} CTI data")


def indicator_matches_filters(
    indicator: CTIIndicator,
    *,
    ioc_type: str | None,
    severity: str | None,
    min_score: int,
    include_false_positive: bool,
) -> bool:
    if ioc_type and indicator.ioc_type != ioc_type:
        return False
    if severity and indicator.severity != severity.upper():
        return False
    if int(indicator.score or 0) < int(min_score or 0):
        return False
    if not include_false_positive and bool(indicator.is_false_positive):
        return False
    return True


@router.get("/indicators")
async def list_indicators(
    ioc_type: str | None = None,
    severity: str | None = None,
    min_score: int = 0,
    include_false_positive: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _assert_cti_role(current_user, "view")
    q = select(CTIIndicator).order_by(CTIIndicator.created_at.desc())
    if ioc_type:
        q = q.where(CTIIndicator.ioc_type == ioc_type)
    if severity:
        q = q.where(CTIIndicator.severity == severity.upper())
    q = q.where(CTIIndicator.score >= min_score)
    if not include_false_positive:
        q = q.where(CTIIndicator.is_false_positive.is_(False))
    result = await db.execute(q.limit(500))
    rows = result.scalars().all()
    filtered = [
        r
        for r in rows
        if indicator_matches_filters(
            r,
            ioc_type=ioc_type,
            severity=severity,
            min_score=min_score,
            include_false_positive=include_false_positive,
        )
    ]
    return [
        {
            "id": r.id,
            "value": r.value,
            "ioc_type": r.ioc_type,
            "source": r.source,
            "score": r.score,
            "severity": r.severity,
            "country_code": r.country_code,
            "actor_names": json.loads(r.actor_names or "[]"),
            "is_false_positive": bool(r.is_false_positive),
            "stix_json": json.loads(r.stix_json or "{}"),
            "tlp": r.tlp,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in filtered
    ]


@router.post("/indicators")
async def create_indicator(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _assert_cti_role(current_user, "annotate")
    value = str(body.get("value", "")).strip()
    if not value:
        raise HTTPException(status_code=400, detail="value is required")
    ioc_type = str(body.get("ioc_type", "general")).strip().lower()
    actor_names = body.get("actor_names") or []
    if not isinstance(actor_names, list):
        actor_names = []

    scoring = compute_ioc_score(
        source_reputation=int(body.get("source_reputation", 0)),
        malware_confidence=int(body.get("malware_confidence", 0)),
        exploitation_likelihood=int(body.get("exploitation_likelihood", 0)),
        siem_matches=int(body.get("siem_matches", 0)),
        is_false_positive=bool(body.get("is_false_positive", False)),
    )
    stix = STIXFactory.indicator(value=value, ioc_type=ioc_type, confidence=int(scoring["score"]))
    indicator = CTIIndicator(
        value=value,
        ioc_type=ioc_type,
        source=str(body.get("source", "")),
        score=int(scoring["score"]),
        severity=str(scoring["severity"]),
        country_code=str(body.get("country_code", "")),
        actor_names=json.dumps(actor_names),
        tags_json=json.dumps(body.get("tags", [])),
        metadata_json=json.dumps(body.get("metadata", {})),
        tlp=str(body.get("tlp", "TLP:CLEAR")).upper(),
        stix_json=json.dumps(stix),
        is_false_positive=bool(body.get("is_false_positive", False)),
        first_seen_at=_utcnow(),
        last_seen_at=_utcnow(),
    )
    db.add(indicator)
    await db.commit()
    await db.refresh(indicator)
    return {"id": indicator.id, "score": indicator.score, "severity": indicator.severity, "stix_json": stix}


@router.post("/indicators/{indicator_id}/false-positive")
async def mark_indicator_false_positive(
    indicator_id: int,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _assert_cti_role(current_user, "annotate")
    res = await db.execute(select(CTIIndicator).where(CTIIndicator.id == indicator_id))
    indicator = res.scalar_one_or_none()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
    indicator.is_false_positive = True
    indicator.false_positive_reason = str(body.get("reason", "")).strip() or "manual"
    indicator.score = 0
    indicator.severity = "LOW"
    indicator.last_seen_at = _utcnow()
    await db.commit()
    return {"ok": True, "id": indicator.id, "is_false_positive": True, "score": 0}


@router.post("/siem/matches")
async def create_siem_match(
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _assert_cti_role(current_user, "manage")
    indicator_id = int(body.get("indicator_id", 0))
    res = await db.execute(select(CTIIndicator).where(CTIIndicator.id == indicator_id))
    indicator = res.scalar_one_or_none()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
    if indicator.is_false_positive:
        return {"ok": True, "suppressed": True, "reason": "false_positive"}

    severity = str(body.get("severity", indicator.severity)).upper()
    row = CTISIEMMatch(
        indicator_id=indicator.id,
        indicator_value=indicator.value,
        severity=severity,
        sentinel_alert_id=str(body.get("sentinel_alert_id", "")),
        matched_rule=str(body.get("matched_rule", "")),
        raw_payload=json.dumps(body.get("payload", {})),
        dispatched_channels=json.dumps(["email", "telegram", "webhook"]),
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)

    event = "SIEM_MATCH_CRITICAL" if severity == "CRITICAL" else "SIEM_MATCH_HIGH"
    alert_result = await dispatch_cti_alert(event, f"{event}: {indicator.value}", f"Sentinel matched {indicator.value}")
    return {"ok": True, "id": row.id, "event": event, "alert": alert_result}


@router.get("/attack/blind-spots")
async def list_blind_spots(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _assert_cti_role(current_user, "view")
    result = await db.execute(select(CTISentinelCoverage))
    rows = result.scalars().all()
    blind = []
    for row in rows:
        state = compute_attack_cell_state(
            used_by_actor=bool(row.actor_name),
            has_sentinel_rule=bool(row.has_sentinel_rule),
            has_recent_activity=bool(row.has_recent_activity),
        )
        if state in {"BLIND_SPOT", "ACTIVE_BLIND_SPOT"}:
            blind.append(
                {
                    "technique_id": row.technique_id,
                    "actor_name": row.actor_name,
                    "state": state,
                    "color": ATTACK_STATES[state],
                }
            )
    return blind


@router.get("/actors/{actor_id}")
async def get_actor(
    actor_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _assert_cti_role(current_user, "view")
    result = await db.execute(select(CTIActor).where(CTIActor.id == actor_id))
    actor = result.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    return {
        "id": actor.id,
        "name": actor.name,
        "aliases": json.loads(actor.aliases or "[]"),
        "mitre_group_id": actor.mitre_group_id,
        "techniques": json.loads(actor.techniques or "[]"),
        "software": json.loads(actor.software or "[]"),
    }


@router.get("/actors/{actor_id}/iocs")
async def list_actor_iocs(
    actor_id: int,
    limit: int = Query(200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _assert_cti_role(current_user, "view")
    actor_res = await db.execute(select(CTIActor).where(CTIActor.id == actor_id))
    actor = actor_res.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Actor not found")
    rows = (
        await db.execute(
            select(CTIIndicator)
            .where(
                or_(
                    CTIIndicator.actor_names.like(f'%"{actor.name}"%'),
                    CTIIndicator.actor_names.like(f"%{actor.name}%"),
                )
            )
            .order_by(CTIIndicator.created_at.desc())
            .limit(limit)
        )
    ).scalars().all()
    actor_lower = actor.name.lower()
    return [
        {"id": i.id, "value": i.value, "ioc_type": i.ioc_type, "severity": i.severity, "score": i.score}
        for i in rows
        if actor_lower in [n.lower() for n in json.loads(i.actor_names or "[]")]
    ]


@router.get("/siem/kql-rule")
async def get_kql_rule(
    value: str = Query(...),
    ioc_type: str = Query("ip"),
    current_user: User = Depends(get_current_user),
):
    _assert_cti_role(current_user, "view")
    return {"kql": generate_sentinel_kql_rule(value, ioc_type)}


@router.get("/indicators/export.csv")
async def export_indicators_csv(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _assert_cti_role(current_user, "export")
    result = await db.execute(select(CTIIndicator).where(CTIIndicator.is_false_positive.is_(False)))
    rows = result.scalars().all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "value", "ioc_type", "score", "severity", "country_code", "tlp"])
    for row in rows:
        if can_export_for_role(row.tlp, _normalize_role(current_user.role)):
            writer.writerow([row.id, row.value, row.ioc_type, row.score, row.severity, row.country_code, row.tlp])
    return PlainTextResponse(output.getvalue(), media_type="text/csv")


@router.get("/indicators/export.stix")
async def export_indicators_stix(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    _assert_cti_role(current_user, "export")
    result = await db.execute(select(CTIIndicator).where(CTIIndicator.is_false_positive.is_(False)))
    rows = result.scalars().all()
    bundle = []
    for row in rows:
        if can_export_for_role(row.tlp, _normalize_role(current_user.role)):
            bundle.append(json.loads(row.stix_json or "{}"))
    return {"type": "bundle", "id": "bundle--zircon-cti", "objects": bundle}
