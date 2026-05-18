import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import and_, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import SLAlert, SLMention, SocialListeningRule, User
from app.schemas import (
    SLAlertOut,
    SLDashboardStats,
    SLMentionOut,
    SLMentionStatusUpdate,
    SLRuleCreate,
    SLRuleOut,
    SLRuleUpdate,
)
from app.services.social_listening.collector import SocialListeningCollector
from app.utils.sanitize import sanitize_string

router = APIRouter()


def _json_load(value: str, default: Any):
    try:
        return json.loads(value or "")
    except Exception:
        return default


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _rule_to_out(rule: SocialListeningRule) -> SLRuleOut:
    data = {
        "id": rule.id,
        "name": rule.name,
        "brand_id": rule.brand_id,
        "brand_terms": _json_load(rule.brand_terms, []),
        "hashtags": _json_load(rule.hashtags, []),
        "exclusions": _json_load(rule.exclusions, []),
        "languages": _json_load(rule.languages, ["uk", "ru", "en"]),
        "platforms": _json_load(rule.platforms, []),
        "severity_threshold": rule.severity_threshold,
        "alert_on": rule.alert_on,
        "schedule_cron": rule.schedule_cron,
        "store_all": rule.store_all,
        "active": rule.active,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }
    return SLRuleOut.model_validate(data)


@router.get("/mentions", response_model=list[SLMentionOut])
async def list_mentions(
    rule_id: Optional[int] = Query(None),
    platform: Optional[str] = Query(None),
    severity_min: Optional[int] = Query(None, ge=1, le=5),
    sentiment: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    q: Optional[str] = Query(None),
    sort: str = Query("-published_at"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    stmt = select(SLMention)
    filters = []

    if rule_id is not None:
        filters.append(SLMention.rule_id == rule_id)
    if platform:
        filters.append(SLMention.source_platform == sanitize_string(platform, max_length=50))
    if severity_min is not None:
        filters.append(SLMention.severity >= severity_min)
    if sentiment:
        filters.append(SLMention.sentiment_label == sanitize_string(sentiment, max_length=10))
    if status:
        filters.append(SLMention.status == sanitize_string(status, max_length=20))
    if since:
        filters.append(SLMention.published_at >= since)
    if until:
        filters.append(SLMention.published_at <= until)
    if q:
        safe_q = sanitize_string(q.strip(), max_length=200)
        term = f"%{safe_q}%"
        filters.append(
            or_(
                SLMention.content_raw.ilike(term),
                SLMention.content_normalized.ilike(term),
                SLMention.author_username.ilike(term),
            )
        )

    if filters:
        stmt = stmt.where(and_(*filters))

    sort_key = sanitize_string((sort or "-published_at").strip(), max_length=50)
    sort_map = {
        "published_at": SLMention.published_at,
        "severity": SLMention.severity,
        "created_at": SLMention.created_at,
        "sentiment_score": SLMention.sentiment_score,
    }
    desc_order = sort_key.startswith("-")
    field = sort_key[1:] if desc_order else sort_key
    sort_col = sort_map.get(field, SLMention.published_at)
    stmt = stmt.order_by(desc(sort_col) if desc_order else sort_col)

    stmt = stmt.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/mentions/export")
async def export_mentions(
    format: str = Query("csv", pattern="^(csv|json)$"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    mentions = (await db.execute(select(SLMention).order_by(desc(SLMention.published_at)).limit(5000))).scalars().all()

    if format == "json":
        payload = [SLMentionOut.model_validate(item).model_dump(mode="json") for item in mentions]
        return JSONResponse(payload)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "id",
            "rule_id",
            "platform",
            "url",
            "author_username",
            "sentiment",
            "severity",
            "status",
            "published_at",
            "content",
        ]
    )
    for item in mentions:
        writer.writerow(
            [
                item.id,
                item.rule_id,
                item.source_platform,
                item.source_url,
                item.author_username,
                item.sentiment_label,
                item.severity,
                item.status,
                item.published_at.isoformat() if item.published_at else "",
                item.content_raw,
            ]
        )

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sl_mentions.csv"},
    )


@router.get("/mentions/{mention_id}", response_model=SLMentionOut)
async def get_mention(mention_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    mention = (await db.execute(select(SLMention).where(SLMention.id == mention_id))).scalar_one_or_none()
    if not mention:
        raise HTTPException(status_code=404, detail="Not found")
    return mention


@router.patch("/mentions/{mention_id}/status", response_model=SLMentionOut)
async def update_mention_status(
    mention_id: int,
    body: SLMentionStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    mention = (await db.execute(select(SLMention).where(SLMention.id == mention_id))).scalar_one_or_none()
    if not mention:
        raise HTTPException(status_code=404, detail="Not found")

    mention.status = body.status
    mention.reviewed_by = current_user.id
    mention.reviewed_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(mention)
    return mention


@router.get("/alerts", response_model=list[SLAlertOut])
async def list_alerts(
    rule_id: Optional[int] = Query(None),
    severity: Optional[int] = Query(None, ge=1, le=5),
    status: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    stmt = select(SLAlert)
    if rule_id is not None:
        stmt = stmt.where(SLAlert.rule_id == rule_id)
    if severity is not None:
        stmt = stmt.where(SLAlert.severity == severity)
    if status:
        stmt = stmt.where(SLAlert.status == sanitize_string(status, max_length=20))
    if since:
        stmt = stmt.where(SLAlert.created_at >= since)
    stmt = stmt.order_by(desc(SLAlert.created_at)).limit(500)
    return (await db.execute(stmt)).scalars().all()


@router.get("/alerts/stats")
async def alert_stats(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    severity_rows = (
        await db.execute(select(SLAlert.severity, func.count(SLAlert.id)).group_by(SLAlert.severity))
    ).all()
    type_rows = (
        await db.execute(select(SLAlert.alert_type, func.count(SLAlert.id)).group_by(SLAlert.alert_type))
    ).all()
    return {
        "by_severity": {str(key): count for key, count in severity_rows},
        "by_type": {str(key): count for key, count in type_rows},
    }


@router.get("/alerts/{alert_id}", response_model=SLAlertOut)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    alert = (await db.execute(select(SLAlert).where(SLAlert.id == alert_id))).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Not found")
    return alert


@router.post("/alerts/{alert_id}/acknowledge", response_model=SLAlertOut)
async def acknowledge_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert = (await db.execute(select(SLAlert).where(SLAlert.id == alert_id))).scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Not found")

    alert.status = "acknowledged"
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(alert)
    return alert


@router.get("/dashboard/summary", response_model=SLDashboardStats)
async def dashboard_summary(
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    delta = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}[window]
    since = datetime.now(timezone.utc) - delta

    total_mentions = (
        await db.execute(select(func.count(SLMention.id)).where(SLMention.created_at >= since))
    ).scalar_one()
    sentiment_rows = (
        await db.execute(
            select(SLMention.sentiment_label, func.count(SLMention.id))
            .where(SLMention.created_at >= since)
            .group_by(SLMention.sentiment_label)
        )
    ).all()
    platform_rows = (
        await db.execute(
            select(SLMention.source_platform, func.count(SLMention.id))
            .where(SLMention.created_at >= since)
            .group_by(SLMention.source_platform)
            .order_by(desc(func.count(SLMention.id)))
            .limit(10)
        )
    ).all()

    return SLDashboardStats(
        total_mentions=total_mentions,
        sentiment_breakdown={str(k or "NEU"): int(v) for k, v in sentiment_rows},
        top_platforms={str(k or "unknown"): int(v) for k, v in platform_rows},
    )


@router.get("/dashboard/timeline")
async def dashboard_timeline(
    window: str = Query("24h", pattern="^(24h|7d|30d)$"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    delta = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}[window]
    since = datetime.now(timezone.utc) - delta
    try:
        rows = (
            await db.execute(
                select(func.date_trunc("hour", SLMention.created_at), func.count(SLMention.id))
                .where(SLMention.created_at >= since)
                .group_by(func.date_trunc("hour", SLMention.created_at))
                .order_by(func.date_trunc("hour", SLMention.created_at))
            )
        ).all()
    except Exception:
        rows = []

    # SQLite fallback (date_trunc unsupported)
    if not rows:
        rows = (
            await db.execute(
                select(func.strftime("%Y-%m-%d %H:00:00", SLMention.created_at), func.count(SLMention.id))
                .where(SLMention.created_at >= since)
                .group_by(func.strftime("%Y-%m-%d %H:00:00", SLMention.created_at))
                .order_by(func.strftime("%Y-%m-%d %H:00:00", SLMention.created_at))
            )
        ).all()

    return {
        "window": window,
        "points": [
            {"time": bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket), "count": int(count)}
            for bucket, count in rows
        ],
    }


@router.get("/", response_model=list[SLRuleOut])
async def list_rules(
    brand_id: Optional[int] = Query(None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    stmt = select(SocialListeningRule)
    if brand_id is not None:
        stmt = stmt.where(SocialListeningRule.brand_id == brand_id)
    stmt = stmt.order_by(desc(SocialListeningRule.created_at))
    rules = (await db.execute(stmt)).scalars().all()
    return [_rule_to_out(rule) for rule in rules]


@router.post("/", response_model=SLRuleOut, status_code=201)
async def create_rule(
    data: SLRuleCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    rule = SocialListeningRule(
        name=data.name,
        brand_id=data.brand_id,
        brand_terms=_json_dump(data.brand_terms),
        hashtags=_json_dump(data.hashtags),
        exclusions=_json_dump(data.exclusions),
        languages=_json_dump(data.languages),
        platforms=_json_dump(data.platforms),
        severity_threshold=data.severity_threshold,
        alert_on=data.alert_on,
        schedule_cron=data.schedule_cron,
        store_all=data.store_all,
        active=data.active,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _rule_to_out(rule)


@router.get("/{rule_id}", response_model=SLRuleOut)
async def get_rule(rule_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    rule = (await db.execute(select(SocialListeningRule).where(SocialListeningRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Not found")
    return _rule_to_out(rule)


@router.patch("/{rule_id}", response_model=SLRuleOut)
async def update_rule(
    rule_id: int,
    data: SLRuleUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    rule = (await db.execute(select(SocialListeningRule).where(SocialListeningRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Not found")

    payload = data.model_dump(exclude_unset=True)
    for key, value in payload.items():
        if key in {"brand_terms", "hashtags", "exclusions", "languages", "platforms"}:
            setattr(rule, key, _json_dump(value))
        else:
            setattr(rule, key, value)

    await db.commit()
    await db.refresh(rule)
    return _rule_to_out(rule)


@router.delete("/{rule_id}")
async def delete_rule(rule_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    rule = (await db.execute(select(SocialListeningRule).where(SocialListeningRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Not found")

    await db.delete(rule)
    await db.commit()
    return {"ok": True}


@router.post("/{rule_id}/activate", response_model=SLRuleOut)
async def activate_rule(rule_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    rule = (await db.execute(select(SocialListeningRule).where(SocialListeningRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Not found")

    rule.active = True
    await db.commit()
    await db.refresh(rule)
    return _rule_to_out(rule)


@router.post("/{rule_id}/deactivate", response_model=SLRuleOut)
async def deactivate_rule(rule_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    rule = (await db.execute(select(SocialListeningRule).where(SocialListeningRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Not found")

    rule.active = False
    await db.commit()
    await db.refresh(rule)
    return _rule_to_out(rule)


@router.post("/{rule_id}/run")
async def run_rule_now(rule_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    rule = (await db.execute(select(SocialListeningRule).where(SocialListeningRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Not found")

    collector = SocialListeningCollector()
    result = await collector.run_rule(rule, db)
    return {"ok": True, "job": result}
