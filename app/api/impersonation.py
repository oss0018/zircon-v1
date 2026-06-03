"""
Impersonation Monitoring API — TS-IMP-001
Router prefix: /api/v1/impersonation
"""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import ImpersonationFinding, ImpersonationRule, TakedownRequest, User
from app.schemas import (
    ImpersonationFindingOut,
    ImpersonationFindingStatusUpdate,
    ImpersonationRuleCreate,
    ImpersonationRuleOut,
    ImpersonationRuleUpdate,
    TakedownRequestCreate,
    TakedownRequestOut,
    TakedownRequestUpdate,
)
from app.services.impersonation.scanner import run_scan_for_rule
from app.utils.sanitize import sanitize_string

logger = logging.getLogger(__name__)
router = APIRouter()

TAKEDOWN_CONTACTS = {
    'telegram': {'method': 'form', 'url': 'https://telegram.org/support', 'avg_response_hours': 72},
    'instagram': {'method': 'form', 'url': 'https://help.instagram.com/contact/636276399721841', 'avg_response_hours': 48},
    'vk': {'method': 'email', 'abuse_email': 'support@vk.com', 'avg_response_hours': 24},
    'facebook': {'method': 'form', 'url': 'https://www.facebook.com/help/contact/169486816475808', 'avg_response_hours': 72},
    'youtube': {'method': 'form', 'url': 'https://support.google.com/youtube/answer/2802057', 'avg_response_hours': 48},
    'google_play': {'method': 'form', 'url': 'https://play.google.com/about/ip.html', 'avg_response_hours': 72},
    'google_ads': {'method': 'form', 'url': 'https://support.google.com/google-ads/contact/trademark_complaint', 'avg_response_hours': 48},
    'yandex': {'method': 'email', 'abuse_email': 'abuse@yandex-team.ru', 'avg_response_hours': 48},
    'namecheap': {'method': 'email', 'abuse_email': 'abuse@namecheap.com', 'avg_response_hours': 24},
    'godaddy': {'method': 'email', 'abuse_email': 'abuse@godaddy.com', 'avg_response_hours': 24},
    'cloudflare': {'method': 'api', 'api_url': 'https://api.cloudflare.com/client/v4/abuse', 'avg_response_hours': 24},
}

SOCIAL_TAKEDOWN_TEMPLATE = """
Subject: Trademark Infringement & Impersonation Report — {brand_name}

Dear {platform} Trust & Safety Team,

We are writing on behalf of {org_name}, the registered owner of the trademark "{trademark_name}" (Registration No. {tm_reg_no}).

We have identified an account on your platform that is impersonating our brand:

Account URL:      {target_url}
Account Handle:   {target_identifier}
Display Name:     {display_name}
Threat Score:     {threat_score}/100
Detected Signals: {signals}
First Detected:   {first_seen}

We request immediate removal of this account.

Contact: {contact_name} <{contact_email}>
""".strip()

DOMAIN_TAKEDOWN_TEMPLATE = """
Subject: Phishing Domain Abuse Report — {target_identifier}

To Whom It May Concern,

{org_name} hereby reports the domain {target_identifier} as being used for brand impersonation of "{brand_name}" (Trademark Reg. No. {tm_reg_no}).

Target URL:       {target_url}
Threat Score:     {threat_score}/100
Detected Signals: {signals}
First Detected:   {first_seen}

We request immediate suspension of this domain.

Contact: {contact_name} <{contact_email}>
""".strip()

_DOMAIN_MODULES = {"m3", "m7", "m8"}
_PENDING_TAKEDOWN_STATUSES = {"draft", "pending_review", "submitted"}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _json_load(value: str, default: Any):
    try:
        return json.loads(value or "")
    except Exception:
        return default


def _json_dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _sanitize_text(value: Optional[str], max_length: int) -> str:
    return sanitize_string((value or "").strip(), max_length=max_length)


def _sanitize_list(values: Optional[list[str]], max_length: int) -> list[str]:
    seen: set[str] = set()
    cleaned: list[str] = []
    for item in values or []:
        safe = sanitize_string(str(item).strip(), max_length=max_length)
        if safe and safe not in seen:
            seen.add(safe)
            cleaned.append(safe)
    return cleaned


def _rule_to_out(rule: ImpersonationRule, findings_count: int = 0) -> ImpersonationRuleOut:
    return ImpersonationRuleOut.model_validate(
        {
            "id": rule.id,
            "brand_id": rule.brand_id,
            "name": rule.name,
            "brand_name": rule.brand_name,
            "brand_name_uk": rule.brand_name_uk or "",
            "brand_name_ru": rule.brand_name_ru or "",
            "official_domains": rule.official_domains or "[]",
            "official_developer_ids": rule.official_developer_ids or "[]",
            "executive_names": rule.executive_names or "[]",
            "partner_domains": rule.partner_domains or "[]",
            "trademark_name": rule.trademark_name or "",
            "trademark_reg_no": rule.trademark_reg_no or "",
            "org_name": rule.org_name or "",
            "contact_name": rule.contact_name or "",
            "contact_email": rule.contact_email or "",
            "contact_phone": rule.contact_phone or "",
            "m1_social_enabled": rule.m1_social_enabled,
            "m2_apps_enabled": rule.m2_apps_enabled,
            "m3_email_enabled": rule.m3_email_enabled,
            "m5_exec_enabled": rule.m5_exec_enabled,
            "m6_ads_enabled": rule.m6_ads_enabled,
            "m7_vip_enabled": rule.m7_vip_enabled,
            "m8_domain_enabled": rule.m8_domain_enabled,
            "social_platforms": rule.social_platforms or '[]',
            "min_impersonation_score": rule.min_impersonation_score,
            "schedule_cron": rule.schedule_cron,
            "active": rule.active,
            "last_scan_at": rule.last_scan_at,
            "findings_count": findings_count,
            "created_at": rule.created_at,
            "updated_at": rule.updated_at,
        }
    )


def _finding_to_out(finding: ImpersonationFinding) -> ImpersonationFindingOut:
    return ImpersonationFindingOut.model_validate(finding)


def _takedown_to_out(request: TakedownRequest) -> TakedownRequestOut:
    return TakedownRequestOut.model_validate(request)


async def _get_rule_or_404(db: AsyncSession, rule_id: int) -> ImpersonationRule:
    rule = (await db.execute(select(ImpersonationRule).where(ImpersonationRule.id == rule_id))).scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


async def _get_finding_or_404(db: AsyncSession, finding_id: int) -> ImpersonationFinding:
    finding = (await db.execute(select(ImpersonationFinding).where(ImpersonationFinding.id == finding_id))).scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


async def _get_takedown_or_404(db: AsyncSession, takedown_id: int) -> TakedownRequest:
    takedown = (await db.execute(select(TakedownRequest).where(TakedownRequest.id == takedown_id))).scalar_one_or_none()
    if not takedown:
        raise HTTPException(status_code=404, detail="Takedown request not found")
    return takedown


def _finding_filters(
    rule_id: Optional[int],
    module: Optional[str],
    platform: Optional[str],
    status: Optional[str],
    min_score: int,
):
    filters = []
    if rule_id is not None:
        filters.append(ImpersonationFinding.rule_id == rule_id)
    if module:
        filters.append(ImpersonationFinding.module == _sanitize_text(module, 10).lower())
    if platform:
        filters.append(ImpersonationFinding.platform.ilike(f"%{_sanitize_text(platform, 50)}%"))
    if status:
        filters.append(ImpersonationFinding.status == _sanitize_text(status, 30))
    filters.append(ImpersonationFinding.threat_score >= min_score)
    return filters


def _render_takedown_cover_letter(rule: ImpersonationRule, finding: ImpersonationFinding) -> str:
    signals = ", ".join(_json_load(finding.signals_json or "[]", [])) or "N/A"
    values = {
        "brand_name": rule.brand_name,
        "platform": (finding.platform or "Platform").replace("_", " ").title(),
        "org_name": rule.org_name or rule.brand_name,
        "trademark_name": rule.trademark_name or rule.brand_name,
        "tm_reg_no": rule.trademark_reg_no or "N/A",
        "target_url": finding.target_url or finding.target_identifier,
        "target_identifier": finding.target_identifier,
        "display_name": finding.display_name or finding.target_identifier,
        "threat_score": finding.threat_score,
        "signals": signals,
        "first_seen": finding.first_seen.isoformat() if finding.first_seen else "N/A",
        "contact_name": rule.contact_name or "Security Team",
        "contact_email": rule.contact_email or "",
    }
    template = DOMAIN_TAKEDOWN_TEMPLATE if finding.module in _DOMAIN_MODULES else SOCIAL_TAKEDOWN_TEMPLATE
    return template.format(**values)


@router.get("/rules", response_model=list[ImpersonationRuleOut])
async def list_rules(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    rules = (await db.execute(select(ImpersonationRule).order_by(ImpersonationRule.created_at.desc()))).scalars().all()
    count_rows = (
        await db.execute(
            select(ImpersonationFinding.rule_id, func.count(ImpersonationFinding.id))
            .group_by(ImpersonationFinding.rule_id)
        )
    ).all()
    counts = {rule_id: count for rule_id, count in count_rows}
    return [_rule_to_out(rule, counts.get(rule.id, 0)) for rule in rules]


@router.post("/rules", response_model=ImpersonationRuleOut, status_code=201)
async def create_rule(
    body: ImpersonationRuleCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    rule = ImpersonationRule(
        name=_sanitize_text(body.name, 200),
        brand_id=body.brand_id,
        brand_name=_sanitize_text(body.brand_name, 100),
        brand_name_uk=_sanitize_text(body.brand_name_uk, 100),
        brand_name_ru=_sanitize_text(body.brand_name_ru, 100),
        official_domains=_json_dump(_sanitize_list(body.official_domains, 253)),
        official_developer_ids=_json_dump(_sanitize_list(body.official_developer_ids, 200)),
        executive_names=_json_dump(_sanitize_list(body.executive_names, 200)),
        partner_domains=_json_dump(_sanitize_list(body.partner_domains, 253)),
        trademark_name=_sanitize_text(body.trademark_name, 200),
        trademark_reg_no=_sanitize_text(body.trademark_reg_no, 100),
        org_name=_sanitize_text(body.org_name, 200),
        contact_name=_sanitize_text(body.contact_name, 200),
        contact_email=_sanitize_text(body.contact_email, 256),
        contact_phone=_sanitize_text(body.contact_phone, 50),
        m1_social_enabled=body.m1_social_enabled,
        m2_apps_enabled=body.m2_apps_enabled,
        m3_email_enabled=body.m3_email_enabled,
        m5_exec_enabled=body.m5_exec_enabled,
        m6_ads_enabled=body.m6_ads_enabled,
        m7_vip_enabled=body.m7_vip_enabled,
        m8_domain_enabled=body.m8_domain_enabled,
        social_platforms=_json_dump(_sanitize_list(body.social_platforms, 50)),
        min_impersonation_score=body.min_impersonation_score,
        schedule_cron=_sanitize_text(body.schedule_cron, 100) or "0 */6 * * *",
        active=body.active,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _rule_to_out(rule)


@router.get("/rules/{rule_id}", response_model=ImpersonationRuleOut)
async def get_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    rule = await _get_rule_or_404(db, rule_id)
    findings_count = (
        await db.execute(select(func.count(ImpersonationFinding.id)).where(ImpersonationFinding.rule_id == rule_id))
    ).scalar_one()
    return _rule_to_out(rule, int(findings_count))


@router.put("/rules/{rule_id}", response_model=ImpersonationRuleOut)
async def update_rule(
    rule_id: int,
    body: ImpersonationRuleUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    rule = await _get_rule_or_404(db, rule_id)
    updates = body.model_dump(exclude_unset=True)
    json_fields = {
        "official_domains": 253,
        "official_developer_ids": 200,
        "executive_names": 200,
        "partner_domains": 253,
        "social_platforms": 50,
    }
    text_fields = {
        "name": 200,
        "brand_name": 100,
        "brand_name_uk": 100,
        "brand_name_ru": 100,
        "trademark_name": 200,
        "trademark_reg_no": 100,
        "org_name": 200,
        "contact_name": 200,
        "contact_email": 256,
        "contact_phone": 50,
        "schedule_cron": 100,
    }
    for field, value in updates.items():
        if field in json_fields:
            setattr(rule, field, _json_dump(_sanitize_list(value, json_fields[field])))
        elif field in text_fields:
            setattr(rule, field, _sanitize_text(value, text_fields[field]))
        else:
            setattr(rule, field, value)
    await db.commit()
    await db.refresh(rule)
    findings_count = (
        await db.execute(select(func.count(ImpersonationFinding.id)).where(ImpersonationFinding.rule_id == rule_id))
    ).scalar_one()
    return _rule_to_out(rule, int(findings_count))


@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    rule = await _get_rule_or_404(db, rule_id)
    await db.delete(rule)
    await db.commit()
    return {"deleted": True, "rule_id": rule_id}


@router.get("/findings/export")
async def export_findings(
    rule_id: Optional[int] = Query(None),
    module: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    min_score: int = Query(0, ge=0, le=100),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    stmt = select(ImpersonationFinding)
    filters = _finding_filters(rule_id, module, platform, status, min_score)
    for filter_clause in filters:
        stmt = stmt.where(filter_clause)
    findings = (await db.execute(stmt.order_by(desc(ImpersonationFinding.last_seen)).limit(10000))).scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "rule_id", "module", "platform", "finding_type", "target_url", "target_identifier",
        "display_name", "threat_score", "status", "first_seen", "last_seen", "signals_json",
    ])
    for finding in findings:
        writer.writerow([
            finding.id,
            finding.rule_id,
            finding.module,
            finding.platform,
            finding.finding_type,
            finding.target_url,
            finding.target_identifier,
            finding.display_name,
            finding.threat_score,
            finding.status,
            finding.first_seen.isoformat() if finding.first_seen else "",
            finding.last_seen.isoformat() if finding.last_seen else "",
            finding.signals_json,
        ])

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=impersonation_findings.csv"},
    )


@router.get("/findings")
async def list_findings(
    rule_id: Optional[int] = Query(None),
    module: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    min_score: int = Query(0, ge=0, le=100),
    limit: int = Query(25, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    filters = _finding_filters(rule_id, module, platform, status, min_score)
    total_stmt = select(func.count(ImpersonationFinding.id))
    items_stmt = select(ImpersonationFinding)
    for filter_clause in filters:
        total_stmt = total_stmt.where(filter_clause)
        items_stmt = items_stmt.where(filter_clause)

    total = (await db.execute(total_stmt)).scalar_one()
    findings = (
        await db.execute(
            items_stmt.order_by(desc(ImpersonationFinding.last_seen)).limit(limit).offset(offset)
        )
    ).scalars().all()
    return {
        "items": [_finding_to_out(item).model_dump(mode="json") for item in findings],
        "total": int(total),
        "limit": limit,
        "offset": offset,
    }


@router.get("/findings/{finding_id}", response_model=ImpersonationFindingOut)
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return _finding_to_out(await _get_finding_or_404(db, finding_id))


@router.patch("/findings/{finding_id}", response_model=ImpersonationFindingOut)
async def update_finding_status(
    finding_id: int,
    body: ImpersonationFindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = await _get_finding_or_404(db, finding_id)
    if body.status == "false_positive" and not _sanitize_text(body.false_positive_reason, 1000):
        raise HTTPException(status_code=400, detail="false_positive_reason cannot be empty or whitespace-only")

    finding.status = body.status
    finding.false_positive_reason = (
        _sanitize_text(body.false_positive_reason, 1000) if body.status == "false_positive" else None
    )
    finding.reviewed_by = current_user.id
    finding.reviewed_at = _utcnow()
    await db.commit()
    await db.refresh(finding)
    return _finding_to_out(finding)


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    total = (await db.execute(select(func.count(ImpersonationFinding.id)))).scalar_one()
    high_risk = (
        await db.execute(select(func.count(ImpersonationFinding.id)).where(ImpersonationFinding.threat_score >= 80))
    ).scalar_one()
    pending_takedowns = (
        await db.execute(select(func.count(TakedownRequest.id)).where(TakedownRequest.status.in_(_PENDING_TAKEDOWN_STATUSES)))
    ).scalar_one()
    active_rules = (
        await db.execute(select(func.count(ImpersonationRule.id)).where(ImpersonationRule.active.is_(True)))
    ).scalar_one()

    module_rows = (
        await db.execute(
            select(ImpersonationFinding.module, func.count(ImpersonationFinding.id)).group_by(ImpersonationFinding.module)
        )
    ).all()
    new_rows = (
        await db.execute(
            select(ImpersonationFinding.module, func.count(ImpersonationFinding.id))
            .where(ImpersonationFinding.status == "new")
            .group_by(ImpersonationFinding.module)
        )
    ).all()
    resolved_rows = (
        await db.execute(
            select(ImpersonationFinding.module, func.count(ImpersonationFinding.id))
            .where(ImpersonationFinding.status == "resolved")
            .group_by(ImpersonationFinding.module)
        )
    ).all()
    status_rows = (
        await db.execute(
            select(ImpersonationFinding.status, func.count(ImpersonationFinding.id)).group_by(ImpersonationFinding.status)
        )
    ).all()
    platform_rows = (
        await db.execute(
            select(ImpersonationFinding.platform, func.count(ImpersonationFinding.id)).group_by(ImpersonationFinding.platform)
        )
    ).all()

    thresholds = {
        "0_39": (
            await db.execute(
                select(func.count(ImpersonationFinding.id)).where(ImpersonationFinding.threat_score < 40)
            )
        ).scalar_one(),
        "40_59": (
            await db.execute(
                select(func.count(ImpersonationFinding.id)).where(
                    ImpersonationFinding.threat_score >= 40,
                    ImpersonationFinding.threat_score < 60,
                )
            )
        ).scalar_one(),
        "60_79": (
            await db.execute(
                select(func.count(ImpersonationFinding.id)).where(
                    ImpersonationFinding.threat_score >= 60,
                    ImpersonationFinding.threat_score < 80,
                )
            )
        ).scalar_one(),
        "80_100": (
            await db.execute(
                select(func.count(ImpersonationFinding.id)).where(ImpersonationFinding.threat_score >= 80)
            )
        ).scalar_one(),
    }

    since = _utcnow() - timedelta(days=14)
    recent_rows = []
    try:
        recent_rows = (
            await db.execute(
                select(func.date_trunc("day", ImpersonationFinding.created_at), func.count(ImpersonationFinding.id))
                .where(ImpersonationFinding.created_at >= since)
                .group_by(func.date_trunc("day", ImpersonationFinding.created_at))
                .order_by(func.date_trunc("day", ImpersonationFinding.created_at))
            )
        ).all()
    except Exception:
        recent_rows = (
            await db.execute(
                select(func.strftime("%Y-%m-%d", ImpersonationFinding.created_at), func.count(ImpersonationFinding.id))
                .where(ImpersonationFinding.created_at >= since)
                .group_by(func.strftime("%Y-%m-%d", ImpersonationFinding.created_at))
                .order_by(func.strftime("%Y-%m-%d", ImpersonationFinding.created_at))
            )
        ).all()

    totals = {str(key): int(value) for key, value in module_rows}
    new_counts = {str(key): int(value) for key, value in new_rows}
    resolved_counts = {str(key): int(value) for key, value in resolved_rows}
    modules = ["m1", "m2", "m3", "m5", "m6", "m7", "m8"]

    return {
        "total": int(total),
        "high_risk": int(high_risk),
        "pending_takedowns": int(pending_takedowns),
        "active_rules": int(active_rules),
        "by_module": {
            module_key: {
                "total": totals.get(module_key, 0),
                "new": new_counts.get(module_key, 0),
                "resolved": resolved_counts.get(module_key, 0),
            }
            for module_key in modules
        },
        "by_status": {str(key or "unknown"): int(value) for key, value in status_rows},
        "by_platform": {str(key or "unknown"): int(value) for key, value in platform_rows},
        "threat_score_distribution": {bucket: int(count) for bucket, count in thresholds.items()},
        "recent_activity": [
            {"date": bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket), "count": int(count)}
            for bucket, count in recent_rows
        ],
    }


@router.post("/rules/{rule_id}/scan", status_code=202)
async def trigger_scan(
    rule_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    await _get_rule_or_404(db, rule_id)
    background_tasks.add_task(run_scan_for_rule, rule_id)
    return {"job": "started", "rule_id": rule_id}


@router.get("/takedowns", response_model=list[TakedownRequestOut])
async def list_takedowns(
    status: Optional[str] = Query(None),
    platform: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    stmt = select(TakedownRequest)
    if status:
        stmt = stmt.where(TakedownRequest.status == _sanitize_text(status, 30))
    if platform:
        stmt = stmt.where(TakedownRequest.target_platform.ilike(f"%{_sanitize_text(platform, 50)}%"))
    takedowns = (await db.execute(stmt.order_by(desc(TakedownRequest.created_at)).limit(1000))).scalars().all()
    return [_takedown_to_out(item) for item in takedowns]


@router.post("/takedowns", response_model=TakedownRequestOut, status_code=201)
async def create_takedown(
    body: TakedownRequestCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    finding = await _get_finding_or_404(db, body.finding_id)
    rule = await _get_rule_or_404(db, finding.rule_id)
    takedown = TakedownRequest(
        finding_id=finding.id,
        target_platform=_sanitize_text(finding.platform, 50),
        target_url=_sanitize_text(finding.target_url or finding.target_identifier, 2000),
        cover_letter=_render_takedown_cover_letter(rule, finding),
        submission_contact_json=_json_dump(TAKEDOWN_CONTACTS.get((finding.platform or "").lower(), {})),
        notes=_sanitize_text(body.notes, 2000),
    )
    db.add(takedown)
    finding.status = "takedown_requested"
    finding.reviewed_by = current_user.id
    finding.reviewed_at = _utcnow()
    await db.commit()
    await db.refresh(takedown)
    return _takedown_to_out(takedown)


@router.patch("/takedowns/{takedown_id}", response_model=TakedownRequestOut)
async def update_takedown(
    takedown_id: int,
    body: TakedownRequestUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    takedown = await _get_takedown_or_404(db, takedown_id)
    if body.status is not None:
        takedown.status = body.status
        if body.status == "submitted":
            takedown.submitted_at = _utcnow()
            takedown.submitted_by = current_user.id
        if body.status == "resolved":
            takedown.resolved_at = _utcnow()
    if body.notes is not None:
        takedown.notes = _sanitize_text(body.notes, 2000)
    await db.commit()
    await db.refresh(takedown)
    return _takedown_to_out(takedown)


@router.get("/takedowns/{takedown_id}", response_model=TakedownRequestOut)
async def get_takedown(
    takedown_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    return _takedown_to_out(await _get_takedown_or_404(db, takedown_id))


@router.get("/status")
async def impersonation_status(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    rules_count = (await db.execute(select(func.count(ImpersonationRule.id)))).scalar_one()
    findings_count = (await db.execute(select(func.count(ImpersonationFinding.id)))).scalar_one()
    pending_takedowns = (
        await db.execute(select(func.count(TakedownRequest.id)).where(TakedownRequest.status.in_(_PENDING_TAKEDOWN_STATUSES)))
    ).scalar_one()
    return {
        "module": "impersonation_monitoring",
        "rules_count": int(rules_count),
        "findings_count": int(findings_count),
        "pending_takedowns": int(pending_takedowns),
    }
