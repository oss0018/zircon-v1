import json
from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import VSScan, VSScanTarget, VSFinding, VSReport, VSCustomTemplate, User
from app.services.vulnscan import VulnScanOrchestrator

router = APIRouter()

_VALID_TARGET_TYPES = {"web", "network", "api", "cidr"}
_VALID_SCOPES = {"SELF", "INTERNAL", "THREAT_INTEL"}
_VALID_PROFILES = {"quick", "standard", "deep"}
_VALID_SCAN_STATUS = {"pending", "running", "completed", "failed", "cancelled"}
_VALID_FINDING_STATUS = {"new", "confirmed", "false_positive", "accepted_risk", "remediated", "retest_pending"}


class TargetCreate(BaseModel):
    name: str
    target_type: str = "web"
    target_value: str
    scope: str = "SELF"
    default_profile: str = "standard"
    tags: list[str] = []
    schedule_cron: str | None = None
    notify_channels: list[str] = ["email", "telegram"]


class TargetUpdate(BaseModel):
    name: str | None = None
    target_type: str | None = None
    target_value: str | None = None
    scope: str | None = None
    default_profile: str | None = None
    tags: list[str] | None = None
    schedule_cron: str | None = None
    notify_channels: list[str] | None = None
    active: bool | None = None


class ScanLaunchRequest(BaseModel):
    profile: str = "standard"
    scope: str = "SELF"
    scanners: list[str] | None = None
    notify_on_complete: bool = True
    report_formats: list[str] = ["json"]
    comment: str = ""


class FindingStatusUpdate(BaseModel):
    status: str
    false_positive_reason: str | None = None
    accepted_risk_reason: str | None = None


class TemplateCreate(BaseModel):
    name: str
    template_id: str
    yaml_content: str
    severity: str = "medium"
    tags: list[str] = []


class TemplateUpdate(BaseModel):
    name: str | None = None
    yaml_content: str | None = None
    severity: str | None = None
    tags: list[str] | None = None
    is_active: bool | None = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def _run_scan_bg(scan_id: int) -> None:
    orchestrator = VulnScanOrchestrator()
    await orchestrator.run(scan_id)


@router.get("/targets")
async def list_targets(
    limit: int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(
        select(VSScanTarget).order_by(VSScanTarget.created_at.desc()).limit(min(limit, 200)).offset(offset)
    )
    targets = result.scalars().all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "target_type": t.target_type,
            "target_value": t.target_value,
            "scope": t.scope,
            "tags": json.loads(t.tags_json or "[]"),
            "default_profile": t.default_profile,
            "schedule_cron": t.schedule_cron,
            "notify_channels": json.loads(t.notify_channels_json or "[]"),
            "active": t.active,
            "created_at": t.created_at.isoformat() if t.created_at else None,
            "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        }
        for t in targets
    ]


@router.post("/targets")
async def create_target(
    body: TargetCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if body.target_type not in _VALID_TARGET_TYPES:
        raise HTTPException(status_code=400, detail="Invalid target_type")
    if body.scope not in _VALID_SCOPES:
        raise HTTPException(status_code=400, detail="Invalid scope")
    if body.default_profile not in _VALID_PROFILES:
        raise HTTPException(status_code=400, detail="Invalid default_profile")

    target = VSScanTarget(
        name=body.name[:255],
        target_type=body.target_type,
        target_value=body.target_value,
        scope=body.scope,
        tags_json=json.dumps(body.tags),
        default_profile=body.default_profile,
        schedule_cron=body.schedule_cron,
        notify_channels_json=json.dumps(body.notify_channels),
        created_by=current_user.id,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return {"id": target.id, "status": "created"}


@router.get("/targets/{target_id}")
async def get_target(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    target_result = await db.execute(select(VSScanTarget).where(VSScanTarget.id == target_id))
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    last_scan_result = await db.execute(
        select(VSScan).where(VSScan.target_id == target_id).order_by(desc(VSScan.created_at)).limit(1)
    )
    last_scan = last_scan_result.scalar_one_or_none()

    return {
        "id": target.id,
        "name": target.name,
        "target_type": target.target_type,
        "target_value": target.target_value,
        "scope": target.scope,
        "tags": json.loads(target.tags_json or "[]"),
        "default_profile": target.default_profile,
        "schedule_cron": target.schedule_cron,
        "notify_channels": json.loads(target.notify_channels_json or "[]"),
        "active": target.active,
        "last_scan": (
            {
                "id": last_scan.id,
                "status": last_scan.status,
                "profile": last_scan.profile,
                "findings_total": last_scan.findings_total,
                "overall_risk": last_scan.overall_risk,
                "completed_at": last_scan.completed_at.isoformat() if last_scan.completed_at else None,
            }
            if last_scan
            else None
        ),
    }


@router.patch("/targets/{target_id}")
async def update_target(
    target_id: int,
    body: TargetUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(VSScanTarget).where(VSScanTarget.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    data = body.model_dump(exclude_none=True)
    if "target_type" in data and data["target_type"] not in _VALID_TARGET_TYPES:
        raise HTTPException(status_code=400, detail="Invalid target_type")
    if "scope" in data and data["scope"] not in _VALID_SCOPES:
        raise HTTPException(status_code=400, detail="Invalid scope")
    if "default_profile" in data and data["default_profile"] not in _VALID_PROFILES:
        raise HTTPException(status_code=400, detail="Invalid default_profile")

    for key, value in data.items():
        if key == "tags":
            target.tags_json = json.dumps(value)
        elif key == "notify_channels":
            target.notify_channels_json = json.dumps(value)
        else:
            setattr(target, key, value)

    await db.commit()
    return {"ok": True}


@router.delete("/targets/{target_id}")
async def delete_target(
    target_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(VSScanTarget).where(VSScanTarget.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete(target)
    await db.commit()
    return {"ok": True}


@router.post("/targets/{target_id}/scan", status_code=202)
async def launch_scan(
    target_id: int,
    body: ScanLaunchRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    target_result = await db.execute(select(VSScanTarget).where(VSScanTarget.id == target_id))
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    if body.profile not in _VALID_PROFILES:
        raise HTTPException(status_code=400, detail="Invalid profile")
    if body.scope not in _VALID_SCOPES:
        raise HTTPException(status_code=400, detail="Invalid scope")

    scan = VSScan(
        target_id=target_id,
        profile=body.profile,
        scope=body.scope,
        status="pending",
        scanners_used_json=json.dumps(body.scanners or []),
        initiated_by=current_user.id,
        comment=body.comment,
        created_at=_utcnow(),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    background_tasks.add_task(_run_scan_bg, scan.id)

    estimates = {"quick": 5, "standard": 15, "deep": 30}
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "estimated_duration_minutes": estimates.get(body.profile, 15),
    }


@router.get("/scans")
async def list_scans(
    target_id: int | None = None,
    profile: str | None = None,
    status: str | None = None,
    limit: int = 20,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(VSScan).order_by(VSScan.created_at.desc())
    if target_id is not None:
        query = query.where(VSScan.target_id == target_id)
    if profile is not None:
        query = query.where(VSScan.profile == profile)
    if status is not None:
        query = query.where(VSScan.status == status)

    result = await db.execute(query.limit(min(limit, 200)).offset(offset))
    scans = result.scalars().all()
    return [
        {
            "id": s.id,
            "target_id": s.target_id,
            "profile": s.profile,
            "scope": s.scope,
            "status": s.status,
            "progress_pct": s.progress_pct,
            "findings_total": s.findings_total,
            "findings_critical": s.findings_critical,
            "findings_high": s.findings_high,
            "findings_medium": s.findings_medium,
            "findings_low": s.findings_low,
            "findings_info": s.findings_info,
            "overall_risk": s.overall_risk,
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in scans
    ]


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    scan_result = await db.execute(select(VSScan).where(VSScan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(select(VSFinding).where(VSFinding.scan_id == scan_id).order_by(VSFinding.id.desc()))
    findings = findings_result.scalars().all()

    return {
        "id": scan.id,
        "target_id": scan.target_id,
        "profile": scan.profile,
        "scope": scan.scope,
        "status": scan.status,
        "progress_pct": scan.progress_pct,
        "scanners_used": json.loads(scan.scanners_used_json or "[]"),
        "findings_total": scan.findings_total,
        "findings_critical": scan.findings_critical,
        "findings_high": scan.findings_high,
        "findings_medium": scan.findings_medium,
        "findings_low": scan.findings_low,
        "findings_info": scan.findings_info,
        "overall_risk": scan.overall_risk,
        "error_message": scan.error_message,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "duration_ms": scan.duration_ms,
        "findings": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity,
                "status": f.status,
                "scanner_source": f.scanner_source,
                "finding_type": f.finding_type,
            }
            for f in findings
        ],
    }


@router.delete("/scans/{scan_id}")
async def cancel_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(VSScan).where(VSScan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status not in {"pending", "running"}:
        return {"ok": True, "status": scan.status}

    scan.status = "cancelled"
    scan.completed_at = _utcnow()
    await db.commit()
    return {"ok": True, "status": scan.status}


@router.get("/scans/{scan_id}/findings")
async def list_scan_findings(
    scan_id: int,
    severity: str | None = None,
    status: str | None = None,
    scanner: str | None = None,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    query = select(VSFinding).where(VSFinding.scan_id == scan_id).order_by(VSFinding.severity_numeric.desc(), VSFinding.id.desc())
    if severity:
        query = query.where(VSFinding.severity == severity.upper())
    if status:
        query = query.where(VSFinding.status == status)
    if scanner:
        query = query.where(VSFinding.scanner_source == scanner)

    result = await db.execute(query.limit(min(limit, 500)).offset(offset))
    findings = result.scalars().all()
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "scanner_source": f.scanner_source,
            "finding_type": f.finding_type,
            "target_url": f.target_url,
            "created_at": f.created_at.isoformat() if f.created_at else None,
        }
        for f in findings
    ]


@router.get("/scans/{scan_id}/summary")
async def scan_summary(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    scan_result = await db.execute(select(VSScan).where(VSScan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings_result = await db.execute(select(VSFinding).where(VSFinding.scan_id == scan_id))
    findings = findings_result.scalars().all()

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    owasp_distribution: dict[str, int] = {}

    for finding in findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        if finding.owasp_category:
            owasp_distribution[finding.owasp_category] = owasp_distribution.get(finding.owasp_category, 0) + 1

    return {
        "scan_id": scan.id,
        "status": scan.status,
        "overall_risk": scan.overall_risk,
        "severity_counts": severity_counts,
        "owasp_distribution": owasp_distribution,
    }


@router.get("/findings/{finding_id}")
async def get_finding(
    finding_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(VSFinding).where(VSFinding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "target_id": finding.target_id,
        "scanner_source": finding.scanner_source,
        "scanner_finding_id": finding.scanner_finding_id,
        "title": finding.title,
        "description": finding.description,
        "finding_type": finding.finding_type,
        "owasp_category": finding.owasp_category,
        "severity": finding.severity,
        "severity_numeric": finding.severity_numeric,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "cve_ids": json.loads(finding.cve_ids_json or "[]"),
        "cwe_ids": json.loads(finding.cwe_ids_json or "[]"),
        "target_url": finding.target_url,
        "target_host": finding.target_host,
        "target_ip": finding.target_ip,
        "target_port": finding.target_port,
        "evidence": finding.evidence,
        "remediation_summary": finding.remediation_summary,
        "remediation_steps": json.loads(finding.remediation_steps_json or "[]"),
        "references": json.loads(finding.references_json or "[]"),
        "status": finding.status,
        "false_positive_reason": finding.false_positive_reason,
        "accepted_risk_reason": finding.accepted_risk_reason,
        "fingerprint": finding.fingerprint,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
        "updated_at": finding.updated_at.isoformat() if finding.updated_at else None,
    }


@router.patch("/findings/{finding_id}/status")
async def update_finding_status(
    finding_id: int,
    body: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if body.status not in _VALID_FINDING_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")

    result = await db.execute(select(VSFinding).where(VSFinding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = body.status
    finding.false_positive_reason = body.false_positive_reason
    finding.accepted_risk_reason = body.accepted_risk_reason
    finding.reviewed_by = current_user.id
    finding.reviewed_at = _utcnow()
    await db.commit()
    return {"ok": True}


@router.get("/templates")
async def list_templates(
    limit: int = 100,
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(VSCustomTemplate).order_by(VSCustomTemplate.created_at.desc()).limit(min(limit, 200)).offset(offset))
    rows = result.scalars().all()
    return [
        {
            "id": t.id,
            "name": t.name,
            "template_id": t.template_id,
            "severity": t.severity,
            "tags": json.loads(t.tags_json or "[]"),
            "is_active": t.is_active,
        }
        for t in rows
    ]


@router.post("/templates")
async def create_template(
    body: TemplateCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    existing = await db.execute(select(VSCustomTemplate).where(VSCustomTemplate.template_id == body.template_id))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="template_id already exists")

    tpl = VSCustomTemplate(
        name=body.name[:255],
        template_id=body.template_id[:100],
        yaml_content=body.yaml_content,
        severity=body.severity,
        tags_json=json.dumps(body.tags),
        created_by=current_user.id,
    )
    db.add(tpl)
    await db.commit()
    await db.refresh(tpl)
    return {"id": tpl.id, "status": "created"}


@router.get("/templates/{template_id}")
async def get_template(
    template_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(VSCustomTemplate).where(VSCustomTemplate.id == template_id))
    tpl = result.scalar_one_or_none()
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")

    return {
        "id": tpl.id,
        "name": tpl.name,
        "template_id": tpl.template_id,
        "yaml_content": tpl.yaml_content,
        "severity": tpl.severity,
        "tags": json.loads(tpl.tags_json or "[]"),
        "is_active": tpl.is_active,
        "created_at": tpl.created_at.isoformat() if tpl.created_at else None,
        "updated_at": tpl.updated_at.isoformat() if tpl.updated_at else None,
    }


@router.patch("/templates/{template_id}")
async def update_template(
    template_id: int,
    body: TemplateUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(VSCustomTemplate).where(VSCustomTemplate.id == template_id))
    tpl = result.scalar_one_or_none()
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")

    for key, value in body.model_dump(exclude_none=True).items():
        if key == "tags":
            tpl.tags_json = json.dumps(value)
        else:
            setattr(tpl, key, value)

    await db.commit()
    return {"ok": True}


@router.delete("/templates/{template_id}")
async def delete_template(
    template_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(VSCustomTemplate).where(VSCustomTemplate.id == template_id))
    tpl = result.scalar_one_or_none()
    if not tpl:
        raise HTTPException(status_code=404, detail="Template not found")
    await db.delete(tpl)
    await db.commit()
    return {"ok": True}


@router.get("/dashboard/summary")
async def dashboard_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    total_targets = (
        await db.execute(select(func.count()).select_from(VSScanTarget))
    ).scalar_one()

    severity_rows = (
        await db.execute(select(VSFinding.severity, func.count()).group_by(VSFinding.severity))
    ).all()
    findings_by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for severity, count in severity_rows:
        findings_by_severity[severity] = count

    scans_result = await db.execute(select(VSScan).order_by(VSScan.created_at.desc()).limit(10))
    scans = scans_result.scalars().all()

    return {
        "total_targets": total_targets,
        "findings_by_severity": findings_by_severity,
        "recent_scans": [
            {
                "id": s.id,
                "target_id": s.target_id,
                "status": s.status,
                "profile": s.profile,
                "overall_risk": s.overall_risk,
                "findings_total": s.findings_total,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
            }
            for s in scans
        ],
    }
