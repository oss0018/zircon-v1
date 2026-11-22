"""Export selected infrastructure records with an integrity manifest."""
import hashlib
import hmac
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import EvidenceArchive, EvidenceCustodyEvent, InfraFinding, InfraInvestigation, User

router = APIRouter()


class EvidenceRequest(BaseModel):
    investigation_id: int = Field(gt=0)
    finding_ids: list[Annotated[int, Field(gt=0)]] = Field(min_length=1, max_length=200)

    @field_validator("finding_ids")
    @classmethod
    def unique_findings(cls, value):
        if len(set(value)) != len(value):
            raise ValueError("Finding IDs must be unique")
        return value


def _time(value):
    return value.isoformat() if value else None


async def _build_archive(
    request: EvidenceRequest,
    db: AsyncSession,
    user: User,
):
    investigation = (await db.execute(select(InfraInvestigation).where(
        InfraInvestigation.id == request.investigation_id,
    ))).scalar_one_or_none()
    if investigation is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if investigation.status != "completed":
        raise HTTPException(status_code=409, detail="Investigation is not completed")
    findings = (await db.execute(select(InfraFinding).where(
        InfraFinding.investigation_id == investigation.id,
        InfraFinding.id.in_(request.finding_ids),
    ).order_by(InfraFinding.id))).scalars().all()
    if len(findings) != len(request.finding_ids):
        raise HTTPException(status_code=404, detail="One or more findings do not belong to this investigation")
    generated_at = datetime.now(timezone.utc).isoformat()
    content = {
        "format": "zircon-infrastructure-evidence-v1",
        "exported_at_utc": generated_at,
        "exported_by": {"id": user.id, "username": user.username},
        "investigation": {
            "id": investigation.id, "target": investigation.target, "target_type": investigation.target_type,
            "status": investigation.status, "modules_json": investigation.modules_json,
            "started_at": _time(investigation.started_at), "completed_at": _time(investigation.completed_at),
            "created_at": _time(investigation.created_at),
        },
        "findings": [{
            "id": finding.id, "module": finding.module, "finding_type": finding.finding_type,
            "entity": finding.entity, "severity": finding.severity, "source": finding.source,
            "data_json_raw": finding.data_json, "recorded_at": _time(finding.created_at),
        } for finding in findings],
    }
    data = json.dumps(content, ensure_ascii=False, indent=2).encode("utf-8")
    manifest = {
        "format": "zircon-evidence-manifest-v1",
        "exported_at_utc": generated_at,
        "files": [{"path": "findings.json", "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}],
        "limitations": (
            "This export contains platform records, not necessarily original source artifacts. "
            "The unsigned manifest does not prove authenticity, chain of custody or legal admissibility. "
            "Preserve the original source material and obtain legal review."
        ),
    }
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("findings.json", data)
        output.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))
    return archive.getvalue(), len(data)


@router.post("/infrastructure")
async def export_infrastructure_evidence(
    request: EvidenceRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    archive, _ = await _build_archive(request, db, user)
    return Response(
        content=archive, media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="infrastructure-evidence-{request.investigation_id}.zip"',
                 "Cache-Control": "no-store"},
    )


@router.post("/packages", status_code=201)
async def save_evidence_package(
    request: EvidenceRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    response.headers["Cache-Control"] = "no-store"
    archive_bytes, raw_size = await _build_archive(request, db, user)
    if raw_size > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Evidence records exceed the 10 MiB package limit")
    locked = await db.execute(update(User).where(User.id == user.id).values(username=User.username)
                              .execution_options(synchronize_session=False))
    if not locked.rowcount:
        raise HTTPException(status_code=401, detail="Account no longer exists")
    archive = EvidenceArchive(owner_id=user.id, investigation_id=request.investigation_id,
                              archive_bytes=archive_bytes, sha256=hashlib.sha256(archive_bytes).hexdigest())
    db.add(archive)
    await db.flush()
    db.add(EvidenceCustodyEvent(archive_id=archive.id, actor_id=user.id,
                                actor_username=user.username, action="package_created"))
    await db.commit()
    await db.refresh(archive)
    return {"id": archive.id, "investigation_id": archive.investigation_id,
            "sha256": archive.sha256, "created_at": archive.created_at}


@router.get("/packages")
async def list_evidence_packages(
    response: Response,
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    response.headers["Cache-Control"] = "no-store"
    rows = (await db.execute(select(
        EvidenceArchive.id, EvidenceArchive.investigation_id, EvidenceArchive.sha256, EvidenceArchive.created_at,
    ).where(EvidenceArchive.owner_id == user.id).order_by(EvidenceArchive.id.desc())
      .offset(offset).limit(50))).all()
    return [{"id": row.id, "investigation_id": row.investigation_id, "sha256": row.sha256,
             "created_at": row.created_at} for row in rows]


async def _owned_archive(archive_id: int, db: AsyncSession, user: User) -> EvidenceArchive:
    archive = (await db.execute(select(EvidenceArchive).where(
        EvidenceArchive.id == archive_id, EvidenceArchive.owner_id == user.id,
    ))).scalar_one_or_none()
    if archive is None:
        raise HTTPException(status_code=404, detail="Evidence package not found")
    return archive


@router.get("/packages/{archive_id}/events")
async def evidence_custody_events(
    archive_id: int, response: Response, offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    response.headers["Cache-Control"] = "no-store"
    owner_match = (await db.execute(select(EvidenceArchive.id).where(
        EvidenceArchive.id == archive_id, EvidenceArchive.owner_id == user.id,
    ))).scalar_one_or_none()
    if owner_match is None:
        raise HTTPException(status_code=404, detail="Evidence package not found")
    events = (await db.execute(select(EvidenceCustodyEvent).where(
        EvidenceCustodyEvent.archive_id == archive_id,
    ).order_by(EvidenceCustodyEvent.id.desc()).offset(offset).limit(50))).scalars().all()
    return [{"id": event.id, "action": event.action, "actor_id": event.actor_id,
             "actor_username": event.actor_username, "recorded_at": event.recorded_at} for event in events]


@router.get("/packages/{archive_id}/download")
async def download_evidence_package(
    archive_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(get_current_user),
):
    archive = await _owned_archive(archive_id, db, user)
    intact = hmac.compare_digest(hashlib.sha256(archive.archive_bytes).hexdigest(), archive.sha256)
    db.add(EvidenceCustodyEvent(archive_id=archive.id, actor_id=user.id, actor_username=user.username,
                                action="download_requested" if intact else "integrity_check_failed"))
    await db.commit()
    if not intact:
        raise HTTPException(status_code=409, detail="Evidence package integrity check failed",
                            headers={"Cache-Control": "no-store"})
    return Response(content=archive.archive_bytes, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="evidence-package-{archive.id}.zip"',
        "Cache-Control": "no-store",
    })
