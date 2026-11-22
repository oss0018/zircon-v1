"""Export selected infrastructure records with an integrity manifest."""
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import InfraFinding, InfraInvestigation, User

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


@router.post("/infrastructure")
async def export_infrastructure_evidence(
    request: EvidenceRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
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
    return Response(
        content=archive.getvalue(), media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="infrastructure-evidence-{investigation.id}.zip"',
                 "Cache-Control": "no-store"},
    )
