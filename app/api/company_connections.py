"""Compare explicitly assigned infrastructure investigations."""
import ipaddress
import re
from collections import defaultdict
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import InfraFinding, InfraInvestigation, User

router = APIRouter()


class CompanyAssignment(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    investigation_ids: list[Annotated[int, Field(gt=0)]] = Field(min_length=1, max_length=50)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Company name must not be blank")
        return value

    @field_validator("investigation_ids")
    @classmethod
    def unique_ids(cls, value: list[int]) -> list[int]:
        if len(set(value)) != len(value):
            raise ValueError("Investigation IDs must be unique within a company")
        return value


class ConnectionRequest(BaseModel):
    companies: list[CompanyAssignment] = Field(min_length=2, max_length=20)

    @model_validator(mode="after")
    def unique_names(self):
        names = [company.name.casefold() for company in self.companies]
        if len(set(names)) != len(names):
            raise ValueError("Company names must be distinct")
        if len({i for c in self.companies for i in c.investigation_ids}) > 100:
            raise ValueError("Select at most 100 distinct investigations")
        return self


def _indicator(value: str, kind: str | None = None) -> tuple[str, str] | None:
    value = value.strip()
    if kind == "domain":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            return None
    if kind != "domain":
        try:
            return "ip", str(ipaddress.ip_address(value))
        except ValueError:
            if kind == "ip":
                return None
    if kind == "ip":
        return None
    value = value.rstrip(".").lower()
    if len(value) > 253 or "." not in value:
        return None
    labels = value.split(".")
    if all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        return "domain", value
    return None


@router.post("/graph")
async def company_connection_graph(
    body: ConnectionRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    ids = {i for company in body.companies for i in company.investigation_ids}
    investigations = (await db.execute(
        select(InfraInvestigation).where(InfraInvestigation.id.in_(ids))
    )).scalars().all()
    by_id = {investigation.id: investigation for investigation in investigations}
    missing = sorted(ids - by_id.keys())
    if missing:
        raise HTTPException(status_code=404, detail=f"Investigations not found: {missing}")
    incomplete = sorted(i for i in ids if by_id[i].status != "completed")
    if incomplete:
        raise HTTPException(status_code=409, detail=f"Investigations are not completed: {incomplete}")

    findings = (await db.execute(
        select(InfraFinding).where(InfraFinding.investigation_id.in_(ids)).order_by(InfraFinding.id)
    )).scalars().all()
    by_investigation = defaultdict(list)
    for finding in findings:
        by_investigation[finding.investigation_id].append(finding)

    observations = defaultdict(lambda: defaultdict(list))
    for company_index, company in enumerate(body.companies):
        for investigation_id in company.investigation_ids:
            investigation = by_id[investigation_id]
            if investigation.target_type in {"domain", "ip"}:
                indicator = _indicator(investigation.target, investigation.target_type)
                if indicator:
                    observations[indicator][company_index].append({
                        "investigation_id": investigation_id, "finding_id": None,
                        "finding_type": "target", "source": "user_assigned_target",
                        "recorded_at": investigation.created_at.isoformat() if investigation.created_at else None,
                    })
            for finding in by_investigation[investigation_id]:
                if finding.module != "dns" or finding.finding_type not in {"subdomain", "historical_dns", "reverse_ip"}:
                    continue
                kind = "domain" if finding.finding_type in {"subdomain", "reverse_ip"} else None
                indicator = _indicator(finding.entity, kind)
                if indicator:
                    observations[indicator][company_index].append({
                        "investigation_id": investigation_id, "finding_id": finding.id,
                        "finding_type": finding.finding_type, "source": finding.source,
                        "recorded_at": finding.created_at.isoformat() if finding.created_at else None,
                    })

    shared = []
    for (kind, value), companies in sorted(observations.items()):
        if len(companies) < 2:
            continue
        shared.append({
            "type": kind, "value": value,
            "companies": [
                {"company_index": index, "evidence": evidence}
                for index, evidence in sorted(companies.items())
            ],
        })
    return {
        "companies": [company.model_dump() for company in body.companies],
        "shared_indicators": shared,
        "notice": (
            "Assignments are user-provided. Shared infrastructure is a lead, not proof of ownership "
            "or a relationship. Historical DNS may be stale; absence of a match does not prove "
            "absence of a connection. Findings and source coverage may be incomplete."
        ),
    }
