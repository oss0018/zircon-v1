"""Compare explicitly assigned infrastructure investigations."""
import ipaddress
import json
import re
from collections import defaultdict
from typing import Annotated, Literal

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import InfraFinding, InfraInvestigation, User
from app.services.wallet_monitoring import normalize_address

router = APIRouter()

_TLS_CERT_TYPES = {
    "certificate", "expired_cert", "expiring_cert", "self_signed_cert",
    "hostname_mismatch_cert", "untrusted_issuer_cert",
}
_SHA256 = re.compile(r"(?:[0-9a-fA-F]{64}|(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2})\Z")


class WalletAssignment(BaseModel):
    chain: Literal["btc", "usdt_trc20"]
    address: str = Field(max_length=100)

    @model_validator(mode="after")
    def normalize(self):
        self.address = normalize_address(self.chain, self.address)
        return self


class CompanyAssignment(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    investigation_ids: list[Annotated[int, Field(gt=0)]] = Field(default_factory=list, max_length=50)
    wallets: list[WalletAssignment] = Field(default_factory=list, max_length=50)

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

    @model_validator(mode="after")
    def validate_sources(self):
        if not self.investigation_ids and not self.wallets:
            raise ValueError("Assign at least one investigation or wallet to each company")
        wallets = [(wallet.chain, wallet.address) for wallet in self.wallets]
        if len(set(wallets)) != len(wallets):
            raise ValueError("Wallets must be unique within a company")
        return self


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


def _certificate_fingerprint(finding: InfraFinding) -> tuple[str | None, str]:
    try:
        data = json.loads(finding.data_json)
    except (TypeError, ValueError):
        return None, "malformed"
    if not isinstance(data, dict):
        return None, "malformed"
    fingerprint = data.get("sha256_fingerprint")
    if fingerprint is None or fingerprint == "":
        return None, "missing"
    if not isinstance(fingerprint, str) or not _SHA256.fullmatch(fingerprint):
        return None, "invalid"
    return fingerprint.replace(":", "").lower(), "available"


def _record_ip(finding: InfraFinding) -> tuple[tuple[str, str] | None, str]:
    try:
        data = json.loads(finding.data_json)
    except (TypeError, ValueError):
        return None, "malformed"
    if not isinstance(data, dict):
        return None, "malformed"
    ip = data.get("ip")
    if ip is None or ip == "":
        return None, "missing"
    if not isinstance(ip, str):
        return None, "invalid"
    indicator = _indicator(ip, "ip")
    return (indicator, "available") if indicator else (None, "invalid")


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
    cert_coverage = {"tls_findings": 0, "available": 0, "missing": 0, "malformed": 0, "invalid": 0}
    tls_ip_coverage = {"tls_findings": 0, "available": 0, "missing": 0, "malformed": 0, "invalid": 0}
    network_coverage = {"open_port_findings": 0, "available": 0, "missing": 0, "malformed": 0, "invalid": 0}
    fingerprints = {}
    observed_ips = {}
    for finding in findings:
        by_investigation[finding.investigation_id].append(finding)
        if finding.module == "cert" and finding.source == "tls_handshake" and finding.finding_type in _TLS_CERT_TYPES:
            fingerprint, status = _certificate_fingerprint(finding)
            cert_coverage["tls_findings"] += 1
            cert_coverage[status] += 1
            if fingerprint:
                fingerprints[finding.id] = fingerprint
            indicator, status = _record_ip(finding)
            tls_ip_coverage["tls_findings"] += 1
            tls_ip_coverage[status] += 1
            if indicator:
                observed_ips[finding.id] = indicator
        elif finding.module == "network" and finding.finding_type == "open_port":
            indicator, status = _record_ip(finding)
            network_coverage["open_port_findings"] += 1
            network_coverage[status] += 1
            if indicator:
                observed_ips[finding.id] = indicator

    observations = defaultdict(lambda: defaultdict(list))
    for company_index, company in enumerate(body.companies):
        for wallet in company.wallets:
            observations[(f"wallet_{wallet.chain}", wallet.address)][company_index].append({
                "investigation_id": None, "finding_id": None,
                "finding_type": "wallet", "source": "user_assigned_wallet",
                "recorded_at": None,
            })
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
                indicators = []
                if finding.id in fingerprints:
                    indicators.append((("certificate_sha256", fingerprints[finding.id]), "sha256_fingerprint"))
                if finding.id in observed_ips:
                    indicators.append((observed_ips[finding.id], "ip"))
                if finding.module == "dns" and finding.finding_type in {"subdomain", "historical_dns", "reverse_ip"}:
                    kind = "domain" if finding.finding_type in {"subdomain", "reverse_ip"} else None
                    indicator = _indicator(finding.entity, kind)
                    if indicator:
                        indicators.append((indicator, "entity"))
                for indicator, field in indicators:
                    observations[indicator][company_index].append({
                        "investigation_id": investigation_id, "finding_id": finding.id,
                        "finding_type": finding.finding_type, "source": finding.source,
                        "indicator_field": field,
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
        "certificate_coverage": cert_coverage,
        "tls_endpoint_coverage": tls_ip_coverage,
        "network_coverage": network_coverage,
        "notice": (
            "Assignments are user-provided and unverified. Shared infrastructure or wallet addresses "
            "are leads, not proof of ownership or a relationship. Shared certificates may be used by unrelated "
            "customers or services. The same finding assigned to multiple companies is not independent evidence. "
            "Wallets are format-checked only, not checked for validity, activity or transfers. "
            "Historical findings may be stale; absence of a match does not prove absence of a connection. "
            "Findings and source coverage may be incomplete."
        ),
    }
