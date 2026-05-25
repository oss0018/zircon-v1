"""
Look-alike Domains API — TS-LAD-001 v1.1
Router prefix: /api/v1/lookalike
"""
from __future__ import annotations

import csv
import io
import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import AsyncIterator, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.auth import get_current_user
from app.database import get_db
from app.models import Brand, LookalikeDomain, LookalikeRule, RuleTrustedDomain, User
from app.utils.sanitize import sanitize_string

logger = logging.getLogger(__name__)

router = APIRouter()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Pydantic schemas ───────────────────────────────────────────────────────────

class RuleCreate(BaseModel):
    brand_id: int
    name: str
    protected_domain: str
    brand_terms: Optional[List[str]] = []
    algorithms: Optional[List[str]] = []
    tld_list: Optional[str] = "top100"
    attack_words: Optional[str] = "core"
    include_idn: Optional[bool] = True
    include_bitsquatting: Optional[bool] = True
    max_variants: Optional[int] = 10000
    similarity_threshold_pct: Optional[int] = 70
    alert_threshold: Optional[int] = 50
    active: Optional[bool] = True

    @field_validator("similarity_threshold_pct")
    @classmethod
    def validate_threshold(cls, v):
        if v is not None and not (30 <= v <= 100):
            raise ValueError("similarity_threshold_pct must be between 30 and 100")
        return v

    @field_validator("alert_threshold")
    @classmethod
    def validate_alert_threshold(cls, v):
        if v is not None and not (30 <= v <= 100):
            raise ValueError("alert_threshold must be between 30 and 100")
        return v


class RulePatch(BaseModel):
    name: Optional[str] = None
    protected_domain: Optional[str] = None
    brand_terms: Optional[List[str]] = None
    algorithms: Optional[List[str]] = None
    tld_list: Optional[str] = None
    attack_words: Optional[str] = None
    include_idn: Optional[bool] = None
    include_bitsquatting: Optional[bool] = None
    max_variants: Optional[int] = None
    similarity_threshold_pct: Optional[int] = None
    alert_threshold: Optional[int] = None
    active: Optional[bool] = None

    @field_validator("similarity_threshold_pct")
    @classmethod
    def validate_threshold(cls, v):
        if v is not None and not (30 <= v <= 100):
            raise ValueError("similarity_threshold_pct must be between 30 and 100")
        return v

    @field_validator("alert_threshold")
    @classmethod
    def validate_alert_threshold(cls, v):
        if v is not None and not (30 <= v <= 100):
            raise ValueError("alert_threshold must be between 30 and 100")
        return v


class RulePreviewBody(BaseModel):
    protected_domain: str
    algorithms: Optional[List[str]] = []
    tld_list: Optional[str] = "top100"
    attack_words: Optional[str] = "core"
    include_idn: Optional[bool] = True
    include_bitsquatting: Optional[bool] = True
    max_variants: Optional[int] = 10000
    similarity_threshold_pct: Optional[int] = 70

    @field_validator("similarity_threshold_pct")
    @classmethod
    def validate_threshold(cls, v):
        if v is not None and not (30 <= v <= 100):
            raise ValueError("similarity_threshold_pct must be between 30 and 100")
        return v


class DomainPatch(BaseModel):
    is_false_positive: Optional[bool] = None
    fp_reason: Optional[str] = None
    status: Optional[str] = None


class AlertDispatchBody(BaseModel):
    domain_id: Optional[int] = None


class TrustedDomainCreate(BaseModel):
    fqdn_pattern: str
    match_type: str = "exact"
    reason: Optional[str] = None

    @field_validator("match_type")
    @classmethod
    def validate_match_type(cls, v):
        if v not in ("exact", "wildcard", "suffix"):
            raise ValueError("match_type must be one of: exact, wildcard, suffix")
        return v


# ── Helper ─────────────────────────────────────────────────────────────────────

def _rule_to_dict(rule: LookalikeRule) -> dict:
    return {
        "id": rule.id,
        "brand_id": rule.brand_id,
        "name": rule.name,
        "protected_domain": rule.protected_domain,
        "brand_terms": json.loads(rule.brand_terms or "[]"),
        "algorithms": json.loads(rule.algorithms or "[]"),
        "tld_list": rule.tld_list,
        "attack_words": rule.attack_words,
        "include_idn": rule.include_idn,
        "include_bitsquatting": rule.include_bitsquatting,
        "max_variants": rule.max_variants,
        "similarity_threshold_pct": rule.similarity_threshold_pct,
        "alert_threshold": rule.alert_threshold,
        "active": rule.active,
        "last_scan_at": rule.last_scan_at.isoformat() if rule.last_scan_at else None,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


def _domain_to_dict(d: LookalikeDomain) -> dict:
    return {
        "id": d.id,
        "rule_id": d.rule_id,
        "fqdn": d.fqdn,
        "label": d.label,
        "tld": d.tld,
        "algorithms": json.loads(d.algorithms or "[]"),
        "levenshtein_distance": d.levenshtein_distance,
        "similarity_score": d.similarity_score,
        "is_idn": d.is_idn,
        "unicode_form": d.unicode_form,
        "status": d.status,
        "dns_checked_at": d.dns_checked_at.isoformat() if d.dns_checked_at else None,
        "has_a_record": d.has_a_record,
        "has_mx_record": d.has_mx_record,
        "has_ns_record": d.has_ns_record,
        "ip": d.ip,
        "http_status": d.http_status,
        "page_title": d.page_title,
        "final_url": d.final_url,
        "server_header": d.server_header,
        "redirect_detected": d.redirect_detected,
        "redirects_to_legitimate": d.redirects_to_legitimate,
        "brand_in_title": d.brand_in_title,
        "phishing_keywords_in_title": d.phishing_keywords_in_title,
        "ssl_valid": d.ssl_valid,
        "ssl_issuer": d.ssl_issuer,
        "ssl_uses_lets_encrypt": d.ssl_uses_lets_encrypt,
        "ssl_cert_age_days": d.ssl_cert_age_days,
        "ssl_is_self_signed": d.ssl_is_self_signed,
        "country_code": d.country_code,
        "asn": d.asn,
        "org": d.org,
        "is_high_risk_country": d.is_high_risk_country,
        "registrar": d.registrar,
        "domain_age_days": d.domain_age_days,
        "whois_privacy": d.whois_privacy,
        "registrant_org": d.registrant_org,
        "creation_date": d.creation_date.isoformat() if d.creation_date else None,
        "expiry_date": d.expiry_date.isoformat() if d.expiry_date else None,
        "screenshot_url": d.screenshot_url,
        "urlscan_uuid": d.urlscan_uuid,
        "urlscan_score": d.urlscan_score,
        "phash_distance": d.phash_distance,
        "visual_similarity_pct": d.visual_similarity_pct,
        "threat_score": d.threat_score,
        "severity": d.severity,
        "signals_fired": json.loads(d.signals_fired or "[]"),
        "first_seen_at": d.first_seen_at.isoformat() if d.first_seen_at else None,
        "last_checked_at": d.last_checked_at.isoformat() if d.last_checked_at else None,
        "is_false_positive": d.is_false_positive,
        "fp_reason": d.fp_reason,
    }


# ── Rules CRUD ─────────────────────────────────────────────────────────────────

@router.get("/rules")
async def list_rules(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """List all lookalike monitoring rules with brand info."""
    result = await db.execute(select(LookalikeRule).order_by(LookalikeRule.created_at.desc()))
    rules = result.scalars().all()
    return [_rule_to_dict(r) for r in rules]


@router.post("/rules", status_code=201)
async def create_rule(
    body: RuleCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Create a new lookalike monitoring rule."""
    # Validate brand exists
    brand_res = await db.execute(select(Brand).where(Brand.id == body.brand_id))
    if not brand_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Brand not found")

    rule = LookalikeRule(
        brand_id=body.brand_id,
        name=sanitize_string(body.name, max_length=200),
        protected_domain=sanitize_string(body.protected_domain, max_length=253),
        brand_terms=json.dumps(body.brand_terms or []),
        algorithms=json.dumps(body.algorithms or []),
        tld_list=body.tld_list or "top100",
        attack_words=body.attack_words or "core",
        include_idn=body.include_idn if body.include_idn is not None else True,
        include_bitsquatting=body.include_bitsquatting if body.include_bitsquatting is not None else True,
        max_variants=body.max_variants or 10000,
        similarity_threshold_pct=body.similarity_threshold_pct or 70,
        alert_threshold=body.alert_threshold or 50,
        active=body.active if body.active is not None else True,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return _rule_to_dict(rule)


@router.get("/rules/{rule_id}")
async def get_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Get rule detail with trusted domain count and last scan summary."""
    result = await db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Count trusted domains
    td_count_res = await db.execute(
        select(func.count()).where(RuleTrustedDomain.rule_id == rule_id)
    )
    td_count = td_count_res.scalar() or 0

    # Count domains by status
    status_counts_res = await db.execute(
        select(LookalikeDomain.status, func.count())
        .where(LookalikeDomain.rule_id == rule_id)
        .group_by(LookalikeDomain.status)
    )
    status_counts = dict(status_counts_res.all())

    data = _rule_to_dict(rule)
    data["trusted_domain_count"] = td_count
    data["domain_status_counts"] = status_counts
    return data


@router.patch("/rules/{rule_id}")
async def update_rule(
    rule_id: int,
    body: RulePatch,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Update rule fields."""
    result = await db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    if body.name is not None:
        rule.name = sanitize_string(body.name, max_length=200)
    if body.protected_domain is not None:
        rule.protected_domain = sanitize_string(body.protected_domain, max_length=253)
    if body.brand_terms is not None:
        rule.brand_terms = json.dumps(body.brand_terms)
    if body.algorithms is not None:
        rule.algorithms = json.dumps(body.algorithms)
    if body.tld_list is not None:
        rule.tld_list = body.tld_list
    if body.attack_words is not None:
        rule.attack_words = body.attack_words
    if body.include_idn is not None:
        rule.include_idn = body.include_idn
    if body.include_bitsquatting is not None:
        rule.include_bitsquatting = body.include_bitsquatting
    if body.max_variants is not None:
        rule.max_variants = body.max_variants
    if body.similarity_threshold_pct is not None:
        rule.similarity_threshold_pct = body.similarity_threshold_pct
    if body.alert_threshold is not None:
        rule.alert_threshold = body.alert_threshold
    if body.active is not None:
        rule.active = body.active

    rule.updated_at = _utcnow()
    await db.commit()
    await db.refresh(rule)
    return _rule_to_dict(rule)


@router.post("/preview")
async def preview_rule_draft(
    body: RulePreviewBody,
    _: User = Depends(get_current_user),
):
    """Preview variant counts for an unsaved rule draft."""
    from app.services.lookalike.generators import GenerationConfig, PermutationEngine

    config = GenerationConfig(
        tld_list=body.tld_list or "top100",
        attack_words=body.attack_words or "core",
        include_idn=body.include_idn if body.include_idn is not None else True,
        include_bitsquatting=body.include_bitsquatting if body.include_bitsquatting is not None else True,
        max_variants=body.max_variants or 10000,
        similarity_threshold_pct=body.similarity_threshold_pct or 70,
        algorithms=body.algorithms or [],
    )
    engine = PermutationEngine(config)
    gen_result = engine.generate_and_filter(body.protected_domain)
    return {
        "raw_count": gen_result.raw_count,
        "filtered_count": gen_result.filtered_count,
        "threshold_pct": gen_result.threshold_pct,
        "filtered_out": gen_result.filtered_out,
    }


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Delete rule and cascade (domains + trusted entries)."""
    result = await db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
    return None


# ── Scan ──────────────────────────────────────────────────────────────────────

@router.post("/rules/{rule_id}/scan")
async def scan_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Trigger a full scan for a rule.

    Streams SSE events:
    - ``data: {"fqdn": ..., "status": ..., "threat_score": ..., "checked": N, "total": N}``
    - Final: ``event: done`` with summary
    """
    result = await db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    # Load trusted domain patterns for this rule
    td_result = await db.execute(
        select(RuleTrustedDomain).where(RuleTrustedDomain.rule_id == rule_id)
    )
    trusted_entries = [
        {
            "fqdn_pattern": td.fqdn_pattern,
            "match_type": td.match_type,
            "expires_at": td.expires_at,
        }
        for td in td_result.scalars().all()
    ]

    from app.services.lookalike.generators import GenerationConfig, PermutationEngine
    from app.services.lookalike.trusted_domains import TrustedDomainMatcher
    from app.services.lookalike.threat_scorer import ThreatScorer

    config = GenerationConfig(
        tld_list=rule.tld_list or "top100",
        attack_words=rule.attack_words or "core",
        include_idn=rule.include_idn,
        include_bitsquatting=rule.include_bitsquatting,
        max_variants=rule.max_variants or 10000,
        similarity_threshold_pct=rule.similarity_threshold_pct or 70,
        algorithms=json.loads(rule.algorithms or "[]"),
    )
    engine = PermutationEngine(config)
    gen_result = engine.generate_and_filter(rule.protected_domain)
    variants = gen_result.variants
    total = len(variants)

    matcher = TrustedDomainMatcher(trusted_entries)
    scorer = ThreatScorer()

    async def _sse_stream() -> AsyncIterator[str]:
        from app.database import AsyncSessionLocal
        from app.services.domain_checker import _is_safe_external_domain

        checked = 0
        registered_count = 0
        trusted_count = 0
        now = _utcnow()

        for variant in variants:
            fqdn = variant["fqdn"]
            label = variant["label"]
            tld = variant["tld"]
            checked += 1

            # Check if trusted
            if matcher.is_trusted(fqdn):
                status = "trusted"
                trusted_count += 1
                threat_score = 0
                severity = 1
                signals: list = []
                domain_data = {
                    "fqdn": fqdn,
                    "label": label,
                    "tld": tld,
                    "algorithms": json.dumps(variant.get("algorithms", [])),
                    "levenshtein_distance": variant.get("levenshtein_distance"),
                    "similarity_score": variant.get("similarity_score"),
                    "is_idn": variant.get("is_idn", False),
                    "unicode_form": variant.get("unicode_form"),
                    "status": status,
                    "threat_score": threat_score,
                    "severity": severity,
                    "signals_fired": json.dumps(signals),
                }
            else:
                # DNS check
                dns_result = await _check_dns_simple(fqdn)
                has_a = dns_result.get("has_a_record", False)
                has_mx = dns_result.get("has_mx_record", False)
                has_ns = dns_result.get("has_ns_record", False)
                ip = dns_result.get("ip")

                status = "registered" if has_a else "unregistered"
                if has_a:
                    registered_count += 1

                # HTTP check for registered domains
                http_status = None
                page_title = None
                brand_in_title = None
                phishing_kw = None
                redirect_detected = None
                redirects_to_legit = None
                ssl_valid = None

                if has_a and _is_safe_external_domain(fqdn):
                    http_result = await _check_http_simple(fqdn, rule.protected_domain)
                    http_status = http_result.get("http_status")
                    page_title = http_result.get("page_title")
                    brand_in_title = http_result.get("brand_in_title")
                    phishing_kw = http_result.get("phishing_keywords_in_title")
                    redirect_detected = http_result.get("redirect_detected")
                    redirects_to_legit = http_result.get("redirects_to_legitimate")
                    ssl_valid = http_result.get("ssl_valid")

                # Phase 2: GeoIP + WHOIS enrichment for live domains
                geoip_data: dict = {}
                whois_data: dict = {}
                if has_a:
                    try:
                        from app.services.lookalike.geoip_enricher import enrich_geoip
                        from app.services.lookalike.whois_enricher import enrich_whois
                        geoip_data, whois_data = await asyncio.gather(
                            enrich_geoip(ip),
                            enrich_whois(fqdn),
                            return_exceptions=True,
                        )
                        if isinstance(geoip_data, Exception):
                            geoip_data = {}
                        if isinstance(whois_data, Exception):
                            whois_data = {}
                    except Exception:
                        pass

                domain_data = {
                    "fqdn": fqdn,
                    "label": label,
                    "tld": tld,
                    "algorithms": json.dumps(variant.get("algorithms", [])),
                    "levenshtein_distance": variant.get("levenshtein_distance"),
                    "similarity_score": variant.get("similarity_score"),
                    "is_idn": variant.get("is_idn", False),
                    "unicode_form": variant.get("unicode_form"),
                    "status": status,
                    "has_a_record": has_a,
                    "has_mx_record": has_mx,
                    "has_ns_record": has_ns,
                    "ip": ip,
                    "http_status": http_status,
                    "page_title": page_title,
                    "brand_in_title": brand_in_title,
                    "phishing_keywords_in_title": phishing_kw,
                    "redirect_detected": redirect_detected,
                    "redirects_to_legitimate": redirects_to_legit,
                    "ssl_valid": ssl_valid,
                    # GeoIP
                    "country_code": geoip_data.get("country_code"),
                    "asn": geoip_data.get("asn"),
                    "org": geoip_data.get("org"),
                    "is_high_risk_country": geoip_data.get("is_high_risk_country"),
                    # WHOIS
                    "registrar": whois_data.get("registrar"),
                    "domain_age_days": whois_data.get("domain_age_days"),
                    "whois_privacy": whois_data.get("whois_privacy"),
                    "registrant_org": whois_data.get("registrant_org"),
                    "creation_date": whois_data.get("creation_date"),
                    "expiry_date": whois_data.get("expiry_date"),
                }

                # Compute threat score for checked domains
                ts, sev, signals = scorer.score(domain_data)
                threat_score = ts
                severity = sev
                domain_data["threat_score"] = ts
                domain_data["severity"] = sev
                domain_data["signals_fired"] = json.dumps(signals)

            # Upsert into DB
            try:
                async with AsyncSessionLocal() as upsert_db:
                    existing_res = await upsert_db.execute(
                        select(LookalikeDomain).where(
                            LookalikeDomain.rule_id == rule_id,
                            LookalikeDomain.fqdn == fqdn,
                        )
                    )
                    existing = existing_res.scalar_one_or_none()
                    if existing:
                        # Update existing record
                        for k, v in domain_data.items():
                            if hasattr(existing, k) and k not in ("fqdn", "rule_id", "first_seen_at"):
                                setattr(existing, k, v)
                        existing.last_checked_at = now
                        existing.dns_checked_at = now
                    else:
                        new_dom = LookalikeDomain(
                            rule_id=rule_id,
                            fqdn=domain_data["fqdn"],
                            label=domain_data["label"],
                            tld=domain_data["tld"],
                            algorithms=domain_data.get("algorithms", "[]"),
                            levenshtein_distance=domain_data.get("levenshtein_distance"),
                            similarity_score=domain_data.get("similarity_score"),
                            is_idn=domain_data.get("is_idn", False),
                            unicode_form=domain_data.get("unicode_form"),
                            status=domain_data.get("status", "unregistered"),
                            has_a_record=domain_data.get("has_a_record"),
                            has_mx_record=domain_data.get("has_mx_record"),
                            has_ns_record=domain_data.get("has_ns_record"),
                            ip=domain_data.get("ip"),
                            http_status=domain_data.get("http_status"),
                            page_title=domain_data.get("page_title"),
                            brand_in_title=domain_data.get("brand_in_title"),
                            phishing_keywords_in_title=domain_data.get("phishing_keywords_in_title"),
                            redirect_detected=domain_data.get("redirect_detected"),
                            redirects_to_legitimate=domain_data.get("redirects_to_legitimate"),
                            ssl_valid=domain_data.get("ssl_valid"),
                            threat_score=domain_data.get("threat_score"),
                            severity=domain_data.get("severity"),
                            signals_fired=domain_data.get("signals_fired", "[]"),
                            dns_checked_at=now,
                            last_checked_at=now,
                        )
                        upsert_db.add(new_dom)
                    await upsert_db.commit()
            except Exception as exc:
                logger.warning("Failed to upsert domain %s: %s", fqdn, exc)

            payload = {
                "fqdn": fqdn,
                "status": domain_data.get("status", "unregistered"),
                "threat_score": domain_data.get("threat_score"),
                "checked": checked,
                "total": total,
            }
            yield f"data: {json.dumps(payload)}\n\n"

        # Update rule last_scan_at
        try:
            async with AsyncSessionLocal() as scan_db:
                scan_res = await scan_db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
                scan_rule = scan_res.scalar_one_or_none()
                if scan_rule:
                    scan_rule.last_scan_at = now
                    scan_rule.updated_at = now
                    await scan_db.commit()
        except Exception as exc:
            logger.warning("Failed to update rule last_scan_at: %s", exc)

        summary = {
            "total": total,
            "registered": registered_count,
            "trusted": trusted_count,
            "unregistered": total - registered_count - trusted_count,
        }
        yield f"event: done\ndata: {json.dumps(summary)}\n\n"

    return StreamingResponse(_sse_stream(), media_type="text/event-stream")


@router.post("/rules/{rule_id}/preview")
async def preview_rule(
    rule_id: int,
    simulate_threshold: Optional[int] = Query(None, ge=30, le=100),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Preview variant counts without scanning."""
    result = await db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    from app.services.lookalike.generators import GenerationConfig, PermutationEngine

    config = GenerationConfig(
        tld_list=rule.tld_list or "top100",
        attack_words=rule.attack_words or "core",
        include_idn=rule.include_idn,
        include_bitsquatting=rule.include_bitsquatting,
        max_variants=rule.max_variants or 10000,
        similarity_threshold_pct=rule.similarity_threshold_pct or 70,
        algorithms=json.loads(rule.algorithms or "[]"),
    )
    engine = PermutationEngine(config)
    gen_result = engine.generate_and_filter(rule.protected_domain, simulate_threshold=simulate_threshold)
    return {
        "raw_count": gen_result.raw_count,
        "filtered_count": gen_result.filtered_count,
        "threshold_pct": gen_result.threshold_pct,
        "filtered_out": gen_result.filtered_out,
    }


# ── Domains ───────────────────────────────────────────────────────────────────

@router.get("/rules/{rule_id}/domains")
async def list_rule_domains(
    rule_id: int,
    fqdn: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    min_threat_score: Optional[int] = Query(None, ge=0, le=100),
    severity: Optional[int] = Query(None, ge=1, le=5),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Paginated list of variant domains for a rule."""
    # Verify rule exists
    rule_res = await db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
    if not rule_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Rule not found")

    query = select(LookalikeDomain).where(LookalikeDomain.rule_id == rule_id)

    if status:
        query = query.where(LookalikeDomain.status == status)
    if fqdn:
        safe_fqdn = sanitize_string(fqdn, max_length=253)
        query = query.where(LookalikeDomain.fqdn.ilike(f"%{safe_fqdn}%"))
    if min_threat_score is not None:
        query = query.where(LookalikeDomain.threat_score >= min_threat_score)
    if severity is not None:
        query = query.where(LookalikeDomain.severity == severity)

    # Count
    count_query = select(func.count()).select_from(query.subquery())
    total_res = await db.execute(count_query)
    total = total_res.scalar() or 0

    # Paginate
    query = (
        query
        .order_by(LookalikeDomain.threat_score.desc().nulls_last(), LookalikeDomain.fqdn)
        .offset((page - 1) * per_page)
        .limit(per_page)
    )
    domains_res = await db.execute(query)
    domains = domains_res.scalars().all()

    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [_domain_to_dict(d) for d in domains],
    }


@router.get("/domains/{domain_id}")
async def get_domain(
    domain_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Full detail for a single variant domain."""
    result = await db.execute(select(LookalikeDomain).where(LookalikeDomain.id == domain_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
    return _domain_to_dict(domain)


@router.patch("/domains/{domain_id}")
async def update_domain(
    domain_id: int,
    body: DomainPatch,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Update is_false_positive, fp_reason, or status on a domain."""
    result = await db.execute(select(LookalikeDomain).where(LookalikeDomain.id == domain_id))
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    if body.is_false_positive is not None:
        domain.is_false_positive = body.is_false_positive
    if body.fp_reason is not None:
        domain.fp_reason = sanitize_string(body.fp_reason, max_length=256)
    if body.status is not None:
        if body.status not in ("unregistered", "registered", "trusted", "error"):
            raise HTTPException(status_code=400, detail="Invalid status value")
        domain.status = body.status

    await db.commit()
    await db.refresh(domain)
    return _domain_to_dict(domain)


@router.get("/rules/{rule_id}/domains/export")
async def export_domains(
    rule_id: int,
    format: str = Query("csv", pattern="^(csv|json)$"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Export all domain results as CSV or JSON."""
    # Verify rule exists
    rule_res = await db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
    if not rule_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Rule not found")

    result = await db.execute(
        select(LookalikeDomain)
        .where(LookalikeDomain.rule_id == rule_id)
        .order_by(LookalikeDomain.threat_score.desc().nulls_last())
    )
    domains = result.scalars().all()

    if format == "json":
        data = [_domain_to_dict(d) for d in domains]
        content = json.dumps(data, indent=2)
        return StreamingResponse(
            iter([content]),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename=lookalike_rule_{rule_id}.json"},
        )

    # CSV
    output = io.StringIO()
    fieldnames = [
        "id", "fqdn", "label", "tld", "status", "threat_score", "severity",
        "has_a_record", "has_mx_record", "ip", "http_status",
        "ssl_valid", "brand_in_title", "phishing_keywords_in_title",
        "is_idn", "levenshtein_distance", "similarity_score",
        "first_seen_at", "last_checked_at",
    ]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for d in domains:
        row = _domain_to_dict(d)
        writer.writerow({k: row.get(k) for k in fieldnames})

    content = output.getvalue()
    return StreamingResponse(
        iter([content]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=lookalike_rule_{rule_id}.csv"},
    )


# ── Trusted Domains ────────────────────────────────────────────────────────────

@router.get("/rules/{rule_id}/trusted")
async def list_trusted(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """List trusted domain entries for a rule."""
    rule_res = await db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
    if not rule_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Rule not found")

    result = await db.execute(
        select(RuleTrustedDomain)
        .where(RuleTrustedDomain.rule_id == rule_id)
        .order_by(RuleTrustedDomain.created_at.desc())
    )
    entries = result.scalars().all()
    return [
        {
            "id": e.id,
            "rule_id": e.rule_id,
            "fqdn_pattern": e.fqdn_pattern,
            "match_type": e.match_type,
            "reason": e.reason,
            "verified": e.verified,
            "expires_at": e.expires_at.isoformat() if e.expires_at else None,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in entries
    ]


@router.post("/rules/{rule_id}/trusted", status_code=201)
async def add_trusted(
    rule_id: int,
    body: TrustedDomainCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Add a trusted domain entry to a rule."""
    rule_res = await db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
    if not rule_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Rule not found")

    entry = RuleTrustedDomain(
        rule_id=rule_id,
        fqdn_pattern=sanitize_string(body.fqdn_pattern, max_length=253),
        match_type=body.match_type,
        reason=sanitize_string(body.reason or "", max_length=1024) or None,
        added_by_user_id=current_user.id,
    )
    db.add(entry)
    await db.commit()
    await db.refresh(entry)
    return {
        "id": entry.id,
        "rule_id": entry.rule_id,
        "fqdn_pattern": entry.fqdn_pattern,
        "match_type": entry.match_type,
        "reason": entry.reason,
        "verified": entry.verified,
        "expires_at": None,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
    }


@router.delete("/rules/{rule_id}/trusted/{trusted_id}", status_code=204)
async def delete_trusted(
    rule_id: int,
    trusted_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Remove a trusted domain entry."""
    result = await db.execute(
        select(RuleTrustedDomain).where(
            RuleTrustedDomain.id == trusted_id,
            RuleTrustedDomain.rule_id == rule_id,
        )
    )
    entry = result.scalar_one_or_none()
    if not entry:
        raise HTTPException(status_code=404, detail="Trusted domain entry not found")
    await db.delete(entry)
    await db.commit()
    return None


# ── Phase 2: Enrich, Takedown, Alert endpoints ───────────────────────────────

@router.post("/rules/{rule_id}/domains/{domain_id}/enrich")
async def enrich_domain(
    rule_id: int,
    domain_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Run WHOIS + GeoIP + URLScan enrichment on a single domain and re-score it.

    The domain row is updated in the DB and the full updated dict is returned.
    """
    from app.config import settings as _settings
    from app.services.lookalike.geoip_enricher import enrich_geoip
    from app.services.lookalike.whois_enricher import enrich_whois
    from app.services.lookalike.screenshot_analyzer import fetch_screenshot_urlscan
    from app.services.lookalike.threat_scorer import ThreatScorer

    result = await db.execute(
        select(LookalikeDomain).where(
            LookalikeDomain.id == domain_id,
            LookalikeDomain.rule_id == rule_id,
        )
    )
    domain = result.scalar_one_or_none()
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")

    # Run enrichment tasks concurrently
    geoip_task = enrich_geoip(domain.ip)
    whois_task = enrich_whois(domain.fqdn)
    screenshot_task = fetch_screenshot_urlscan(domain.fqdn, _settings.urlscan_api_key)

    geoip_data, whois_data, screenshot_data = await asyncio.gather(
        geoip_task, whois_task, screenshot_task, return_exceptions=True
    )
    if isinstance(geoip_data, Exception):
        geoip_data = {}
    if isinstance(whois_data, Exception):
        whois_data = {}
    if isinstance(screenshot_data, Exception):
        screenshot_data = {}

    # Apply enrichment results to the domain row
    for field, value in geoip_data.items():
        if hasattr(domain, field):
            setattr(domain, field, value)
    for field in ("registrar", "domain_age_days", "whois_privacy", "registrant_org",
                  "creation_date", "expiry_date"):
        if field in whois_data and hasattr(domain, field):
            setattr(domain, field, whois_data[field])
    if screenshot_data.get("screenshot_url"):
        domain.screenshot_url = screenshot_data.get("screenshot_url")
    if screenshot_data.get("urlscan_uuid"):
        domain.urlscan_uuid = screenshot_data.get("urlscan_uuid")
    if screenshot_data.get("urlscan_score") is not None:
        domain.urlscan_score = screenshot_data.get("urlscan_score")

    # Re-score
    scorer = ThreatScorer()
    domain_dict = {col.name: getattr(domain, col.name) for col in domain.__table__.columns}
    ts, sev, signals = scorer.score(domain_dict)
    domain.threat_score = ts
    domain.severity = sev
    domain.signals_fired = json.dumps(signals)
    domain.last_checked_at = _utcnow()

    await db.commit()
    await db.refresh(domain)
    return _domain_to_dict(domain)


@router.get("/rules/{rule_id}/domains/{domain_id}/takedown")
async def download_takedown(
    rule_id: int,
    domain_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Stream a UDRP-style plain-text evidence package for a domain.
    """
    from app.services.lookalike.takedown import generate_takedown_package

    try:
        content = await generate_takedown_package(rule_id, domain_id, db)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))

    filename = f"takedown_rule{rule_id}_domain{domain_id}.txt"
    return StreamingResponse(
        iter([content]),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.post("/rules/{rule_id}/alert")
async def trigger_alerts(
    rule_id: int,
    body: Optional[AlertDispatchBody] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Manually trigger alert dispatch for all registered domains above threshold
    for a rule.
    """
    from app.services.lookalike.alert_engine import dispatch_lookalike_alerts

    rule_res = await db.execute(select(LookalikeRule).where(LookalikeRule.id == rule_id))
    rule = rule_res.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")

    domains_res = await db.execute(
        select(LookalikeDomain).where(
            LookalikeDomain.rule_id == rule_id,
            LookalikeDomain.status == "registered",
        )
    )
    domains = list(domains_res.scalars().all())
    if body and body.domain_id is not None:
        domains = [domain for domain in domains if domain.id == body.domain_id]

    result = await dispatch_lookalike_alerts(
        rule_id,
        domains,
        db,
        alert_threshold=rule.alert_threshold or 50,
    )
    return result


# ── Internal DNS/HTTP helpers ─────────────────────────────────────────────────

async def _check_dns_simple(fqdn: str) -> dict:
    """
    Perform async DNS checks for A, MX, NS records using aiodns.
    Falls back to socket.gethostbyname if aiodns unavailable.
    """
    result: dict = {
        "has_a_record": False,
        "has_mx_record": False,
        "has_ns_record": False,
        "ip": None,
    }
    try:
        import aiodns  # type: ignore
        import asyncio

        resolver = aiodns.DNSResolver()

        async def _query(qtype: str):
            try:
                return await resolver.query(fqdn, qtype)
            except Exception:
                return None

        a_res, mx_res, ns_res = await asyncio.gather(
            _query("A"), _query("MX"), _query("NS"), return_exceptions=True
        )
        if a_res and not isinstance(a_res, Exception):
            result["has_a_record"] = True
            result["ip"] = str(a_res[0].host) if hasattr(a_res[0], "host") else None
        if mx_res and not isinstance(mx_res, Exception):
            result["has_mx_record"] = True
        if ns_res and not isinstance(ns_res, Exception):
            result["has_ns_record"] = True

    except ImportError:
        import asyncio
        import socket

        loop = asyncio.get_event_loop()
        try:
            ip = await loop.run_in_executor(None, socket.gethostbyname, fqdn)
            result["has_a_record"] = True
            result["ip"] = ip
        except Exception:
            pass

    return result


async def _check_http_simple(fqdn: str, protected_domain: str) -> dict:
    """Minimal HTTP probe: status, title, redirect, SSL."""
    from app.services.lookalike.generators import PHISHING_KEYWORDS

    result: dict = {
        "http_status": None,
        "page_title": None,
        "brand_in_title": None,
        "phishing_keywords_in_title": None,
        "redirect_detected": None,
        "redirects_to_legitimate": None,
        "ssl_valid": None,
    }
    import re as _re
    _TITLE_RE = _re.compile(r"<title[^>]*>([^<]{1,512})</title>", _re.IGNORECASE | _re.DOTALL)
    protected_label = protected_domain.split(".")[0].lower()

    try:
        import httpx
        timeout = httpx.Timeout(5.0)
        async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, verify=False) as client:
            try:
                resp = await client.get(f"http://{fqdn}", follow_redirects=True)
                result["http_status"] = resp.status_code
                final_url = str(resp.url)

                # Check redirect
                if resp.history:
                    result["redirect_detected"] = True
                    result["redirects_to_legitimate"] = protected_label in final_url.lower()

                # Page title
                content = resp.text[:32768]
                m = _TITLE_RE.search(content)
                if m:
                    title = m.group(1).strip()[:512]
                    result["page_title"] = title
                    result["brand_in_title"] = protected_label in title.lower()
                    result["phishing_keywords_in_title"] = any(
                        kw in title.lower() for kw in PHISHING_KEYWORDS
                    )
            except Exception:
                pass

            # SSL check
            try:
                ssl_resp = await client.get(f"https://{fqdn}", follow_redirects=False)
                result["ssl_valid"] = ssl_resp.status_code < 600
            except Exception:
                result["ssl_valid"] = False

    except ImportError:
        pass

    return result
