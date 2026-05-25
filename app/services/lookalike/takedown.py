"""
Takedown package generator — Look-alike Domains Phase 2.

build_evidence_text(rule, domain_dict) → UDRP-style plain-text evidence string.
generate_takedown_package(rule_id, domain_id, db_session) → UTF-8 bytes.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import LookalikeDomain, LookalikeRule


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def build_evidence_text(rule: LookalikeRule, domain_dict: dict) -> str:
    """
    Build a UDRP-style plain-text evidence document.

    Parameters
    ----------
    rule:
        LookalikeRule ORM object (or dict-like with matching attributes).
    domain_dict:
        Dict of domain fields (as returned by ``_domain_to_dict``).
    """
    case_ref = f"ZIRCON-{_utcnow().strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"
    now_str = _utcnow().strftime("%Y-%m-%d %H:%M UTC")

    fqdn = domain_dict.get("fqdn", "N/A")
    protected = rule.protected_domain if hasattr(rule, "protected_domain") else domain_dict.get("protected_domain", "N/A")
    rule_name = rule.name if hasattr(rule, "name") else domain_dict.get("rule_name", "N/A")
    threat_score = domain_dict.get("threat_score", "N/A")
    severity = domain_dict.get("severity", "N/A")
    signals = domain_dict.get("signals_fired") or []
    if isinstance(signals, str):
        try:
            signals = json.loads(signals)
        except Exception:
            signals = []

    ip = domain_dict.get("ip", "N/A") or "N/A"
    country = domain_dict.get("country_code", "N/A") or "N/A"
    registrar = domain_dict.get("registrar", "N/A") or "N/A"
    registrant_org = domain_dict.get("registrant_org", "N/A") or "N/A"
    age_days = domain_dict.get("domain_age_days")
    age_str = f"{age_days} days" if age_days is not None else "N/A"
    creation_date = domain_dict.get("creation_date")
    if isinstance(creation_date, datetime):
        creation_date = creation_date.isoformat()
    expiry_date = domain_dict.get("expiry_date")
    if isinstance(expiry_date, datetime):
        expiry_date = expiry_date.isoformat()
    ssl_valid = domain_dict.get("ssl_valid")
    whois_privacy = domain_dict.get("whois_privacy")
    screenshot_url = domain_dict.get("screenshot_url", "N/A") or "N/A"
    urlscan_uuid = domain_dict.get("urlscan_uuid", "N/A") or "N/A"
    urlscan_score = domain_dict.get("urlscan_score")
    visual_sim = domain_dict.get("visual_similarity_pct")

    doc = f"""
================================================================================
BRAND PROTECTION TAKEDOWN EVIDENCE PACKAGE
Case Reference: {case_ref}
Generated: {now_str}
================================================================================

SECTION 1 — COMPLAINANT
------------------------
Rule Name      : {rule_name}
Protected Asset: {protected}
Report Date    : {now_str}

SECTION 2 — INFRINGING DOMAIN
------------------------------
Infringing FQDN : {fqdn}
IP Address      : {ip}
Country         : {country}
Registrar       : {registrar}
Registrant Org  : {registrant_org}
Registration Date: {creation_date or "N/A"}
Expiry Date     : {expiry_date or "N/A"}
Domain Age      : {age_str}
SSL Valid       : {ssl_valid}
WHOIS Privacy   : {whois_privacy}

SECTION 3 — TECHNICAL EVIDENCE
-------------------------------
HTTP Status     : {domain_dict.get("http_status", "N/A")}
Page Title      : {domain_dict.get("page_title", "N/A") or "N/A"}
Final URL       : {domain_dict.get("final_url", "N/A") or "N/A"}
Brand in Title  : {domain_dict.get("brand_in_title")}
Phishing KW     : {domain_dict.get("phishing_keywords_in_title")}
Redirect        : {domain_dict.get("redirect_detected")}
MX Record       : {domain_dict.get("has_mx_record")}

SECTION 4 — VISUAL SIMILARITY ANALYSIS
----------------------------------------
URLScan UUID    : {urlscan_uuid}
URLScan Score   : {urlscan_score if urlscan_score is not None else "N/A"}
Screenshot URL  : {screenshot_url}
Visual Similarity: {visual_sim if visual_sim is not None else "N/A"}%

SECTION 5 — SIMILARITY ANALYSIS
---------------------------------
Threat Score    : {threat_score} / 100
Severity        : {severity} / 5
Levenshtein Dist: {domain_dict.get("levenshtein_distance", "N/A")}
Similarity Score: {domain_dict.get("similarity_score", "N/A")}
Signals Fired   :
""".lstrip()

    for sig in signals:
        doc += f"  - {sig}\n"

    doc += """
SECTION 6 — GROUNDS FOR TAKEDOWN
----------------------------------
The infringing domain identified above is confusingly similar to the
complainant's protected domain, constituting:

  1. Trademark / brand name infringement through cybersquatting.
  2. Potential phishing, fraud, or consumer deception.
  3. Unauthorised use of the complainant's intellectual property.

Under UDRP Policy §4(a), the complainant asserts:
  (i)  The domain is identical or confusingly similar to a mark in which
       the complainant has rights.
  (ii) The registrant has no rights or legitimate interests in the domain.
  (iii) The domain has been registered and is being used in bad faith.

SECTION 7 — ACTION REQUESTED
------------------------------
  1. Immediate suspension/transfer of the infringing domain.
  2. Preservation of all registration and traffic logs.
  3. Notification of hosting provider for content takedown.

================================================================================
END OF EVIDENCE PACKAGE
================================================================================
"""
    return doc


async def generate_takedown_package(
    rule_id: int,
    domain_id: int,
    db_session: AsyncSession,
) -> bytes:
    """
    Load rule + domain from the DB, build the evidence document, and return
    UTF-8–encoded bytes.

    Raises ValueError if rule or domain is not found.
    """
    rule_res = await db_session.execute(
        select(LookalikeRule).where(LookalikeRule.id == rule_id)
    )
    rule = rule_res.scalar_one_or_none()
    if not rule:
        raise ValueError(f"LookalikeRule {rule_id} not found")

    domain_res = await db_session.execute(
        select(LookalikeDomain).where(
            LookalikeDomain.id == domain_id,
            LookalikeDomain.rule_id == rule_id,
        )
    )
    domain = domain_res.scalar_one_or_none()
    if not domain:
        raise ValueError(f"LookalikeDomain {domain_id} not found for rule {rule_id}")

    # Build a plain dict from the ORM object
    domain_dict: dict = {col.name: getattr(domain, col.name) for col in domain.__table__.columns}
    # Parse signals_fired JSON
    if isinstance(domain_dict.get("signals_fired"), str):
        try:
            domain_dict["signals_fired"] = json.loads(domain_dict["signals_fired"])
        except Exception:
            domain_dict["signals_fired"] = []

    text = build_evidence_text(rule, domain_dict)
    return text.encode("utf-8")
