import json
from typing import Any
from uuid import uuid4

from stix2 import Indicator, Report, ThreatActor


class STIXFactory:
    """STIX 2.1 object helper for CTI MVP."""

    @staticmethod
    def indicator(*, value: str, ioc_type: str, labels: list[str] | None = None, confidence: int = 50) -> dict[str, Any]:
        pattern_map = {
            "ip": f"[ipv4-addr:value = '{value}']",
            "domain": f"[domain-name:value = '{value}']",
            "url": f"[url:value = '{value}']",
            "hash": f"[file:hashes.'SHA-256' = '{value}']",
            "email": f"[email-addr:value = '{value}']",
        }
        pattern = pattern_map.get(ioc_type, f"[x-zircon-observable:value = '{value}']")
        obj = Indicator(
            id=f"indicator--{uuid4()}",
            name=f"{ioc_type}:{value}",
            indicator_types=["malicious-activity"],
            pattern_type="stix",
            pattern=pattern,
            labels=labels or ["zircon-cti"],
            confidence=max(0, min(int(confidence), 100)),
            allow_custom=True,
            spec_version="2.1",
        )
        return json.loads(obj.serialize())

    @staticmethod
    def threat_actor(*, name: str, aliases: list[str] | None = None) -> dict[str, Any]:
        actor = ThreatActor(
            id=f"threat-actor--{uuid4()}",
            name=name,
            aliases=aliases or [],
            threat_actor_types=["nation-state"],
            allow_custom=True,
            spec_version="2.1",
        )
        return json.loads(actor.serialize())

    @staticmethod
    def report(*, name: str, object_refs: list[str], labels: list[str] | None = None) -> dict[str, Any]:
        report = Report(
            id=f"report--{uuid4()}",
            name=name,
            report_types=["threat-report"],
            object_refs=object_refs,
            labels=labels or ["zircon-cti"],
            allow_custom=True,
            spec_version="2.1",
        )
        return json.loads(report.serialize())
