"""
Tests for the OSINT Infrastructure Intelligence module.
Covers: models exist, OSINT clients registered, CloudOSINT permutations,
DNS/Network/Cert module structure, and API router endpoint registration.
"""
import json
import pytest


# ── Model presence ────────────────────────────────────────────────────────────

def test_infra_models_importable():
    from app.models import InfraInvestigation, InfraFinding
    assert InfraInvestigation.__tablename__ == "infra_investigations"
    assert InfraFinding.__tablename__ == "infra_findings"


def test_infra_investigation_columns():
    from app.models import InfraInvestigation
    col_names = {c.name for c in InfraInvestigation.__table__.columns}
    assert "target" in col_names
    assert "target_type" in col_names
    assert "status" in col_names
    assert "summary_json" in col_names
    assert "modules_json" in col_names
    assert "error_message" in col_names


def test_infra_finding_columns():
    from app.models import InfraFinding
    col_names = {c.name for c in InfraFinding.__table__.columns}
    assert "investigation_id" in col_names
    assert "module" in col_names
    assert "finding_type" in col_names
    assert "entity" in col_names
    assert "severity" in col_names
    assert "source" in col_names
    assert "data_json" in col_names


# ── OSINT client registration ─────────────────────────────────────────────────

def test_crtsh_client_registered():
    from app.services.osint import OSINT_CLIENTS
    assert "crtsh" in OSINT_CLIENTS


def test_whoisxml_client_registered():
    from app.services.osint import OSINT_CLIENTS
    assert "whoisxml" in OSINT_CLIENTS


def test_phase2_osint_clients_registered():
    from app.services.osint import OSINT_CLIENTS
    assert "fofa" in OSINT_CLIENTS
    assert "zoomeye" in OSINT_CLIENTS
    assert "criminalip" in OSINT_CLIENTS


def test_crtsh_get_client():
    from app.services.osint import get_client
    client = get_client("crtsh")
    assert client is not None
    assert client.service_name == "crtsh"


def test_whoisxml_no_key_returns_error():
    from app.services.osint.whoisxml import WhoisXMLClient
    import asyncio
    client = WhoisXMLClient(api_key="")
    result = asyncio.run(client.search("example.com", "domain"))
    assert "error" in result
    assert "API key" in result["error"]


def test_fofa_no_key_returns_error():
    from app.services.osint.fofa import FOFAClient
    import asyncio
    client = FOFAClient(api_key="")
    result = asyncio.run(client.search("example.com", "domain"))
    assert "error" in result
    assert "API key" in result["error"]


# ── Cloud OSINT permutations ──────────────────────────────────────────────────

def test_cloud_permutations_contains_brand():
    from app.services.infrastructure_intelligence.cloud_osint import CloudOSINTModule
    mod = CloudOSINTModule({})
    perms = mod.generate_permutations("acme")
    assert "acme" in perms


def test_cloud_permutations_max_80():
    from app.services.infrastructure_intelligence.cloud_osint import CloudOSINTModule
    mod = CloudOSINTModule({})
    perms = mod.generate_permutations("testbrand")
    assert len(perms) <= 80


def test_cloud_permutations_deduplicated():
    from app.services.infrastructure_intelligence.cloud_osint import CloudOSINTModule
    mod = CloudOSINTModule({})
    perms = mod.generate_permutations("acme")
    assert len(perms) == len(set(perms))


def test_cloud_run_skips_non_domain():
    from app.services.infrastructure_intelligence.cloud_osint import CloudOSINTModule
    import asyncio
    mod = CloudOSINTModule({})
    result = asyncio.run(mod.run("192.168.1.1", "ip"))
    assert result == []


def test_cloud_run_skips_asn():
    from app.services.infrastructure_intelligence.cloud_osint import CloudOSINTModule
    import asyncio
    mod = CloudOSINTModule({})
    result = asyncio.run(mod.run("AS12345", "asn"))
    assert result == []


# ── DNS module ────────────────────────────────────────────────────────────────

def test_dns_module_run_ip_type():
    """IP target_type should trigger reverse_ip_lookup (returns empty without keys)."""
    from app.services.infrastructure_intelligence.dns_intelligence import DNSIntelligenceModule
    import asyncio
    mod = DNSIntelligenceModule({})
    result = asyncio.run(mod.run("1.2.3.4", "ip"))
    assert isinstance(result, list)


def test_dns_module_returns_list():
    from app.services.infrastructure_intelligence.dns_intelligence import DNSIntelligenceModule
    import asyncio
    mod = DNSIntelligenceModule({})
    # Without any API keys, only crt.sh path runs (network call, may fail in test)
    # We just verify the return type is a list and no exception is raised
    result = asyncio.run(mod.enumerate_subdomains("nonexistent.invalid"))
    assert isinstance(result, list)


# ── Network module ────────────────────────────────────────────────────────────

def test_network_port_severity():
    from app.services.infrastructure_intelligence.network_intelligence import _port_severity
    assert _port_severity(23) == 4    # Telnet
    assert _port_severity(3389) == 4  # RDP
    assert _port_severity(9200) == 3  # Elasticsearch
    assert _port_severity(6379) == 3  # Redis
    assert _port_severity(80) == 2    # HTTP (default)
    assert _port_severity(443) == 2   # HTTPS (default)


def test_network_run_no_keys_returns_empty():
    from app.services.infrastructure_intelligence.network_intelligence import NetworkIntelligenceModule
    import asyncio
    mod = NetworkIntelligenceModule({})
    result = asyncio.run(mod.run("example.com", "domain"))
    assert isinstance(result, list)
    assert result == []  # No shodan/censys keys → empty


def test_tech_stack_detect_from_findings():
    from app.services.infrastructure_intelligence.tech_stack import TechStackModule
    mod = TechStackModule({})
    findings = [
        {
            "entity": "1.2.3.4:443",
            "source": "shodan",
            "data_json": {"banner": "Apache/2.4.58 OpenSSL/3.0.0"},
        }
    ]
    detected = mod.detect_from_findings(findings)
    assert isinstance(detected, list)
    assert any(f.get("module") == "tech_stack" and f.get("finding_type") == "detected_tech" for f in detected)
    assert any("Apache" in f.get("entity", "") for f in detected)


def test_bgp_module_run_unsupported_target_type():
    from app.services.infrastructure_intelligence.bgp_asn import BGPASNModule
    import asyncio
    mod = BGPASNModule({})
    result = asyncio.run(mod.run("example.com", "domain"))
    assert result == []


# ── Cert module ───────────────────────────────────────────────────────────────

def test_cert_run_non_domain_returns_empty():
    from app.services.infrastructure_intelligence.cert_intelligence import CertIntelligenceModule
    import asyncio
    mod = CertIntelligenceModule({})
    result = asyncio.run(mod.run("1.2.3.4", "ip"))
    assert result == []


# ── Orchestrator ──────────────────────────────────────────────────────────────

def test_orchestrator_importable():
    from app.services.infrastructure_intelligence import InfraOrchestrator
    orch = InfraOrchestrator()
    assert orch is not None


def test_infra_package_exports_phase2_modules():
    from app.services.infrastructure_intelligence import BGPASNModule, TechStackModule
    assert BGPASNModule is not None
    assert TechStackModule is not None


# ── API router ────────────────────────────────────────────────────────────────

def test_api_router_importable():
    from app.api.infra_intel import router
    from fastapi import APIRouter
    assert isinstance(router, APIRouter)


def test_api_router_has_investigate_route():
    from app.api.infra_intel import router
    paths = [r.path for r in router.routes]
    assert "/investigate" in paths


def test_api_router_has_investigations_route():
    from app.api.infra_intel import router
    paths = [r.path for r in router.routes]
    assert "/investigations" in paths


def test_api_router_has_detail_route():
    from app.api.infra_intel import router
    paths = [r.path for r in router.routes]
    assert "/investigations/{investigation_id}" in paths


def test_api_router_has_summary_route():
    from app.api.infra_intel import router
    paths = [r.path for r in router.routes]
    assert "/investigations/{investigation_id}/summary" in paths


def test_api_router_valid_modules_include_phase2():
    from app.api.infra_intel import _VALID_MODULES, InvestigateRequest
    assert "tech_stack" in _VALID_MODULES
    assert "bgp_asn" in _VALID_MODULES
    assert "tech_stack" in InvestigateRequest.model_fields["modules"].default
    assert "bgp_asn" in InvestigateRequest.model_fields["modules"].default


def test_known_services_include_phase2_integrations():
    from app.api.integrations import KNOWN_SERVICES
    known_types = {s["type"] for s in KNOWN_SERVICES}
    assert "fofa" in known_types
    assert "zoomeye" in known_types
    assert "criminalip" in known_types
    assert "whoisxml" in known_types
    assert "crtsh" in known_types
    assert "malwarebazaar" in known_types


# ── GrayhatWarfare ────────────────────────────────────────────────────────────

def test_grayhatwarfare_client_registered():
    from app.services.osint import OSINT_CLIENTS
    assert "grayhatwarfare" in OSINT_CLIENTS


def test_grayhatwarfare_no_key_returns_error():
    from app.services.osint.grayhatwarfare import GrayhatWarfareClient
    import asyncio
    client = GrayhatWarfareClient(api_key="")
    result = asyncio.run(client.search("example", "general"))
    assert "error" in result
    assert "API key" in result["error"]


def test_grayhatwarfare_no_key_files_returns_error():
    from app.services.osint.grayhatwarfare import GrayhatWarfareClient
    import asyncio
    client = GrayhatWarfareClient(api_key="")
    result = asyncio.run(client.search_files("passwords"))
    assert "error" in result
    assert "API key" in result["error"]


def test_grayhatwarfare_in_known_services():
    from app.api.integrations import KNOWN_SERVICES
    known_types = {s["type"] for s in KNOWN_SERVICES}
    assert "grayhatwarfare" in known_types


def test_grayhatwarfare_in_infra_service_types():
    from app.services.infrastructure_intelligence.orchestrator import _INFRA_SERVICE_TYPES
    assert "grayhatwarfare" in _INFRA_SERVICE_TYPES


def test_cloud_module_query_grayhatwarfare_no_key():
    """Without a key, query_grayhatwarfare should return an empty list silently."""
    from app.services.infrastructure_intelligence.cloud_osint import CloudOSINTModule
    import asyncio
    mod = CloudOSINTModule({})
    result = asyncio.run(mod.query_grayhatwarfare("acme"))
    assert result == []


def test_cloud_module_query_grayhatwarfare_parses_buckets():
    """Verify bucket list parsing logic with a mock response."""
    from app.services.infrastructure_intelligence.cloud_osint import CloudOSINTModule
    import asyncio
    from unittest.mock import AsyncMock, patch

    mock_response = {
        "buckets": [
            {"bucket": "acme-dev", "type": "aws_s3", "url": "https://acme-dev.s3.amazonaws.com", "fileCount": 12},
        ]
    }

    mod = CloudOSINTModule({"grayhatwarfare": "fakekey"})
    with patch("app.services.osint.grayhatwarfare.GrayhatWarfareClient.search", new=AsyncMock(return_value=mock_response)):
        result = asyncio.run(mod.query_grayhatwarfare("acme"))

    assert len(result) == 1
    finding = result[0]
    assert finding["module"] == "cloud"
    assert finding["finding_type"] == "bucket_exposed"
    assert finding["severity"] == 5
    assert finding["source"] == "grayhatwarfare"
    assert finding["data_json"]["bucket"] == "acme-dev"
    assert finding["data_json"]["provider"] == "aws_s3"
    assert finding["data_json"]["indexed_files"] == 12
