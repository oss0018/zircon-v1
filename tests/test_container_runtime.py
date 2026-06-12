from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_root_dockerfile_installs_vuln_scanner_binaries():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "nikto" in dockerfile
    assert "testssl.sh" in dockerfile
    assert "nuclei_" in dockerfile
    assert "NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates" in dockerfile
    assert 'ENTRYPOINT ["zircon-entrypoint.sh"]' in dockerfile


def test_compose_shares_nuclei_templates_volume_for_runtime_services():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert compose.count("nuclei_templates:/opt/nuclei-templates") == 5
    assert "nuclei_templates:" in compose


def test_runtime_scripts_cover_template_bootstrap_and_tool_verification():
    entrypoint = (ROOT / "docker" / "zircon-entrypoint.sh").read_text(encoding="utf-8")
    verify_script = (ROOT / "docker" / "verify-vuln-tools.sh").read_text(encoding="utf-8")

    assert "-update-templates" in entrypoint
    assert "NUCLEI_TEMPLATES_DIR" in entrypoint
    for tool in ("testssl.sh", "nikto", "nuclei"):
        assert tool in verify_script
